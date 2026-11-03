// Package cluster implements the isolated master/slave control transport.
package cluster

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	panelcrypto "github.com/mhsanaei/3x-ui/v3/internal/util/crypto"
)

const (
	RoleMaster            = "master"
	RoleSlave             = "slave"
	IdentityValidityYears = 3
)

var ErrControlPeerMismatch = errors.New("control peer identity or fingerprint mismatch")

type Identity struct {
	GUID string `json:"guid"`
	Role string `json:"role"`
}

func (i Identity) Validate() error {
	id, err := uuid.Parse(i.GUID)
	if err != nil || id == uuid.Nil || id.String() != i.GUID {
		return errors.New("control identity requires a canonical nonzero UUID")
	}
	if i.Role != RoleMaster && i.Role != RoleSlave {
		return errors.New("control identity role must be master or slave")
	}
	return nil
}

func (i Identity) serverName() string { return i.GUID + ".control.3x-ui.internal" }

// Credentials contains this machine's key only, plus the public control CA.
// It must not be returned by panel settings or API responses.
type Credentials struct {
	CACertPEM string `json:"caCertPem"`
	CertPEM   string `json:"certPem"`
	KeyPEM    string `json:"keyPem"`
}

type Peer struct {
	Identity
	Fingerprint                  string `json:"fingerprint"`
	CertificateNotAfter          int64  `json:"certificateNotAfter,omitempty"`
	PreviousFingerprint          string `json:"previousFingerprint,omitempty"`
	PreviousUntil                int64  `json:"previousUntil,omitempty"`
	PendingFingerprint           string `json:"pendingFingerprint,omitempty"`
	PendingUntil                 int64  `json:"pendingUntil,omitempty"`
	AcknowledgedLocalFingerprint string `json:"acknowledgedLocalFingerprint,omitempty"`
}

func (p Peer) Validate() error {
	if err := p.Identity.Validate(); err != nil {
		return err
	}
	_, err := decodeFingerprint(p.Fingerprint)
	if err != nil {
		return err
	}
	for _, extra := range []struct {
		pin   string
		until int64
	}{{p.PreviousFingerprint, p.PreviousUntil}, {p.PendingFingerprint, p.PendingUntil}} {
		if extra.pin != "" {
			if _, err := decodeFingerprint(extra.pin); err != nil || extra.until <= 0 {
				return errors.New("invalid control pin transition")
			}
		}
	}
	if p.AcknowledgedLocalFingerprint != "" {
		_, err = decodeFingerprint(p.AcknowledgedLocalFingerprint)
	}
	return err
}

func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func PeerFromPEM(certPEM string) (Peer, error) {
	der, err := parsePEM([]byte(certPEM), "CERTIFICATE")
	if err != nil {
		return Peer{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Peer{}, err
	}
	identity, err := CertificateIdentity(cert)
	if err != nil {
		return Peer{}, err
	}
	return Peer{Identity: identity, Fingerprint: Fingerprint(cert), CertificateNotAfter: cert.NotAfter.UnixMilli()}, nil
}

func decodeFingerprint(value string) ([]byte, error) {
	pin, err := hex.DecodeString(value)
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("control fingerprint must be a hex SHA-256 hash")
	}
	return pin, nil
}

// NewCSR generates the private key locally. Role and identity are assigned by
// the issuer, never copied from untrusted CSR subject or extension fields.
func NewCSR() (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func parsePEM(data []byte, kind string) ([]byte, error) {
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN "+kind+"-----")) {
		return nil, fmt.Errorf("expected %s PEM", kind)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("expected exactly one %s PEM block", kind)
	}
	return block.Bytes, nil
}

func rootCertificate(caPEM string) (*x509.Certificate, error) {
	der, err := parsePEM([]byte(caPEM), "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("control trust root is not a signing CA")
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		return nil, err
	}
	if time.Now().Before(ca.NotBefore) || !time.Now().Before(ca.NotAfter) {
		return nil, errors.New("control CA is not currently valid")
	}
	return ca, nil
}

// IssueIdentity signs a validated CSR with an issuer-assigned GUID and role.
// A control-only URI separates these credentials from legacy panel mTLS.
func IssueIdentity(ca panelcrypto.CertKeyPEM, csrPEM []byte, identity Identity) ([]byte, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	if len(csrPEM) > 16<<10 {
		return nil, errors.New("control CSR is too large")
	}
	der, err := parsePEM(csrPEM, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	root, err := rootCertificate(string(ca.CertPEM))
	if err != nil {
		return nil, err
	}
	_, signer, err := panelcrypto.LoadCAFromPEM(ca)
	if err != nil {
		return nil, err
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(public, root.RawSubjectPublicKeyInfo) {
		return nil, errors.New("control CA certificate and key do not match")
	}
	// Restrict identity keys to the local generator's P-256 format.
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("control CSR must use an ECDSA P-256 key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expires := now.AddDate(IdentityValidityYears, 0, 0)
	if root.NotAfter.Before(expires) {
		expires = root.NotAfter
	}
	name := &url.URL{Scheme: "spiffe", Host: "3x-ui", Path: "/control/" + identity.Role + "/" + identity.GUID}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: identity.GUID},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: expires,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, DNSNames: []string{identity.serverName()}, URIs: []*url.URL{name},
	}
	issued, err := x509.CreateCertificate(rand.Reader, template, root, csr.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued}), nil
}

func CertificateIdentity(cert *x509.Certificate) (Identity, error) {
	if cert == nil || cert.IsCA || len(cert.URIs) != 1 {
		return Identity{}, errors.New("certificate has no unique control identity")
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" || u.Host != "3x-ui" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return Identity{}, errors.New("invalid control identity URI")
	}
	path, ok := strings.CutPrefix(u.Path, "/control/")
	if !ok {
		return Identity{}, errors.New("invalid control identity path")
	}
	role, guid, ok := strings.Cut(path, "/")
	if !ok {
		return Identity{}, errors.New("invalid control identity path")
	}
	identity := Identity{GUID: guid, Role: role}
	if err := identity.Validate(); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func (c Credentials) Load() (tls.Certificate, *x509.CertPool, Identity, error) {
	root, err := rootCertificate(c.CACertPEM)
	if err != nil {
		return tls.Certificate{}, nil, Identity{}, err
	}
	der, err := parsePEM([]byte(c.CertPEM), "CERTIFICATE")
	if err != nil {
		return tls.Certificate{}, nil, Identity{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, Identity{}, err
	}
	identity, err := CertificateIdentity(leaf)
	if err != nil {
		return tls.Certificate{}, nil, Identity{}, err
	}
	cert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
	if err != nil {
		return tls.Certificate{}, nil, Identity{}, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: identity.serverName(), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return tls.Certificate{}, nil, Identity{}, err
		}
	}
	cert.Leaf = leaf
	return cert, pool, identity, nil
}

func ServerTLS(credentials Credentials) (*tls.Config, error) {
	cert, roots, _, err := credentials.Load()
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven, NextProtos: []string{"http/1.1"}}, nil
}

func matchPeer(cert *x509.Certificate, peer Peer) error {
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return fmt.Errorf("%w: expired or not yet valid certificate", ErrControlPeerMismatch)
	}
	identity, err := CertificateIdentity(cert)
	if err != nil {
		return err
	}
	if identity != peer.Identity {
		return fmt.Errorf("%w: identity", ErrControlPeerMismatch)
	}
	actual := sha256.Sum256(cert.Raw)
	for _, candidate := range []struct {
		pin   string
		until int64
	}{{peer.Fingerprint, 0}, {peer.PreviousFingerprint, peer.PreviousUntil}, {peer.PendingFingerprint, peer.PendingUntil}} {
		if candidate.pin == "" || candidate.until != 0 && time.Now().UnixMilli() >= candidate.until {
			continue
		}
		want, err := decodeFingerprint(candidate.pin)
		if err == nil && subtle.ConstantTimeCompare(want, actual[:]) == 1 {
			return nil
		}
	}
	return fmt.Errorf("%w: fingerprint", ErrControlPeerMismatch)
}

// ClientTLS uses the private CA and expected logical server name, allowing a
// direct IP connection without a public domain or an ACME certificate.
func ClientTLS(credentials Credentials, peer Peer) (*tls.Config, error) {
	if err := peer.Validate(); err != nil {
		return nil, err
	}
	cert, roots, _, err := credentials.Load()
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots,
		NextProtos: []string{ControlPinALPNPrefix + peer.Fingerprint, "http/1.1"},
		ServerName: peer.Identity.serverName(), VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
				return errors.New("unverified control server")
			}
			return matchPeer(cs.PeerCertificates[0], peer)
		}}, nil
}

// BootstrapTLS trusts only an out-of-band master certificate fingerprint.
// InsecureSkipVerify replaces public-CA/name validation with the mandatory pin;
// it is never used without this verification callback.
func BootstrapTLS(master Peer) (*tls.Config, error) {
	if err := master.Validate(); err != nil {
		return nil, err
	}
	if master.Role != RoleMaster {
		return nil, errors.New("bootstrap target must be a master")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, NextProtos: []string{ControlPinALPNPrefix + master.Fingerprint, "http/1.1"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("bootstrap server presented no certificate")
			}
			leaf := cs.PeerCertificates[0]
			if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
				return errors.New("bootstrap certificate is not currently valid")
			}
			return matchPeer(leaf, master)
		}}, nil
}
