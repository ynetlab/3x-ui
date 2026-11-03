package cluster

import (
	"crypto/x509"
	"errors"
	"time"
)

// The public pin selects an old, still-valid server leaf during a renewal.
// It grants no authority; both TLS validation and HTTP peer authorization remain.
const ControlPinALPNPrefix = "3x-ui-control-pin-"

func ValidateIdentityCertificate(certPEM, caPEM string, expected Identity) (Peer, *x509.Certificate, error) {
	root, err := rootCertificate(caPEM)
	if err != nil {
		return Peer{}, nil, err
	}
	der, err := parsePEM([]byte(certPEM), "CERTIFICATE")
	if err != nil {
		return Peer{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return Peer{}, nil, err
	}
	identity, err := CertificateIdentity(leaf)
	if err != nil || identity != expected {
		return Peer{}, nil, errors.New("control certificate identity changed")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: identity.serverName(), KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: time.Now()}); err != nil {
			return Peer{}, nil, err
		}
	}
	return Peer{Identity: identity, Fingerprint: Fingerprint(leaf), CertificateNotAfter: leaf.NotAfter.UnixMilli()}, leaf, nil
}

func ValidateControlCA(certPEM string) (*x509.Certificate, error) { return rootCertificate(certPEM) }
