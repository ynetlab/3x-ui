// Package panelcert contains public panel certificates, independently of the
// private CA and leaf identities used on the cluster control listener.
package panelcert

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sort"
	"strings"
	"time"
)

type Bundle struct {
	Certificate string   `json:"certificate"`
	PrivateKey  string   `json:"privateKey"`
	Domains     []string `json:"domains"`
}

func Fingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// Validate verifies the key, public trust, server usage and the exact SAN set.
// A nil roots pool uses the operating system's trusted public roots.
func (b Bundle) Validate(now time.Time, roots *x509.CertPool) (tls.Certificate, error) {
	bad := errors.New("invalid_panel_certificate")
	if len(b.Certificate) > 128<<10 || len(b.PrivateKey) > 16<<10 || len(b.Domains) < 1 || len(b.Domains) > 100 {
		return tls.Certificate{}, bad
	}
	pair, err := tls.X509KeyPair([]byte(b.Certificate), []byte(b.PrivateKey))
	if err != nil || len(pair.Certificate) == 0 {
		return tls.Certificate{}, bad
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || leaf.NotAfter.Before(now.Add(time.Hour)) || len(leaf.IPAddresses) > 0 || len(leaf.URIs) > 0 || len(leaf.EmailAddresses) > 0 {
		return tls.Certificate{}, bad
	}
	wanted := append([]string(nil), b.Domains...)
	actual := append([]string(nil), leaf.DNSNames...)
	sort.Strings(wanted)
	sort.Strings(actual)
	if len(wanted) != len(actual) {
		return tls.Certificate{}, bad
	}
	for i, domain := range wanted {
		if domain == "" || strings.ToLower(domain) != domain || domain != actual[i] || i > 0 && wanted[i-1] == domain {
			return tls.Certificate{}, bad
		}
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return tls.Certificate{}, bad
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return tls.Certificate{}, bad
	}
	pair.Leaf = leaf
	return pair, nil
}

func EncodeChain(chain [][]byte) string {
	var result []byte
	for _, der := range chain {
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return string(result)
}
