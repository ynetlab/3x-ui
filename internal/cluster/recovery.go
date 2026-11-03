package cluster

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
)

func RecoveryMessage(id, guid, csr, masterPin string) string {
	digest := sha256.Sum256([]byte(csr))
	data, _ := json.Marshal([]string{"3x-ui-control-recovery-v1", id, guid, base64.RawURLEncoding.EncodeToString(digest[:]), masterPin})
	return string(data)
}

// Recovery proves possession of the previously pinned private key. This is
// solely a local-root, one-time enrollment proof; it never makes an expired
// certificate valid for TLS and never trusts a revoked CA to issue identities.
func SignRecoveryProof(credentials Credentials, message string) (string, error) {
	pair, err := tls.X509KeyPair([]byte(credentials.CertPEM), []byte(credentials.KeyPEM))
	if err != nil {
		return "", err
	}
	signer, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("unsupported recovery key")
	}
	digest := sha256.Sum256([]byte(message))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(signature), nil
}
func VerifyRecoveryProof(certPEM, pin string, expected Identity, message, signature string) error {
	der, err := parsePEM([]byte(certPEM), "CERTIFICATE")
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	identity, err := CertificateIdentity(leaf)
	if err != nil || identity != expected {
		return ErrControlPeerMismatch
	}
	actual := Fingerprint(leaf)
	if subtle.ConstantTimeCompare([]byte(actual), []byte(pin)) != 1 {
		return ErrControlPeerMismatch
	}
	sig, err := base64.RawStdEncoding.Strict().DecodeString(signature)
	if err != nil {
		return err
	}
	return leaf.CheckSignature(x509.ECDSAWithSHA256, []byte(message), sig)
}
