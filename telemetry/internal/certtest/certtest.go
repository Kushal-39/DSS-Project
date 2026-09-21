// Package certtest mints throwaway X.509 material.
//
// It exists for two reasons. Tests need a certificate authority they control,
// and checking certificates into a repository means checking in a private key
// and a certificate that will expire on a date nobody chose. The other reason:
// until Person 2 lands the shared self-signed CA from the Transport Contract
// (docs/division.md §2), nobody can try the mTLS path at all — this is enough
// to mint one locally and watch the audit channel refuse a peer without a
// certificate.
//
// It is deliberately stdlib-only and deterministic in shape: a CA, a server
// certificate with SANs, and a client certificate.
package certtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Lifetime is how long generated material is valid.
const Lifetime = 24 * time.Hour

// Bundle is one issued certificate and its key, in PEM form.
type Bundle struct {
	CertPEM []byte
	KeyPEM  []byte
}

// CA is a generated certificate authority.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

// NewCA generates a self-signed certificate authority.
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("certtest: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(Lifetime),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("certtest: create CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certtest: parse CA certificate: %w", err)
	}
	return &CA{
		Cert:    certificate,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// Issue signs a leaf certificate. A server certificate gets the given names in
// its SAN list (verification ignores the common name in modern TLS, so a
// certificate without SANs is a certificate nobody can connect to); a client
// certificate is issued for client authentication.
func (ca *CA) Issue(commonName string, server bool, dnsNames []string, ips []net.IP) (*Bundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("certtest: generate key for %s: %w", commonName, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(Lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = dnsNames
		template.IPAddresses = ips
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("certtest: create certificate for %s: %w", commonName, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("certtest: marshal key for %s: %w", commonName, err)
	}
	return &Bundle{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// WriteFiles writes the bundle into dir as <prefix>.crt and <prefix>.key and
// returns the paths, in the shape tlsconf.Settings expects.
func (b *Bundle) WriteFiles(dir, prefix string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, prefix+".crt")
	keyPath = filepath.Join(dir, prefix+".key")
	if err := os.WriteFile(certPath, b.CertPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("certtest: write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, b.KeyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("certtest: write %s: %w", keyPath, err)
	}
	return certPath, keyPath, nil
}

// WriteCAFile writes the CA certificate into dir and returns its path.
func (ca *CA) WriteCAFile(dir string) (string, error) {
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, ca.CertPEM, 0o600); err != nil {
		return "", fmt.Errorf("certtest: write %s: %w", path, err)
	}
	return path, nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certtest: generate serial: %w", err)
	}
	return serial, nil
}
