// Package certgen mints the local development certificate authority and the
// certificates the mTLS path needs.
//
// Why it exists: the Transport Contract (docs/division.md §2) is the shared
// self-signed CA, and Person 2 owns it. Until it lands, "strict mTLS
// enforcement" is unverifiable — the listener would have nothing to present and
// nothing to verify against. This package closes that gap so the control can be
// demonstrated, tested and reviewed today, and so the moment Person 2 publishes
// the real CA, switching to it is a configuration change (PAYMENT_TLS_* points
// at the new files) rather than a code change.
//
// It is deliberately NOT a general-purpose PKI:
//
//   - The certificates are for `docker compose up` on a developer machine.
//     The keys are written to disk, and a key on disk is a key that can leak.
//     Nothing here is acceptable for production, where certificates come from
//     the organisation's CA and the private key never leaves a KMS/HSM.
//   - The identities match the Compose service names (`gateway`,
//     `account-service`, `payment-service`), because that is what the
//     allowlist and the certificate SANs have to agree on.
//
// One platform caveat worth stating rather than discovering: on Windows, Go's
// file modes are advisory and access is governed by ACLs inherited from the
// directory, so a private key generated there is readable by the user account
// even though this package asks for 0600. The mitigation is that ./certs is
// gitignored and development-only, which is why the generated CA is documented
// as unreachable from any shared environment.
package certgen

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

// Lifetimes. A development CA that expires in a day breaks an integration test
// on an unrelated Monday; these are long enough to be forgotten about and short
// enough that they are clearly not production credentials.
const (
	caLifetime       = 10 * 365 * 24 * time.Hour
	leafLifetime     = 365 * 24 * time.Hour
	organizationName = "DSS-Project-Dev"
)

// DefaultHosts are the subject alternative names the payment service's
// certificate carries: the Compose service name (what the Account Service and
// the gateway dial) and localhost/loopback (what the container's own health
// check dials).
var DefaultHosts = []string{"payment-service", "localhost"}

// DefaultLoopback addresses, for the health check inside the container.
var DefaultLoopback = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

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
	KeyPEM  []byte
}

// Names of the generated files, exported so the Compose file, the health check
// and the README can all name the same thing.
const (
	CAFile                = "ca.crt"
	CAKeyFile             = "ca.key"
	ServerFile            = "payment-service.crt"
	ServerKeyFile         = "payment-service.key"
	ServerClientFile      = "payment-service-client.crt"
	ServerClientKeyFile   = "payment-service-client.key"
	AccountServiceFile    = "account-service.crt"
	AccountServiceKeyFile = "account-service.key"
	GatewayFile           = "gateway.crt"
	GatewayKeyFile        = "gateway.key"
	ProbeFile             = "probe.crt"
	ProbeKeyFile          = "probe.key"
)

// AllFiles lists every file a complete bundle contains.
func AllFiles() []string {
	return []string{
		CAFile, CAKeyFile,
		ServerFile, ServerKeyFile,
		ServerClientFile, ServerClientKeyFile,
		AccountServiceFile, AccountServiceKeyFile,
		GatewayFile, GatewayKeyFile,
		ProbeFile, ProbeKeyFile,
	}
}

// NewCA generates a self-signed certificate authority.
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("certgen: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{organizationName}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caLifetime),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("certgen: create the CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certgen: parse the CA certificate: %w", err)
	}
	return &CA{
		Cert:    certificate,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  encodeECKey(key),
	}, nil
}

// Issue signs a leaf certificate.
//
// A server certificate carries the DNS names and IPs it can be reached at —
// modern TLS ignores the common name for hostname verification, so a
// certificate without SANs is a certificate nobody can connect to — and an
// extended key usage that matches its role. A client certificate is issued for
// client authentication only, so a client certificate that is stolen cannot be
// used to impersonate a server.
func (ca *CA) Issue(commonName string, server bool, dnsNames []string, ips []net.IP) (*Bundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("certgen: generate the key for %s: %w", commonName, err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{organizationName}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = dnsNames
		template.IPAddresses = ips
	} else {
		// The identity of a client certificate is read from the SAN list when
		// no common name is present, so it is set here too.
		template.DNSNames = []string{commonName}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("certgen: create the certificate for %s: %w", commonName, err)
	}
	return &Bundle{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  encodeECKey(key),
	}, nil
}

// WriteBundle generates a complete set of mTLS material into dir.
//
// It is idempotent: when every file already exists it does nothing and returns
// false, which is what makes it safe to run on every container start. If only
// some files exist the result is an error unless force is set, because a
// half-present bundle means the files come from different CAs — the single most
// confusing mTLS failure to debug ("certificate signed by unknown authority"
// for a certificate you just generated).
func WriteBundle(dir string, hosts []string, force bool) (bool, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("certgen: cannot create %s: %w", dir, err)
	}

	switch present, missing := countFiles(dir); {
	case missing == 0 && !force:
		return false, nil
	case present > 0 && missing > 0 && !force:
		return false, fmt.Errorf(
			"certgen: %s holds an incomplete bundle (%d of %d files present); re-run with --force to "+
				"regenerate every file, or delete the directory", dir, present, len(AllFiles()))
	}

	ca, err := NewCA("dss-project-dev-ca")
	if err != nil {
		return false, err
	}

	server, err := ca.Issue("payment-service", true, hosts, DefaultLoopback)
	if err != nil {
		return false, err
	}
	serverClient, err := ca.Issue("payment-service-client", false, nil, nil)
	if err != nil {
		return false, err
	}
	accountService, err := ca.Issue("account-service", false, nil, nil)
	if err != nil {
		return false, err
	}
	gateway, err := ca.Issue("gateway", false, nil, nil)
	if err != nil {
		return false, err
	}
	// The probe identity is what the container's own health check presents. It
	// is a client certificate like any other, and it is deliberately NOT in the
	// business allowlist: the diagnostic credential can ask whether the service
	// is alive, and cannot move money.
	probe, err := ca.Issue("probe", false, nil, nil)
	if err != nil {
		return false, err
	}

	files := []struct {
		name    string
		pem     []byte
		private bool
	}{
		{CAFile, ca.CertPEM, false},
		{CAKeyFile, ca.KeyPEM, true},
		{ServerFile, server.CertPEM, false},
		{ServerKeyFile, server.KeyPEM, true},
		{ServerClientFile, serverClient.CertPEM, false},
		{ServerClientKeyFile, serverClient.KeyPEM, true},
		{AccountServiceFile, accountService.CertPEM, false},
		{AccountServiceKeyFile, accountService.KeyPEM, true},
		{GatewayFile, gateway.CertPEM, false},
		{GatewayKeyFile, gateway.KeyPEM, true},
		{ProbeFile, probe.CertPEM, false},
		{ProbeKeyFile, probe.KeyPEM, true},
	}

	for _, file := range files {
		// Private keys are 0600; certificates are world-readable so a host user
		// can pass them to curl.
		mode := os.FileMode(0o644)
		if file.private {
			mode = 0o600
		}
		path := filepath.Join(dir, file.name)
		if err := os.WriteFile(path, file.pem, mode); err != nil {
			return false, fmt.Errorf("certgen: cannot write %s: %w", path, err)
		}
	}
	return true, nil
}

func countFiles(dir string) (present, missing int) {
	for _, name := range AllFiles() {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			present++
		} else {
			missing++
		}
	}
	return present, missing
}

func encodeECKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		// MarshalECPrivateKey only fails on an invalid curve, which cannot
		// happen for a key this package just generated.
		panic(fmt.Sprintf("certgen: cannot marshal the private key: %v", err))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certgen: generate a serial number: %w", err)
	}
	return serial, nil
}
