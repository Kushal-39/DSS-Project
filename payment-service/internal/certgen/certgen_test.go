package certgen

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteBundleProducesUsableMaterial(t *testing.T) {
	dir := t.TempDir()

	created, err := WriteBundle(dir, DefaultHosts, false)
	if err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	if !created {
		t.Fatal("WriteBundle reported no work on an empty directory")
	}

	for _, name := range AllFiles() {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}

	// The server certificate must be verifiable against the CA and carry the
	// names a client dials: modern TLS ignores the common name, so a certificate
	// without SANs is one nobody can connect to.
	ca := parseCert(t, dir, CAFile)
	server := parseCert(t, dir, ServerFile)

	if _, err := server.Verify(x509.VerifyOptions{
		Roots:     poolOf(ca),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "payment-service",
	}); err != nil {
		t.Errorf("the server certificate does not verify for payment-service: %v", err)
	}
	if _, err := server.Verify(x509.VerifyOptions{
		Roots:     poolOf(ca),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "localhost",
	}); err != nil {
		t.Errorf("the server certificate does not verify for localhost (the health check's name): %v", err)
	}
	if !ca.IsCA {
		t.Error("the CA certificate is not marked as a CA")
	}

	// Each client identity must be usable for client authentication and chain to
	// the same CA, because that is what the peer allowlist will match on.
	for _, name := range []string{AccountServiceFile, GatewayFile, ProbeFile, ServerClientFile} {
		leaf := parseCert(t, dir, name)
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:     poolOf(ca),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			t.Errorf("%s does not verify for client authentication: %v", name, err)
		}
	}
	if name := parseCert(t, dir, ProbeFile).Subject.CommonName; name != "probe" {
		t.Errorf("probe certificate common name = %q, want probe", name)
	}
}

// A private key on disk must not be readable by every user on the machine.
func TestPrivateKeysAreNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteBundle(dir, DefaultHosts, false); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	if runtime.GOOS == "windows" {
		// Windows has no POSIX file modes: Go synthesises 0666 for any writable
		// file and access is governed by ACLs inherited from the directory.
		// The protection there is that ./certs is gitignored and development
		// only, which docs/decisions.md states rather than implies.
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	for _, name := range []string{CAKeyFile, ServerKeyFile, ServerClientKeyFile, ProbeKeyFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is readable by group/other (%v)", name, info.Mode().Perm())
		}
	}
}

func TestWriteBundleIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := WriteBundle(dir, DefaultHosts, false); err != nil {
		t.Fatalf("first WriteBundle: %v", err)
	}

	created, err := WriteBundle(dir, DefaultHosts, false)
	if err != nil {
		t.Fatalf("second WriteBundle: %v", err)
	}
	if created {
		t.Error("a complete bundle must not be regenerated (that would invalidate every distributed certificate)")
	}

	// An incomplete bundle is refused rather than half-written: files from two
	// different CAs produce "certificate signed by unknown authority" for a
	// certificate that was just generated.
	if err := os.Remove(filepath.Join(dir, ProbeFile)); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := WriteBundle(dir, DefaultHosts, false); err == nil {
		t.Error("an incomplete bundle must be refused without --force")
	}
	if created, err := WriteBundle(dir, DefaultHosts, true); err != nil || !created {
		t.Errorf("--force must regenerate the bundle (created=%v err=%v)", created, err)
	}
}

func parseCert(t *testing.T, dir, name string) *x509.Certificate {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("%s is not PEM", name)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return certificate
}

func poolOf(certificate *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return pool
}
