// Package tlsconf builds the TLS settings for the audit channel.
//
// The project's Transport Contract (docs/division.md §2) requires internal
// service-to-service traffic to use TLS 1.3 with mutual certificate
// verification against the shared self-signed CA. The audit channel is
// service-to-service traffic: the collector pushes to the telemetry ingest API.
// Until the shared CA exists nothing in this repository serves TLS, so this
// package makes compliance a configuration change rather than a code change:
//
//	TELEMETRY_TLS_CERT_FILE / _KEY_FILE   serve the ingest API over TLS
//	TELEMETRY_TLS_CA_FILE                 the shared CA that signed the peers
//	TELEMETRY_TLS_REQUIRE_CLIENT_CERT     verify the collector's certificate
//	TELEMETRY_TLS_CERT_FILE / _KEY_FILE   present one when collecting
//
// Nothing here is required for the pipeline to run: with no TLS settings the
// service behaves exactly as before (plain HTTP, bearer-token authenticated),
// which is what the other components do today and what a local `docker compose
// up --build` must keep doing.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// Settings is one side of a TLS connection: the files to present, the CA to
// trust, and (for a server) whether the peer must present a certificate.
type Settings struct {
	// CertFile and KeyFile are our own certificate chain and private key.
	CertFile string
	KeyFile  string
	// CAFile is the certificate authority that signed the peer's certificate.
	// For a server it is the authority its clients must chain to; for a client
	// it is the authority the server must chain to.
	CAFile string
	// RequireClientCert makes a listener mutual: a peer without a certificate
	// signed by CAFile is refused during the handshake, before any request.
	RequireClientCert bool
	// ServerName overrides the name verified against the server certificate.
	// Empty uses the host the connection was made to, which is what a
	// service-name URL like http://telemetry:8088 should do.
	ServerName string
}

// Enabled reports whether any TLS setting was supplied.
func (s Settings) Enabled() bool {
	return s.CertFile != "" || s.KeyFile != "" || s.CAFile != ""
}

// Validate checks the settings are internally consistent, without touching the
// filesystem, so a misconfiguration is reported by name at startup.
func (s Settings) Validate() error {
	if (s.CertFile == "") != (s.KeyFile == "") {
		return fmt.Errorf("a certificate and its key must be configured together (one is set and the other is not)")
	}
	if s.RequireClientCert && s.CAFile == "" {
		return fmt.Errorf("requiring a client certificate needs the CA that signed it, otherwise there is nothing to verify against")
	}
	return nil
}

// Server returns the listener configuration, or nil when TLS is not configured.
func (s Settings) Server() (*tls.Config, error) {
	if !s.Enabled() {
		return nil, nil
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}

	config := &tls.Config{
		// The Transport Contract specifies TLS 1.3. Refusing to negotiate
		// below it is the whole point of naming a version in a contract.
		MinVersion: tls.VersionTLS13,
		// The audit API is reached by service name inside the compose network,
		// and the certificates are issued to those names.
		ClientAuth: tls.NoClientCert,
	}

	if s.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: cannot load the server certificate %q and key %q: %w", s.CertFile, s.KeyFile, err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	if s.CAFile != "" {
		pool, err := loadCertPool(s.CAFile)
		if err != nil {
			return nil, err
		}
		config.ClientCAs = pool
		if s.RequireClientCert {
			config.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			// A certificate that is offered is still recorded and verified
			// when it chains to the CA, so an operator can roll mTLS out
			// without breaking clients that have not been given one yet.
			config.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return config, nil
}

// Client returns the dialing configuration, or nil when TLS is not configured.
func (s Settings) Client() (*tls.Config, error) {
	if !s.Enabled() {
		return nil, nil
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: strings.TrimSpace(s.ServerName),
	}
	if s.CAFile != "" {
		// Trust only the shared CA rather than the system pool: this is an
		// internal channel, and a certificate from a public authority is not a
		// reason to accept a connection to the audit API.
		pool, err := loadCertPool(s.CAFile)
		if err != nil {
			return nil, err
		}
		config.RootCAs = pool
	}
	if s.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: cannot load the client certificate %q and key %q: %w", s.CertFile, s.KeyFile, err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

// loadCertPool reads a PEM bundle into a certificate pool.
//
// AppendCertsFromPEM reports false for a file that parses but holds no
// certificate, which is the error a truncated or wrongly-encoded CA file
// produces; treating that as success would silently trust nothing and reject
// every peer at handshake time, far from the cause.
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tls: cannot read the CA file %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls: the CA file %q contains no PEM certificate", path)
	}
	return pool, nil
}
