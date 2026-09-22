// Package mtls builds the TLS settings for this service's listener and for the
// connections it makes, and answers the question the listener cannot: *who*
// just connected.
//
// The project's Transport Contract (docs/division.md §2) requires internal
// service-to-service traffic to use TLS 1.3 with mutual certificate
// verification against a shared self-signed CA. Person 5's deliverable says
// "validate client certificates on every incoming connection", so this package
// is not a configuration convenience — it is the control.
//
// Two design points worth stating, because both are easy to get wrong:
//
//  1. The TLS material is loaded from files that the transport configuration
//     names, exactly as telemetry/internal/tlsconf does; a service that cannot
//     produce its certificate must not accept traffic, so every failure here is
//     fatal at startup.
//
//  2. A certificate that chains to the shared CA proves a caller is inside the
//     trust domain. It does not prove *which* service the caller is, and it
//     does not prove the caller was authorized to reach this endpoint. That is
//     PeerIdentity's job, and the caller-side allowlist lives in the API
//     (internal/httpapi), not in the handshake.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// MinVersion is the TLS version the Transport Contract names. It is a constant
// rather than a setting: a contract that can be negotiated down is not a
// contract.
const MinVersion = tls.VersionTLS13

// ServerSettings is the listener's TLS material.
type ServerSettings struct {
	CertFile string
	KeyFile  string
	// CAFile is the shared CA that signed the callers' certificates.
	CAFile string
	// RequireClientCert makes the listener mutual.
	RequireClientCert bool
}

// Enabled reports whether TLS material was supplied.
func (s ServerSettings) Enabled() bool {
	return s.CertFile != "" || s.KeyFile != "" || s.CAFile != ""
}

// Validate reports whether the settings are internally consistent.
func (s ServerSettings) Validate() error {
	if (s.CertFile == "") != (s.KeyFile == "") {
		return errors.New("mtls: a server certificate and its key must be configured together")
	}
	if s.RequireClientCert && s.CAFile == "" {
		return errors.New("mtls: requiring a client certificate needs the CA that signed it")
	}
	return nil
}

// ServerConfig returns the listener configuration.
//
// With RequireClientCert (the default) a peer that presents no certificate, or
// one that does not chain to CAFile, is refused *during the handshake*: no
// handler, no route, no policy call, no ledger row.
func (s ServerSettings) ServerConfig() (*tls.Config, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	config := &tls.Config{
		MinVersion: MinVersion,
		ClientAuth: tls.NoClientCert,
	}
	if s.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("mtls: cannot load the server certificate %q and key %q: %w",
				s.CertFile, s.KeyFile, err)
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
			// Staged roll-out only (PAYMENT_TLS_REQUIRE_CLIENT_CERT=false): a
			// certificate that *is* offered is still verified against the CA,
			// and the API refuses an unverified connection later. Startup warns
			// loudly.
			config.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return config, nil
}

// ClientSettings is one side of an outbound TLS connection.
type ClientSettings struct {
	CertFile string
	KeyFile  string
	// CAFile is the authority the *server* must chain to. Empty falls back to
	// the system pool, which is the right default for the IdP's JWKS endpoint if
	// it is ever reached over a public certificate.
	CAFile string
	// ServerName overrides the name verified in the server certificate.
	ServerName string
	// MinVersion defaults to MinVersion when zero, so no caller can
	// accidentally negotiate TLS 1.0 on an internal link.
	MinVersion uint16
}

// Enabled reports whether any TLS setting was supplied.
func (c ClientSettings) Enabled() bool {
	return c.CertFile != "" || c.KeyFile != "" || c.CAFile != "" || c.ServerName != ""
}

// Config returns the dialing configuration.
func (c ClientSettings) Config() (*tls.Config, error) {
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, errors.New("mtls: a client certificate and its key must be configured together")
	}
	minVersion := c.MinVersion
	if minVersion == 0 {
		minVersion = MinVersion
	}
	config := &tls.Config{
		MinVersion: minVersion,
		ServerName: strings.TrimSpace(c.ServerName),
	}
	if c.CAFile != "" {
		// Trust only the shared CA rather than the system pool: this is an
		// internal channel, and a certificate from a public authority is not a
		// reason to accept a connection to the Account Service.
		pool, err := loadCertPool(c.CAFile)
		if err != nil {
			return nil, err
		}
		config.RootCAs = pool
	}
	if c.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("mtls: cannot load the client certificate %q and key %q: %w",
				c.CertFile, c.KeyFile, err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

// Peer is the authenticated identity of a connected client.
type Peer struct {
	// Identity is the client's service identity: the leaf certificate's common
	// name, or its first DNS/URI name when the common name is empty (a
	// certificate that identifies itself only in the SAN list, which is what
	// RFC 6125 and modern practice prefer).
	Identity string
	// Subject is the certificate's full subject, for the log line.
	Subject string
	// SerialNumber identifies the exact certificate, so a decision can name the
	// credential rather than only the service.
	SerialNumber string
	// Verified reports whether the client certificate was verified against the
	// configured CA on this connection.
	Verified bool
}

// PeerIdentity extracts the authenticated identity from an established
// connection.
//
// Verified is derived from the TLS state of *this* connection and never from a
// header. A service that trusted an `X-Client-Verified: true` header would let
// any caller assert its own authorization — the classic Zero-Trust failure.
func PeerIdentity(state *tls.ConnectionState) (Peer, bool) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return Peer{}, false
	}
	verified := len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) > 0

	leaf := state.PeerCertificates[0]
	identity := strings.TrimSpace(leaf.Subject.CommonName)
	if identity == "" && len(leaf.DNSNames) > 0 {
		identity = strings.TrimSpace(leaf.DNSNames[0])
	}
	if identity == "" && len(leaf.URIs) > 0 {
		identity = leaf.URIs[0].String()
	}

	return Peer{
		Identity:     identity,
		Subject:      leaf.Subject.String(),
		SerialNumber: leaf.SerialNumber.String(),
		Verified:     verified,
	}, true
}

// Allowed reports whether the peer's identity is in the allowlist. An empty
// allowlist means "any CA-verified client", which is what a service with no
// named callers would configure; the default configuration names them.
func (p Peer) Allowed(allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}
	for _, allowed := range allowlist {
		if strings.EqualFold(strings.TrimSpace(allowed), p.Identity) {
			return true
		}
	}
	return false
}

// loadCertPool reads a PEM bundle into a certificate pool.
//
// AppendCertsFromPEM reports false for a file that parses but holds no
// certificate; treating that as success would silently trust nothing and
// reject every peer at handshake time, far from the cause.
func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mtls: cannot read the CA file %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("mtls: the CA file %q contains no PEM certificate", path)
	}
	return pool, nil
}

// OutboundServerName derives the name to verify in a server's certificate from
// the URL the caller dialed, so an internal https://account-service:8082 URL
// verifies the certificate issued to `account-service`.
func OutboundServerName(rawURL string) string {
	host := rawURL
	if index := strings.Index(host, "://"); index >= 0 {
		host = host[index+3:]
	}
	if index := strings.IndexAny(host, "/?#"); index >= 0 {
		host = host[:index]
	}
	if name, _, err := net.SplitHostPort(host); err == nil {
		return name
	}
	return host
}
