package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"paymentservice/internal/certgen"
)

// material mints a development bundle into a temporary directory and returns the
// paths the settings need.
type material struct {
	dir        string
	caFile     string
	certFile   string
	keyFile    string
	clientCert string
	clientKey  string
}

func newMaterial(t *testing.T) material {
	t.Helper()
	dir := t.TempDir()
	if _, err := certgen.WriteBundle(dir, certgen.DefaultHosts, false); err != nil {
		t.Fatalf("certgen.WriteBundle: %v", err)
	}
	return material{
		dir:        dir,
		caFile:     filepath.Join(dir, certgen.CAFile),
		certFile:   filepath.Join(dir, certgen.ServerFile),
		keyFile:    filepath.Join(dir, certgen.ServerKeyFile),
		clientCert: filepath.Join(dir, certgen.AccountServiceFile),
		clientKey:  filepath.Join(dir, certgen.AccountServiceKeyFile),
	}
}

func TestServerSettingsRequireMutualTLS(t *testing.T) {
	m := newMaterial(t)

	settings := ServerSettings{CertFile: m.certFile, KeyFile: m.keyFile, CAFile: m.caFile, RequireClientCert: true}
	config, err := settings.ServerConfig()
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	if config.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3 (the Transport Contract names the version)", config.MinVersion)
	}
	if config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", config.ClientAuth)
	}

	// Requiring a client certificate without a CA has nothing to verify against.
	broken := ServerSettings{CertFile: m.certFile, KeyFile: m.keyFile, RequireClientCert: true}
	if _, err := broken.ServerConfig(); err == nil {
		t.Error("requiring a client certificate without a CA must be refused")
	} else if !strings.Contains(err.Error(), "CA") {
		t.Errorf("the error must name the missing CA, got %v", err)
	}

	// A certificate without its key cannot serve anything.
	if _, err := (ServerSettings{CertFile: m.certFile, RequireClientCert: false}).ServerConfig(); err == nil {
		t.Error("a certificate without its private key must be refused")
	}

	// The staged-rollout mode still verifies a certificate that is offered.
	staged := ServerSettings{CertFile: m.certFile, KeyFile: m.keyFile, CAFile: m.caFile}
	stagedConfig, err := staged.ServerConfig()
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	if stagedConfig.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", stagedConfig.ClientAuth)
	}
}

func TestClientSettingsBuildAMutualConfiguration(t *testing.T) {
	m := newMaterial(t)

	settings := ClientSettings{
		CertFile: filepath.Join(m.dir, certgen.ServerClientFile),
		KeyFile:  filepath.Join(m.dir, certgen.ServerClientKeyFile),
		CAFile:   m.caFile,
	}
	config, err := settings.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if config.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", config.MinVersion)
	}
	if len(config.Certificates) != 1 {
		t.Error("the client identity was not loaded")
	}
	if config.RootCAs == nil {
		t.Error("the shared CA must replace the system pool on an internal channel")
	}

	// A client certificate without its key is a configuration error, not a
	// silent fall back to "no client identity".
	if _, err := (ClientSettings{CertFile: settings.CertFile}).Config(); err == nil {
		t.Error("a client certificate without its key must be refused")
	}
}

func TestPeerIdentityPrefersTheCommonNameAndRequiresAChain(t *testing.T) {
	m := newMaterial(t)
	leaf := loadLeaf(t, m.clientCert)

	identity, ok := PeerIdentity(&tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, loadLeaf(t, m.caFile)}},
	})
	if !ok {
		t.Fatal("a presented certificate must produce a peer")
	}
	if identity.Identity != "account-service" {
		t.Errorf("identity = %q, want account-service", identity.Identity)
	}
	if !identity.Verified {
		t.Error("a certificate with a verified chain must be reported as verified")
	}
	if identity.SerialNumber == "" {
		t.Error("the certificate serial number is part of the evidence and must be reported")
	}

	// An unverified chain is not an identity: that is the distinction the whole
	// allowlist rests on.
	unverified, _ := PeerIdentity(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}})
	if unverified.Verified {
		t.Error("a certificate with no verified chain must not be reported as verified")
	}

	if _, ok := PeerIdentity(&tls.ConnectionState{}); ok {
		t.Error("a connection with no peer certificate must not produce an identity")
	}
	if _, ok := PeerIdentity(nil); ok {
		t.Error("a nil connection state must not produce an identity")
	}
}

func TestPeerAllowedMatchesOnlyTheAllowlist(t *testing.T) {
	allowlist := []string{"gateway", "account-service"}

	if !(Peer{Identity: "gateway"}).Allowed(allowlist) {
		t.Error("an allowlisted identity must be allowed")
	}
	if !(Peer{Identity: "ACCOUNT-SERVICE"}).Allowed(allowlist) {
		t.Error("the comparison must be case-insensitive (certificates are not consistent)")
	}
	// The probe certificate is a valid CA-signed credential that must NOT be able
	// to move money.
	if (Peer{Identity: "probe"}).Allowed(allowlist) {
		t.Error("an identity outside the allowlist must be refused")
	}
	if !(Peer{Identity: "anything"}).Allowed(nil) {
		t.Error("an empty allowlist means \"any CA-verified client\"")
	}
}

type handshakeResult struct {
	status     int
	body       string
	clientErr  error
	rejections []Rejection
}

// runHandshake starts a real mTLS server over a real listener and performs one
// request with the given client configuration.
//
// The client certificate and its key always come from the same bundle: pairing a
// certificate with another CA's key is a loading error, not a handshake failure,
// and would test nothing.
func runHandshake(t *testing.T, m material, clientMaterial material, useClientCert bool, extraRejections int) handshakeResult {
	t.Helper()

	serverConfig, err := ServerSettings{
		CertFile:          m.certFile,
		KeyFile:           m.keyFile,
		CAFile:            m.caFile,
		RequireClientCert: true,
	}.ServerConfig()
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rejections := make(chan Rejection, 32)
	listener := NewListener(raw, serverConfig, 2*time.Second, func(rejection Rejection) {
		rejections <- rejection
	})

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			t.Error("a handler must never run for an unverified connection")
		}
		fmt.Fprint(w, "ok")
	})}
	// net/http logs every refused accept through its ErrorLog; the rejections are
	// asserted directly, so the doubling noise is discarded.
	server.ErrorLog = log.New(io.Discard, "", 0)
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(readFile(t, m.caFile))
	clientTLS.RootCAs = pool
	if useClientCert {
		certificate, err := tls.LoadX509KeyPair(clientMaterial.clientCert, clientMaterial.clientKey)
		if err != nil {
			t.Fatalf("load client certificate: %v", err)
		}
		clientTLS.Certificates = []tls.Certificate{certificate}
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS}}

	response, err := client.Get("https://" + raw.Addr().String() + "/healthz")
	result := handshakeResult{clientErr: err}
	if err == nil {
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		result.status = response.StatusCode
		result.body = string(body)
	}

	// Give the listener a moment to report the rejection it just made.
	for i := 0; i < extraRejections; i++ {
		_, _ = client.Get("https://" + raw.Addr().String() + "/healthz")
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case rejection := <-rejections:
			result.rejections = append(result.rejections, rejection)
			continue
		case <-time.After(150 * time.Millisecond):
		case <-deadline:
		}
		break
	}
	return result
}

func TestListenerAcceptsACAVerifiedClient(t *testing.T) {
	m := newMaterial(t)
	result := runHandshake(t, m, m, true, 0)

	if result.clientErr != nil {
		t.Fatalf("a CA-signed client must complete the handshake: %v", result.clientErr)
	}
	if result.status != http.StatusOK || result.body != "ok" {
		t.Fatalf("status = %d body = %q", result.status, result.body)
	}
	if len(result.rejections) != 0 {
		t.Fatalf("no rejection was expected, got %+v", result.rejections)
	}
}

func TestListenerRefusesAClientWithNoCertificate(t *testing.T) {
	m := newMaterial(t)
	result := runHandshake(t, m, m, false, 0)

	if result.clientErr == nil {
		t.Fatal("a client without a certificate must not be served")
	}
	if len(result.rejections) != 1 {
		t.Fatalf("expected exactly one reported rejection, got %+v", result.rejections)
	}
	// This line is the point of performing the handshake in the listener: the
	// refusal never reaches a handler, so without it the most common
	// integration failure in this project would leave no trace at all.
	if result.rejections[0].Reason != ReasonNoCertificate {
		t.Errorf("reason = %q, want %q", result.rejections[0].Reason, ReasonNoCertificate)
	}
	if result.rejections[0].RemoteAddr == "" {
		t.Error("a rejection must name the peer it refused")
	}
}

func TestListenerRefusesACertificateFromAnotherCA(t *testing.T) {
	m := newMaterial(t)
	foreign := newMaterial(t) // a different CA entirely

	result := runHandshake(t, m, foreign, true, 0)

	if result.clientErr == nil {
		t.Fatal("a certificate from another CA must not be served")
	}
	if len(result.rejections) != 1 {
		t.Fatalf("expected exactly one rejection, got %+v", result.rejections)
	}
	rejection := result.rejections[0]
	if rejection.Reason != ReasonUntrustedCertificate {
		t.Errorf("reason = %q, want %q", rejection.Reason, ReasonUntrustedCertificate)
	}
	// The offered certificate is available on the failed handshake, so the audit
	// line can name the caller instead of only saying "someone".
	if rejection.Identity != "account-service" {
		t.Errorf("identity = %q, want the offered certificate's name", rejection.Identity)
	}
}

func TestListenerRefusesAPlainTCPClientAndKeepsServing(t *testing.T) {
	m := newMaterial(t)

	serverConfig, err := ServerSettings{
		CertFile: m.certFile, KeyFile: m.keyFile, CAFile: m.caFile, RequireClientCert: true,
	}.ServerConfig()
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rejections := make(chan Rejection, 8)
	listener := NewListener(raw, serverConfig, 2*time.Second, func(rejection Rejection) {
		rejections <- rejection
	})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	// A client that speaks HTTP, not TLS. The refuse path must not take the
	// serve loop down: returning a permanent error here would stop the service
	// on the first scanner.
	connection, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fmt.Fprint(connection, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
	_ = connection.Close()

	// Give the listener a moment to finish classifying the bad client's handshake
	// and return to a clean accept loop before we probe it — otherwise we are
	// racing the monitor goroutine that hands successful handshakes back to
	// Accept.
	time.Sleep(300 * time.Millisecond)

	select {
	case rejection := <-rejections:
		if rejection.Reason != ReasonNotTLS && rejection.Reason != ReasonHandshakeFailed {
			t.Errorf("reason = %q, want a non-TLS or generic handshake failure", rejection.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a non-TLS client must be reported")
	}

	// In case Go's TLS handshake first recorded the plain text as a transient
	// accept error, clear it now so the listener's next Accept is not handed a
	// stale error.
	listener.ClearAcceptErr()

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLSConfig(t, m)}}
	response, err := client.Get("https://" + raw.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("the server stopped serving after a bad client: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
}

// Every refusal is refused, but reporting all of them would let a port scan fill
// the audit store. The bound is the report rate, not the refusal — so this is
// asserted on the limiter directly rather than through the network, where
// net/http's own accept backoff would space the attempts out past the window.
func TestRejectionReportingIsRateLimited(t *testing.T) {
	listener := &Listener{}
	listener.windowFrom = time.Now()

	reported := 0
	for attempt := 0; attempt < 200; attempt++ {
		if report, _ := listener.record(); report {
			reported++
		}
	}

	if reported != rateBurst {
		t.Errorf("reported = %d, want the burst of %d", reported, rateBurst)
	}

	// Reporting resumes in the next window, and the first report of it carries
	// the count that was suppressed — a sustained refusal stays visible instead
	// of disappearing into the limiter.
	listener.windowFrom = time.Now().Add(-2 * rateWindow)
	report, suppressed := listener.record()
	if !report {
		t.Fatal("reporting must resume after the window elapses")
	}
	if suppressed != 200-rateBurst {
		t.Errorf("the first report of the next window carried suppressed = %d, want %d",
			suppressed, 200-rateBurst)
	}
}

func TestOutboundServerNameStripsSchemePortAndPath(t *testing.T) {
	cases := map[string]string{
		"https://account-service:8082":          "account-service",
		"https://policy-engine:8181/v1/data":    "policy-engine",
		"account-service:8082":                  "account-service",
		"http://idp:8080/.well-known/jwks.json": "idp",
	}
	for input, want := range cases {
		if got := OutboundServerName(input); got != want {
			t.Errorf("OutboundServerName(%q) = %q, want %q", input, got, want)
		}
	}
}

func clientTLSConfig(t *testing.T, m material) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(readFile(t, m.caFile))
	certificate, err := tls.LoadX509KeyPair(m.clientCert, m.clientKey)
	if err != nil {
		t.Fatalf("load client certificate: %v", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{certificate},
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func loadLeaf(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(readFile(t, path))
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return certificate
}
