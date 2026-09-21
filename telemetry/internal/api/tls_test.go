package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"telemetry/internal/certtest"
	"telemetry/internal/store"
	"telemetry/internal/tlsconf"
)

// The Transport Contract path (docs/division.md §2), exercised through the real
// handler rather than through the configuration alone: a collector that holds a
// certificate from the shared CA can push a batch over TLS 1.3, and a peer
// without one cannot reach the ingest API at all.

type mtlsStack struct {
	server   *httptest.Server
	caFile   string
	store    *store.Memory
	clientCA *certtest.CA
}

func newMTLSStack(t *testing.T) *mtlsStack {
	t.Helper()

	ca, err := certtest.NewCA("dss-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	serverBundle, err := ca.Issue("telemetry", true, []string{"localhost", "telemetry"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("issue server certificate: %v", err)
	}
	dir := t.TempDir()
	serverCert, serverKey, err := serverBundle.WriteFiles(dir, "server")
	if err != nil {
		t.Fatalf("write server certificate: %v", err)
	}
	caFile, err := ca.WriteCAFile(dir)
	if err != nil {
		t.Fatalf("write CA: %v", err)
	}

	serverTLS, err := (tlsconf.Settings{
		CertFile:          serverCert,
		KeyFile:           serverKey,
		CAFile:            caFile,
		RequireClientCert: true,
	}).Server()
	if err != nil {
		t.Fatalf("server TLS: %v", err)
	}

	auditStore := store.NewMemory()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewUnstartedServer(New(logger, testConfig(), auditStore, nil, now).Handler())
	server.TLS = serverTLS
	server.StartTLS()
	t.Cleanup(server.Close)

	return &mtlsStack{server: server, caFile: caFile, store: auditStore, clientCA: ca}
}

// collectorClient builds the client the shipper uses, from the same settings.
func (s *mtlsStack) collectorClient(t *testing.T, certFile, keyFile string) *http.Client {
	t.Helper()
	config, err := (tlsconf.Settings{
		CAFile:   s.caFile,
		CertFile: certFile,
		KeyFile:  keyFile,
	}).Client()
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
}

const tlsBatch = `{"time":"2026-09-21T11:59:00Z","msg":"http_request","method":"POST","path":"/login","status":401}`

func TestIngestOverMutualTLS(t *testing.T) {
	stack := newMTLSStack(t)

	bundle, err := stack.clientCA.Issue("telemetry-collector", false, nil, nil)
	if err != nil {
		t.Fatalf("issue client certificate: %v", err)
	}
	certFile, keyFile, err := bundle.WriteFiles(t.TempDir(), "collector")
	if err != nil {
		t.Fatalf("write client certificate: %v", err)
	}

	request, err := http.NewRequest(http.MethodPost, stack.server.URL+"/v1/audit/logs", strings.NewReader(tlsBatch))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("X-Telemetry-Token", ingestToken)
	request.Header.Set("Content-Type", "application/x-ndjson")

	response, err := stack.collectorClient(t, certFile, keyFile).Do(request)
	if err != nil {
		t.Fatalf("a collector with a CA-issued certificate could not push over mTLS: %v", err)
	}
	defer response.Body.Close()

	payload, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}
	var receipt ingestResult
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if receipt.Accepted != 1 {
		t.Errorf("receipt = %+v, want one accepted decision", receipt)
	}
	if stack.store.Len() != 1 {
		t.Errorf("stored %d events, want 1", stack.store.Len())
	}
}

func TestIngestRefusesAPeerWithoutACertificate(t *testing.T) {
	stack := newMTLSStack(t)

	// The token alone is not enough once mTLS is required: possession of a
	// secret string must not be the only thing between an attacker and the
	// security record.
	client := stack.collectorClient(t, "", "")

	request, err := http.NewRequest(http.MethodPost, stack.server.URL+"/v1/audit/logs", strings.NewReader(tlsBatch))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("X-Telemetry-Token", ingestToken)

	if _, err := client.Do(request); err == nil {
		t.Fatal("a peer with no certificate and a valid token was served")
	}
	if stack.store.Len() != 0 {
		t.Errorf("stored %d events from an unauthenticated peer, want 0", stack.store.Len())
	}
}

// A collector that trusts the wrong authority must not connect: the audit
// channel pins the shared CA rather than accepting any valid certificate.
func TestIngestRefusesAServerItCannotVerify(t *testing.T) {
	stack := newMTLSStack(t)

	otherCA, err := certtest.NewCA("some-other-ca")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	otherCAFile, err := otherCA.WriteCAFile(t.TempDir())
	if err != nil {
		t.Fatalf("write CA: %v", err)
	}
	bundle, err := stack.clientCA.Issue("telemetry-collector", false, nil, nil)
	if err != nil {
		t.Fatalf("issue client certificate: %v", err)
	}
	certFile, keyFile, err := bundle.WriteFiles(t.TempDir(), "collector")
	if err != nil {
		t.Fatalf("write client certificate: %v", err)
	}

	config, err := (tlsconf.Settings{CAFile: otherCAFile, CertFile: certFile, KeyFile: keyFile}).Client()
	if err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}}

	if _, err := client.Get(stack.server.URL + "/healthz"); err == nil {
		t.Fatal("a client trusting an unrelated CA verified the audit API")
	}
}
