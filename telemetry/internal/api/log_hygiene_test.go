package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"telemetry/internal/audit"
	"telemetry/internal/store"
)

// A log line is the most common way a credential leaks: the token ends up in a
// URL, the URL ends up in an access log, the access log ends up exported to a
// log store with different access rules from the audit trail itself. This test
// performs the requests that carry credentials and asserts that neither the
// ingest token nor the read token can be recovered from the logs.
func TestCredentialsNeverReachTheLogOutput(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := testConfig()
	cfg.ReadToken = readToken
	auditStore := store.NewMemory()
	server := httptest.NewServer(New(logger, cfg, auditStore, nil, now).Handler())
	t.Cleanup(server.Close)

	// A correct ingest push, a rejected ingest push, a dashboard sign-in, a
	// rejected read, and an ingest payload that happens to quote a token: every
	// path where a credential is in play.
	do(t, server, http.MethodPost, "/v1/audit/logs",
		`{"time":"2026-09-21T11:59:00Z","msg":"http_request","method":"GET","path":"/","status":200}`,
		map[string]string{"X-Telemetry-Token": ingestToken})
	do(t, server, http.MethodPost, "/v1/audit/logs",
		`{"msg":"login_attempt","outcome":"denied"}`,
		map[string]string{"X-Telemetry-Token": "wrong-" + ingestToken})
	do(t, server, http.MethodPost, "/v1/audit/events",
		`{"msg":"access_decision","decision":"deny","reason":"probe"}`,
		map[string]string{"Authorization": "Bearer " + ingestToken})
	do(t, server, http.MethodGet, "/dashboard?token="+readToken, "", nil)
	do(t, server, http.MethodGet, "/v1/audit/summary", "", map[string]string{"X-Telemetry-Token": readToken})

	output := logged.String()
	if output == "" {
		t.Fatal("nothing was logged, so this test proves nothing")
	}
	for name, secret := range map[string]string{"ingest token": ingestToken, "read token": readToken} {
		if strings.Contains(output, secret) {
			t.Errorf("%s appears in the log output:\n%s", name, output)
		}
	}

	// The queries a browser makes are logged with their method, their path and
	// their status — but never with the query string that carried the token.
	if strings.Contains(output, "token=") {
		t.Errorf("a query string carrying a token was logged:\n%s", output)
	}
}

// The readiness and metrics endpoints are what a platform probes; they must not
// be the one place a credential is echoed back.
func TestOperationalEndpointsDoNotReflectConfiguration(t *testing.T) {
	cfg := testConfig()
	cfg.ReadToken = readToken
	server := httptest.NewServer(New(slog.New(slog.NewTextHandler(io.Discard, nil)), cfg, store.NewMemory(), nil, now).Handler())
	t.Cleanup(server.Close)

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		response, payload := do(t, server, http.MethodGet, path, "", nil)
		if response.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, response.StatusCode)
		}
		if strings.Contains(string(payload), ingestToken) || strings.Contains(string(payload), readToken) {
			t.Errorf("%s echoes a credential:\n%s", path, payload)
		}
	}
}

// A store failure must not be reported with its internal error text either: the
// dashboard is reachable by anyone the read token is shared with, and a
// connection string can appear inside a driver error.
func TestStoreErrorsAreNotEchoedToCallers(t *testing.T) {
	server := httptest.NewServer(New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testConfig(),
		failingStore{},
		nil, now,
	).Handler())
	t.Cleanup(server.Close)

	response, payload := do(t, server, http.MethodGet, "/v1/audit/summary", "", nil)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", response.StatusCode)
	}
	if strings.Contains(string(payload), "postgres://") {
		t.Errorf("the store's internal error was returned to the caller:\n%s", payload)
	}
}

// failingStore is the real Store interface with everything but the two methods
// under test left unimplemented: the failure is injected where it matters, not
// simulated for the whole surface.
type failingStore struct{ store.Store }

func (failingStore) Ping(context.Context) error { return errStoreDown }

func (failingStore) Summary(context.Context, time.Time, time.Time) (*audit.Summary, error) {
	return nil, errStoreDown
}

// errStoreDown carries a connection string, which is what a real driver error
// looks like and exactly what must not reach the caller.
var errStoreDown = errors.New("failed to connect to `host=db user=telemetry database=audit`: postgres://telemetry:secret@db:5432/audit is unreachable")
