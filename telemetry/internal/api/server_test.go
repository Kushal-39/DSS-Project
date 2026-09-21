package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"telemetry/internal/audit"
	"telemetry/internal/config"
	"telemetry/internal/store"
)

const (
	traceID     = "4bf92f3577b34da6a3ce929d0e0e4736"
	ingestToken = "ingest-secret-token"
	readToken   = "read-secret-token"
)

var clock = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func now() time.Time { return clock }

// recordingForwarder stands in for the OTLP mirror to Jaeger.
type recordingForwarder struct {
	bodies [][]byte
	err    error
}

func (f *recordingForwarder) Forward(_ context.Context, body []byte) error {
	f.bodies = append(f.bodies, body)
	return f.err
}

func testConfig() *config.Config {
	return &config.Config{
		Store:           config.StoreMemory,
		IngestToken:     ingestToken,
		DefaultService:  "producer",
		MaxBodyBytes:    1 << 20,
		DashboardWindow: time.Hour,
		MaxWindow:       24 * time.Hour,
	}
}

func newTestServer(t *testing.T, cfg *config.Config, auditStore store.Store, forwarder SpanForwarder) *httptest.Server {
	t.Helper()
	if cfg == nil {
		cfg = testConfig()
	}
	if auditStore == nil {
		auditStore = store.NewMemory()
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(logger, cfg, auditStore, forwarder, now).Handler())
	t.Cleanup(server.Close)
	return server
}

func do(t *testing.T, server *httptest.Server, method, path, body string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { response.Body.Close() })
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response, payload
}

func authHeaders() map[string]string {
	return map[string]string{"X-Telemetry-Token": ingestToken, "Content-Type": "application/json"}
}

func TestIngestRequiresTheCollectorToken(t *testing.T) {
	server := newTestServer(t, nil, nil, nil)
	body := `{"msg":"http_request","method":"GET","path":"/","status":403}`

	// An unauthenticated audit endpoint lets anyone forge or flood the
	// security record, so this must be a hard 401 rather than a silent accept.
	for _, headers := range []map[string]string{
		{},
		{"X-Telemetry-Token": "wrong"},
		{"Authorization": "Bearer wrong"},
		{"Authorization": "Basic " + ingestToken},
	} {
		response, payload := do(t, server, http.MethodPost, "/v1/audit/logs", body, headers)
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("headers %v: status = %d, want 401", headers, response.StatusCode)
		}
		if !strings.Contains(string(payload), "unauthorized") {
			t.Errorf("headers %v: body = %s", headers, payload)
		}
	}
}

func TestIngestAcceptsEitherTokenHeader(t *testing.T) {
	server := newTestServer(t, nil, nil, nil)
	body := `{"msg":"http_request","method":"GET","path":"/","status":403}`

	for _, headers := range []map[string]string{
		{"X-Telemetry-Token": ingestToken},
		{"Authorization": "Bearer " + ingestToken},
	} {
		response, _ := do(t, server, http.MethodPost, "/v1/audit/logs", body, headers)
		if response.StatusCode != http.StatusOK {
			t.Errorf("headers %v: status = %d, want 200", headers, response.StatusCode)
		}
	}
}

func TestIngestLogsNormalisesAndStores(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	// A realistic collector batch: two decisions and two lines of chatter.
	body := strings.Join([]string{
		`{"time":"2026-09-21T11:59:00Z","msg":"http_request","method":"POST","path":"/login","status":401,"traceparent":"00-` + traceID + `-00f067aa0ba902b7-01"}`,
		`{"msg":"db: ping failed, retrying"}`,
		`plain text`,
		`{"time":"2026-09-21T11:59:30Z","msg":"login_attempt","outcome":"denied","username":"admin"}`,
	}, "\n")

	response, payload := do(t, server, http.MethodPost, "/v1/audit/logs", body,
		map[string]string{"X-Telemetry-Token": ingestToken, "Content-Type": "application/x-ndjson"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}

	var result ingestResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if result.Accepted != 2 || result.Skipped != 2 || result.Duplicates != 0 {
		t.Errorf("receipt = %+v, want accepted 2, skipped 2, duplicates 0", result)
	}
	if got := auditStore.Len(); got != 2 {
		t.Errorf("stored %d events, want 2", got)
	}

	// Re-ingesting the same batch is a collector retry, not a second decision.
	response, payload = do(t, server, http.MethodPost, "/v1/audit/logs", body,
		map[string]string{"X-Telemetry-Token": ingestToken, "Content-Type": "application/x-ndjson"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 0 || result.Duplicates != 2 {
		t.Errorf("second delivery = %+v, want 0 accepted and 2 duplicates", result)
	}
	if got := auditStore.Len(); got != 2 {
		t.Errorf("stored %d events after a retry, want 2", got)
	}
}

func TestIngestEventsAcceptsArraysAndEnvelopes(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	// The record carries its own timestamp, which is what makes re-delivery
	// recognisable. A record without one is timestamped at ingestion, so two
	// deliveries of it are two genuine observations rather than a retry —
	// which is why every component in this project logs "time".
	record := `{"time":"2026-09-21T11:59:00Z","msg":"access_decision","service":"policy-engine","allow":false,"reason":"threat_level_high","user_id":"customer"}`

	for _, body := range []string{
		record,
		"[" + record + "]",
		`{"events":[` + record + `]}`,
	} {
		response, payload := do(t, server, http.MethodPost, "/v1/audit/events", body, authHeaders())
		if response.StatusCode != http.StatusOK {
			t.Fatalf("body %q: status = %d, %s", body, response.StatusCode, payload)
		}
	}
	// The three shapes describe the same decision, so it is counted once.
	if got := auditStore.Len(); got != 1 {
		t.Errorf("stored %d events, want 1", got)
	}
}

func TestIngestTracesStoresSpansAndMirrorsThem(t *testing.T) {
	auditStore := store.NewMemory()
	forwarder := &recordingForwarder{}
	server := newTestServer(t, nil, auditStore, forwarder)

	body := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api-gateway"}}]},
		"scopeSpans":[{"spans":[{"traceId":"` + traceID + `","spanId":"00f067aa0ba902b7","name":"POST /api/v1/payment",
		"startTimeUnixNano":"1758440000000000000","endTimeUnixNano":"1758440000120000000",
		"status":{"code":"STATUS_CODE_ERROR"}}]}]}]}`

	response, payload := do(t, server, http.MethodPost, "/v1/traces", body, authHeaders())
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}
	var result ingestResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 1 {
		t.Errorf("receipt = %+v, want 1 accepted span", result)
	}
	if len(forwarder.bodies) != 1 {
		t.Fatalf("mirrored %d payloads, want 1 (the visual span browser needs them)", len(forwarder.bodies))
	}
	if string(forwarder.bodies[0]) != body {
		t.Error("the mirrored payload was rewritten instead of passed through")
	}
}

func TestAMirrorFailureDoesNotFailTheIngest(t *testing.T) {
	auditStore := store.NewMemory()
	forwarder := &recordingForwarder{err: errors.New("jaeger is down")}
	server := newTestServer(t, nil, auditStore, forwarder)

	body := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"` + traceID + `","spanId":"00f067aa0ba902b7","name":"x"}]}]}]}`
	response, payload := do(t, server, http.MethodPost, "/v1/traces", body, authHeaders())

	// The audit copy is what matters; failing the request would only make the
	// producer retry and duplicate work.
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}
	if forwarder.bodies == nil {
		t.Error("the mirror was not attempted")
	}
}

func TestIngestRejectsBadPayloadsWithoutStoringAnything(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	tests := []struct {
		name string
		path string
		body string
	}{
		{"not JSON at all", "/v1/audit/logs", "just some text"},
		{"malformed JSON", "/v1/audit/events", `{"msg":`},
		{"empty body", "/v1/audit/events", "   "},
		{"bad OTLP envelope", "/v1/traces", `{"resourceSpans":"nope"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, payload := do(t, server, http.MethodPost, test.path, test.body, authHeaders())
			if response.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body %s)", response.StatusCode, payload)
			}
		})
	}
	if got := auditStore.Len(); got != 0 {
		t.Errorf("a rejected payload stored %d events", got)
	}
}

func TestIngestRefusesAnOversizedPayload(t *testing.T) {
	cfg := testConfig()
	cfg.MaxBodyBytes = 512
	server := newTestServer(t, cfg, nil, nil)

	body := `{"msg":"http_request","blob":"` + strings.Repeat("x", 2048) + `"}`
	response, payload := do(t, server, http.MethodPost, "/v1/audit/logs", body, authHeaders())
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body %s)", response.StatusCode, payload)
	}
}

func TestSummaryReflectsTheWindow(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	// Inside the window.
	seed(t, auditStore, "idp", audit.CategoryAuth, audit.DecisionDeny, "invalid_credentials", "admin", clock.Add(-5*time.Minute), traceID)
	seed(t, auditStore, "api-gateway", audit.CategoryAccess, audit.DecisionPermit, "ok", "customer", clock.Add(-4*time.Minute), "")
	// Outside the window.
	seed(t, auditStore, "idp", audit.CategoryAuth, audit.DecisionDeny, "invalid_credentials", "admin", clock.Add(-3*time.Hour), "")

	response, payload := do(t, server, http.MethodGet, "/v1/audit/summary?window=1h", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}

	var envelope struct {
		Window  string        `json:"window"`
		Summary audit.Summary `json:"summary"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if envelope.Window != "1h0m0s" {
		t.Errorf("window = %q", envelope.Window)
	}
	if envelope.Summary.Total != 2 {
		t.Errorf("total = %d, want 2 (the third event is outside the window)", envelope.Summary.Total)
	}
	if envelope.Summary.Denials != 1 || envelope.Summary.UnauthorizedAttempts != 1 {
		t.Errorf("denials/unauthorized = %d/%d, want 1/1",
			envelope.Summary.Denials, envelope.Summary.UnauthorizedAttempts)
	}
	if len(envelope.Summary.LatestDenials) != 1 {
		t.Errorf("latest_denials = %d, want 1", len(envelope.Summary.LatestDenials))
	}
}

func TestSummaryClampsAnAbsurdWindow(t *testing.T) {
	server := newTestServer(t, nil, nil, nil)

	// A public read endpoint must not be usable to make the database scan
	// everything, so an over-long window is clamped rather than rejected.
	response, payload := do(t, server, http.MethodGet, "/v1/audit/summary?window=8760h", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}
	var envelope struct {
		Window string `json:"window"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Window != "24h0m0s" {
		t.Errorf("window = %q, want the 24h maximum", envelope.Window)
	}

	for _, bad := range []string{"window=banana", "window=0", "window=-1h"} {
		response, _ := do(t, server, http.MethodGet, "/v1/audit/summary?"+bad, "", nil)
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", bad, response.StatusCode)
		}
	}
}

func TestEventsFilterAndPaginate(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	for i := 0; i < 5; i++ {
		seed(t, auditStore, "idp", audit.CategoryAuth, audit.DecisionDeny, "invalid_credentials", "admin",
			clock.Add(-time.Duration(i+1)*time.Minute), "")
	}
	seed(t, auditStore, "api-gateway", audit.CategoryAccess, audit.DecisionPermit, "ok", "customer",
		clock.Add(-10*time.Minute), "")

	type envelope struct {
		Count  int           `json:"count"`
		Events []audit.Event `json:"events"`
	}

	response, payload := do(t, server, http.MethodGet, "/v1/audit/events?decision=DENY&limit=3", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var page envelope
	if err := json.Unmarshal(payload, &page); err != nil {
		t.Fatal(err)
	}
	if page.Count != 3 {
		t.Errorf("count = %d, want 3 (the page size)", page.Count)
	}
	for _, event := range page.Events {
		if event.Decision != audit.DecisionDeny {
			t.Errorf("filter leaked a %s event", event.Decision)
		}
	}

	// Newest first, and paging moves forward without repeating.
	response, payload = do(t, server, http.MethodGet, "/v1/audit/events?decision=DENY&limit=3&offset=3", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var second envelope
	if err := json.Unmarshal(payload, &second); err != nil {
		t.Fatal(err)
	}
	if second.Count != 2 {
		t.Errorf("second page count = %d, want 2", second.Count)
	}
	if len(second.Events) > 0 && len(page.Events) > 0 && second.Events[0].ID == page.Events[0].ID {
		t.Error("the second page repeats the first page's first event")
	}

	// A filter that matches nothing is an empty list, not an error.
	response, payload = do(t, server, http.MethodGet, "/v1/audit/events?service=nobody", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if err := json.Unmarshal(payload, &page); err != nil {
		t.Fatal(err)
	}
	if page.Count != 0 || page.Events == nil {
		t.Errorf("empty result = %+v, want an empty array a dashboard can render", page)
	}

	for _, bad := range []string{"limit=abc", "offset=-1"} {
		response, _ := do(t, server, http.MethodGet, "/v1/audit/events?"+bad, "", nil)
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", bad, response.StatusCode)
		}
	}
}

func TestTraceEndpointJoinsSpansAndDecisions(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	seed(t, auditStore, "idp", audit.CategoryAuth, audit.DecisionDeny, "invalid_credentials", "admin",
		clock.Add(-2*time.Minute), traceID)

	response, payload := do(t, server, http.MethodGet, "/v1/audit/traces/"+traceID, "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}
	var envelope struct {
		Trace audit.Trace `json:"trace"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Trace.TraceID != traceID || envelope.Trace.EventCount != 1 || envelope.Trace.Denied != 1 {
		t.Errorf("trace = %+v", envelope.Trace)
	}
	if len(envelope.Trace.Services) != 1 || envelope.Trace.Services[0] != "idp" {
		t.Errorf("services = %v", envelope.Trace.Services)
	}

	// An unknown trace is a 404, distinct from a malformed id, so a reviewer
	// can tell "nothing recorded" from "you pasted the wrong thing".
	response, payload = do(t, server, http.MethodGet, "/v1/audit/traces/"+strings.Repeat("b", 32), "", nil)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("unknown trace: status = %d, want 404 (%s)", response.StatusCode, payload)
	}
	for _, bad := range []string{"short", strings.Repeat("z", 32), strings.Repeat("a", 33)} {
		response, _ = do(t, server, http.MethodGet, "/v1/audit/traces/"+bad, "", nil)
		if response.StatusCode != http.StatusBadRequest {
			t.Errorf("trace id %q: status = %d, want 400", bad, response.StatusCode)
		}
	}
}

func TestReadEndpointsCanBeTokenProtected(t *testing.T) {
	cfg := testConfig()
	cfg.ReadToken = readToken
	server := newTestServer(t, cfg, nil, nil)

	for _, path := range []string{"/v1/audit/summary", "/v1/audit/events", "/dashboard"} {
		response, _ := do(t, server, http.MethodGet, path, "", nil)
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without a token: status = %d, want 401", path, response.StatusCode)
		}

		response, _ = do(t, server, http.MethodGet, path, "", map[string]string{"X-Telemetry-Token": "wrong"})
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s with a wrong token: status = %d, want 401", path, response.StatusCode)
		}

		response, _ = do(t, server, http.MethodGet, path, "", map[string]string{"X-Telemetry-Token": readToken})
		if response.StatusCode != http.StatusOK {
			t.Errorf("%s with the token: status = %d, want 200", path, response.StatusCode)
		}
	}

	// Health and metrics stay open: Docker and the platform probe them without
	// holding service tokens.
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		response, _ := do(t, server, http.MethodGet, path, "", nil)
		if response.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, response.StatusCode)
		}
	}
}

func TestDashboardIsServedAndNeedsNoBuildStep(t *testing.T) {
	server := newTestServer(t, nil, nil, nil)

	response, payload := do(t, server, http.MethodGet, "/dashboard", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("content-type = %q", contentType)
	}
	page := string(payload)
	for _, want := range []string{"Audit Dashboard", "unauthorized attempts", "Trace explorer", "/v1/audit/summary"} {
		if !strings.Contains(page, want) {
			t.Errorf("the dashboard does not mention %q", want)
		}
	}

	// The bare root redirects, so a reviewer who tries the host gets the page.
	// Redirects must be observed rather than followed here, or the assertion
	// would be testing the destination.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	rootResponse, err := noRedirect.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer rootResponse.Body.Close()
	if rootResponse.StatusCode != http.StatusFound {
		t.Errorf("GET / status = %d, want 302", rootResponse.StatusCode)
	}
	if location := rootResponse.Header.Get("Location"); location != "/dashboard" {
		t.Errorf("GET / redirects to %q, want /dashboard", location)
	}

	response, _ = do(t, server, http.MethodGet, "/nonsense", "", nil)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("GET /nonsense status = %d, want 404", response.StatusCode)
	}
}

func TestHealthReadinessAndMetrics(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	response, payload := do(t, server, http.MethodGet, "/healthz", "", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(payload), "ok") {
		t.Errorf("healthz = %d %s", response.StatusCode, payload)
	}

	response, payload = do(t, server, http.MethodGet, "/readyz", "", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(payload), "ready") {
		t.Errorf("readyz = %d %s", response.StatusCode, payload)
	}

	do(t, server, http.MethodPost, "/v1/audit/logs",
		`{"msg":"http_request","method":"GET","path":"/","status":401}`, authHeaders())
	do(t, server, http.MethodPost, "/v1/audit/logs", `plain text`, authHeaders())
	do(t, server, http.MethodPost, "/v1/audit/logs", `{}`, map[string]string{"X-Telemetry-Token": "wrong"})

	response, payload = do(t, server, http.MethodGet, "/metrics", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	metrics := string(payload)
	for _, want := range []string{
		"telemetry_events_ingested_total 1",
		"telemetry_payloads_rejected_total 1",
		"telemetry_ingest_rejections_total 1",
		"telemetry_ready 1",
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics missing %q:\n%s", want, metrics)
		}
	}
}

func TestIngestCanBeExplicitlyLeftOpenForALocalDemo(t *testing.T) {
	cfg := testConfig()
	cfg.IngestToken = ""
	cfg.InsecureIngest = true
	auditStore := store.NewMemory()
	server := newTestServer(t, cfg, auditStore, nil)

	response, payload := do(t, server, http.MethodPost, "/v1/audit/logs",
		`{"msg":"http_request","method":"GET","path":"/","status":403}`, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}
	if got := auditStore.Len(); got != 1 {
		t.Errorf("stored %d events, want 1", got)
	}
}

// seed writes an event straight into the store, so tests can control the
// clock without depending on the normaliser's own timestamps.
func seed(t *testing.T, auditStore store.Store, service string, category audit.Category,
	decision audit.Decision, reason, subject string, at time.Time, traceID string) {
	t.Helper()
	event := audit.Event{
		OccurredAt: at.UTC(),
		Category:   category,
		Decision:   decision,
		Reason:     reason,
		Service:    service,
		Subject:    subject,
		TraceID:    traceID,
		Method:     "POST",
		Path:       "/login",
		Status:     401,
	}
	event.ID = event.Fingerprint()
	if _, err := auditStore.InsertEvents(context.Background(), []audit.Event{event}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}
