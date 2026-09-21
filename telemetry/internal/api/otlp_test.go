package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"telemetry/internal/audit"
	"telemetry/internal/store"
)

// logsExport is an ExportLogsServiceRequest with one decision and one line of
// chatter, in the shape an OpenTelemetry SDK emits by default.
const logsExport = `{
  "resourceLogs": [{
    "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "api-gateway"}}]},
    "scopeLogs": [{
      "logRecords": [
        {
          "timeUnixNano": "1758440000123456789",
          "severityNumber": 17,
          "body": {"stringValue": "access_decision"},
          "attributes": [
            {"key": "decision", "value": {"stringValue": "deny"}},
            {"key": "reason", "value": {"stringValue": "threat_level_high"}},
            {"key": "user_id", "value": {"stringValue": "customer"}}
          ],
          "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
          "spanId": "00f067aa0ba902b7"
        },
        {
          "timeUnixNano": "1758440000000000000",
          "body": {"stringValue": "cache warmed"},
          "attributes": [{"key": "entries", "value": {"intValue": "42"}}]
        }
      ]
    }]
  }]
}`

// The OTLP logs signal is the difference between "point your exporter here" and
// an integration that only works if the service also prints JSON.
func TestIngestOTLPLogsStoresDecisions(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	response, payload := do(t, server, http.MethodPost, "/v1/logs", logsExport, authHeaders())
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}

	var result ingestResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if result.Accepted != 1 || result.Skipped != 1 {
		t.Errorf("receipt = %+v, want accepted 1, skipped 1", result)
	}

	events, err := auditStore.QueryEvents(context.Background(), audit.Filter{TraceID: traceID})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("stored %d events for the trace, want 1", len(events))
	}
	stored := events[0]
	if stored.IngestedVia != "otlp" {
		t.Errorf("IngestedVia = %q, want otlp", stored.IngestedVia)
	}
	if stored.Service != "api-gateway" {
		t.Errorf("Service = %q, want api-gateway", stored.Service)
	}
	if stored.Category != audit.CategoryAuthz || stored.Decision != audit.DecisionDeny {
		t.Errorf("Category/Decision = %q/%q, want AUTHZ/DENY", stored.Category, stored.Decision)
	}
	if stored.TraceID != traceID {
		t.Errorf("TraceID = %q, want %q", stored.TraceID, traceID)
	}

	// Re-exporting is a retry, not a second decision.
	response, payload = do(t, server, http.MethodPost, "/v1/logs", logsExport, authHeaders())
	if response.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d", response.StatusCode)
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 0 || result.Duplicates != 1 {
		t.Errorf("second delivery = %+v, want 0 accepted and 1 duplicate", result)
	}
}

// OTLP/protobuf is the SDK default. Refusing it with the exact setting that
// makes it work is the difference between a producer fixing its exporter and it
// giving up; a generic 400 would send the reader looking in the wrong place.
func TestIngestRejectsProtobufWithGuidance(t *testing.T) {
	server := newTestServer(t, nil, nil, nil)

	for _, path := range []string{"/v1/traces", "/v1/logs", "/v1/audit/logs"} {
		headers := authHeaders()
		headers["Content-Type"] = "application/x-protobuf"
		response, payload := do(t, server, http.MethodPost, path, "\x1a\x04\x0a\x02\x08\x01", headers)

		if response.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("%s: status = %d, want 415", path, response.StatusCode)
		}
		if !strings.Contains(string(payload), "http/json") {
			t.Errorf("%s: body = %s, want it to name the OTEL_EXPORTER_OTLP_PROTOCOL setting", path, payload)
		}
	}
}

// A decision and the span it happened inside must be reachable from the same
// trace id whichever signal carried them — otherwise the trace view has spans
// with no verdict and verdicts with no span.
func TestOTLPAndTracesJoinOnOneTraceID(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	traces := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api-gateway"}}]},
		"scopeSpans":[{"spans":[{"traceId":"` + traceID + `","spanId":"00f067aa0ba902b7","name":"POST /api/v1/payment",
		"startTimeUnixNano":"1758440000000000000","endTimeUnixNano":"1758440000120000000",
		"status":{"code":"STATUS_CODE_OK"}}]}]}]}`

	if response, payload := do(t, server, http.MethodPost, "/v1/traces", traces, authHeaders()); response.StatusCode != http.StatusOK {
		t.Fatalf("traces status = %d, body = %s", response.StatusCode, payload)
	}
	if response, payload := do(t, server, http.MethodPost, "/v1/logs", logsExport, authHeaders()); response.StatusCode != http.StatusOK {
		t.Fatalf("logs status = %d, body = %s", response.StatusCode, payload)
	}

	httpResponse, payload := do(t, server, http.MethodGet, "/v1/audit/traces/"+traceID, "", nil)
	if httpResponse.StatusCode != http.StatusOK {
		t.Fatalf("trace status = %d, body = %s", httpResponse.StatusCode, payload)
	}

	var body struct {
		Trace struct {
			Spans  []map[string]any `json:"spans"`
			Events []map[string]any `json:"events"`
		} `json:"trace"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("decode trace: %v", err)
	}
	trace := body.Trace
	if len(trace.Spans) != 1 {
		t.Errorf("trace has %d spans, want 1", len(trace.Spans))
	}
	if len(trace.Events) != 1 {
		t.Errorf("trace has %d events, want 1", len(trace.Events))
	}
}

// A record dated in the future is stored but can never appear in a dashboard
// window, which ends at now. That is how a producer logging local time with a
// "Z" suffix silently loses every decision it makes, so it is counted.
func TestFutureDatedRecordsAreStoredAndFlagged(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	ahead := clock.Add(6 * time.Hour).Format(time.RFC3339)
	record := `{"time":"` + ahead + `","msg":"login_attempt","outcome":"denied","username":"admin"}`

	response, payload := do(t, server, http.MethodPost, "/v1/audit/events", record, authHeaders())
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, payload)
	}

	// Stored: forensics keeps what the producer actually said.
	if auditStore.Len() != 1 {
		t.Errorf("stored %d events, want the record kept", auditStore.Len())
	}

	_, metrics := do(t, server, http.MethodGet, "/metrics", "", nil)
	if !strings.Contains(string(metrics), "telemetry_events_future_dated_total 1") {
		t.Errorf("the future-dated record was not counted:\n%s", metrics)
	}

	// A few minutes of ordinary clock drift is not a producer bug.
	close := `{"time":"` + clock.Add(30*time.Second).Format(time.RFC3339) + `","msg":"login_attempt","outcome":"permit"}`
	if _, payload := do(t, server, http.MethodPost, "/v1/audit/events", close, authHeaders()); !strings.Contains(string(payload), "accepted") {
		t.Fatalf("body = %s", payload)
	}
	_, metrics = do(t, server, http.MethodGet, "/metrics", "", nil)
	if !strings.Contains(string(metrics), "telemetry_events_future_dated_total 1") {
		t.Errorf("30s of drift was counted as clock skew:\n%s", metrics)
	}
}

// A malformed export must be rejected, never silently stored as nothing.
func TestIngestOTLPLogsRejectsAMalformedExport(t *testing.T) {
	auditStore := store.NewMemory()
	server := newTestServer(t, nil, auditStore, nil)

	response, payload := do(t, server, http.MethodPost, "/v1/logs", `{"resourceLogs": "not an array"}`, authHeaders())
	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
	if !strings.Contains(string(payload), "invalid_payload") {
		t.Errorf("body = %s, want an invalid_payload error", payload)
	}
	if auditStore.Len() != 0 {
		t.Errorf("stored %d events from a malformed payload", auditStore.Len())
	}
}
