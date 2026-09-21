package otlp

import (
	"encoding/json"
	"strings"
	"testing"

	"telemetry/internal/audit"
)

// logsExport is a realistic ExportLogsServiceRequest as an OpenTelemetry SDK
// emits it for OTEL_EXPORTER_OTLP_PROTOCOL=http/json: 64-bit integers as
// strings, severity as a number, the payload nested in body, trace context as
// flat ids.
const logsExport = `{
  "resourceLogs": [{
    "resource": {"attributes": [
      {"key": "service.name", "value": {"stringValue": "api-gateway"}},
      {"key": "service.version", "value": {"stringValue": "1.0.0"}}
    ]},
    "scopeLogs": [{
      "scope": {"name": "gateway/authz"},
      "logRecords": [
        {
          "timeUnixNano": "1758440000123456789",
          "severityNumber": 17,
          "body": {"stringValue": "access_decision"},
          "attributes": [
            {"key": "service", "value": {"stringValue": "api-gateway"}},
            {"key": "decision", "value": {"stringValue": "deny"}},
            {"key": "reason", "value": {"stringValue": "threat_level_high"}},
            {"key": "user_id", "value": {"stringValue": "customer"}},
            {"key": "path", "value": {"stringValue": "/api/v1/payment"}},
            {"key": "status", "value": {"intValue": "403"}},
            {"key": "remote_addr", "value": {"stringValue": "10.0.0.7"}}
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

// An OTel log record must land in the audit trail with the same meaning a
// structured stdout line would have: same classifier, same identity, same
// trace join.
func TestDecodeLogsClassifiesADecision(t *testing.T) {
	events, skipped, err := DecodeLogs([]byte(logsExport), "unknown")
	if err != nil {
		t.Fatalf("DecodeLogs: %v", err)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (the cache line carries no decision)", skipped)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}

	event := events[0]
	if event.Category != audit.CategoryAuthz {
		t.Errorf("Category = %q, want %q", event.Category, audit.CategoryAuthz)
	}
	if event.Decision != audit.DecisionDeny {
		t.Errorf("Decision = %q, want %q", event.Decision, audit.DecisionDeny)
	}
	if event.Reason != "threat_level_high" {
		t.Errorf("Reason = %q, want threat_level_high", event.Reason)
	}
	if event.Subject != "customer" {
		t.Errorf("Subject = %q, want customer", event.Subject)
	}
	if event.Path != "/api/v1/payment" || event.Status != 403 {
		t.Errorf("Path/Status = %q/%d, want /api/v1/payment/403", event.Path, event.Status)
	}
	if event.RemoteAddr != "10.0.0.7" {
		t.Errorf("RemoteAddr = %q, want 10.0.0.7", event.RemoteAddr)
	}

	// The resource attributes name the emitter, which is what attributes the
	// decision to a component rather than to "unknown".
	if event.Service != "api-gateway" {
		t.Errorf("Service = %q, want api-gateway", event.Service)
	}

	// The trace join is the whole point: an id decoded a character short (or
	// padded to double length) still stores cleanly and then never matches an
	// HTTP decision, which is exactly the bug this asserts against.
	if event.TraceID != traceID {
		t.Errorf("TraceID = %q, want %q", event.TraceID, traceID)
	}
	if event.SpanID != spanID {
		t.Errorf("SpanID = %q, want %q", event.SpanID, spanID)
	}
	if event.ID == "" {
		t.Error("event has no fingerprint")
	}
}

// Nanosecond timestamps are ~1.7e18. Reading one through float64 or as
// milliseconds places the event in the wrong era, so the magnitude and the
// fraction are both asserted.
func TestDecodeLogsPreservesTimestampPrecision(t *testing.T) {
	events, _, err := DecodeLogs([]byte(logsExport), "unknown")
	if err != nil {
		t.Fatalf("DecodeLogs: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no events decoded")
	}

	occurred := events[0].OccurredAt.UTC()
	if occurred.Year() != 2025 {
		t.Fatalf("OccurredAt = %s, want a 2025 timestamp", occurred)
	}
	if occurred.Nanosecond() != 123456789 {
		t.Errorf("Nanosecond = %d, want 123456789", occurred.Nanosecond())
	}
}

// severityNumber alone has to yield a readable level; a decoded-but-ignored
// field is a silent gap, and severityText is optional in the wire format.
func TestDecodeLogsFallsBackToSeverityNumber(t *testing.T) {
	events, _, err := DecodeLogs([]byte(logsExport), "unknown")
	if err != nil {
		t.Fatalf("DecodeLogs: %v", err)
	}
	level, _ := events[0].Raw["level"].(string)
	if level != "ERROR" {
		t.Errorf("level = %q, want ERROR (severityNumber 17)", level)
	}

	explicit := strings.Replace(logsExport, `"severityNumber": 17,`, `"severityText": "WARN",`, 1)
	events, _, err = DecodeLogs([]byte(explicit), "unknown")
	if err != nil {
		t.Fatalf("DecodeLogs: %v", err)
	}
	if level, _ := events[0].Raw["level"].(string); level != "WARN" {
		t.Errorf("level = %q, want WARN (severityText is the producer's own wording)", level)
	}
}

// A 64-bit attribute arrives as a string because a JSON number cannot hold it.
// Rounding it while decoding would quietly corrupt a request id or a byte count.
func TestDecodeLogsKeepsLargeIntegerAttributesExact(t *testing.T) {
	const big = "9223372036854775807"
	payload := strings.Replace(logsExport,
		`{"key": "remote_addr", "value": {"stringValue": "10.0.0.7"}}`,
		`{"key": "remote_addr", "value": {"stringValue": "10.0.0.7"}},
            {"key": "bytes", "value": {"intValue": "`+big+`"}}`, 1)

	events, _, err := DecodeLogs([]byte(payload), "unknown")
	if err != nil {
		t.Fatalf("DecodeLogs: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no events decoded")
	}

	encoded, err := json.Marshal(events[0].Raw)
	if err != nil {
		t.Fatalf("marshal raw: %v", err)
	}
	if !strings.Contains(string(encoded), big) {
		t.Errorf("raw payload lost precision: %s", encoded)
	}
}

// An OpenTelemetry SDK's default encoding is protobuf. Saying so precisely is
// the difference between a producer fixing its exporter and it giving up.
func TestDecodeLogsRejectsNonJSONWithGuidance(t *testing.T) {
	_, _, err := DecodeLogs([]byte{0x1a, 0x04, 0x0a, 0x02, 0x08, 0x01}, "unknown")
	if err == nil {
		t.Fatal("expected an error for a protobuf payload")
	}
	if !strings.Contains(err.Error(), "OTLP/JSON") {
		t.Errorf("error = %v, want it to name OTLP/JSON", err)
	}

	if _, _, err := DecodeLogs([]byte("   "), "unknown"); err == nil {
		t.Error("expected an error for an empty payload")
	}
}

// A trace id without a span id still identifies the trace; dropping the whole
// record instead would lose the decision.
func TestDecodeLogsAcceptsATraceIDWithoutASpanID(t *testing.T) {
	payload := strings.Replace(logsExport, `"spanId": "00f067aa0ba902b7"`, `"spanId": ""`, 1)
	events, _, err := DecodeLogs([]byte(payload), "unknown")
	if err != nil {
		t.Fatalf("DecodeLogs: %v", err)
	}
	if events[0].TraceID != traceID {
		t.Errorf("TraceID = %q, want %q", events[0].TraceID, traceID)
	}
	if events[0].SpanID == "" {
		t.Error("SpanID is empty: the record must still carry a usable span identity")
	}
}
