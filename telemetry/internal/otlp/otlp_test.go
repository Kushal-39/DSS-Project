package otlp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	spanID  = "00f067aa0ba902b7"
	childID = "00f067aa0ba902b8"
)

// export is a realistic ExportTraceServiceRequest, in exactly the shape an
// OpenTelemetry SDK emits for OTEL_EXPORTER_OTLP_PROTOCOL=http/json: 64-bit
// integers as strings, ids as hex, status as an enum name.
const export = `{
  "resourceSpans": [{
    "resource": {"attributes": [
      {"key": "service.name", "value": {"stringValue": "api-gateway"}},
      {"key": "service.version", "value": {"stringValue": "1.0.0"}}
    ]},
    "scopeSpans": [{
      "scope": {"name": "gateway/http"},
      "spans": [
        {
          "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
          "spanId": "00f067aa0ba902b7",
          "name": "POST /api/v1/payment",
          "kind": 2,
          "startTimeUnixNano": "1758440000000000000",
          "endTimeUnixNano": "1758440000123500000",
          "attributes": [
            {"key": "http.request.method", "value": {"stringValue": "POST"}},
            {"key": "url.path", "value": {"stringValue": "/api/v1/payment"}},
            {"key": "http.response.status_code", "value": {"intValue": "403"}},
            {"key": "retry.count", "value": {"intValue": "0"}},
            {"key": "sampled", "value": {"boolValue": true}}
          ],
          "status": {"code": "STATUS_CODE_ERROR", "message": "policy denied"}
        },
        {
          "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
          "spanId": "00f067aa0ba902b8",
          "parentSpanId": "00f067aa0ba902b7",
          "name": "policy check",
          "kind": 3,
          "startTimeUnixNano": "1758440000010000000",
          "endTimeUnixNano": "1758440000040000000",
          "attributes": [{"key": "policy.engine", "value": {"stringValue": "opa"}}],
          "status": {"code": "STATUS_CODE_OK"}
        }
      ]
    }]
  }]
}`

func TestDecodeRealisticExport(t *testing.T) {
	spans, err := Decode([]byte(export), "unknown")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}

	gateway := spans[0]
	// The regression that matters: ids keep their real width. A trace id is 32
	// hex characters (16 bytes); getting that wrong still round-trips through
	// ingest and simply never joins to anything, which is invisible until the
	// trace view is compared with a component's audit decisions.
	if gateway.TraceID != traceID {
		t.Errorf("trace_id = %q (%d chars), want %q", gateway.TraceID, len(gateway.TraceID), traceID)
	}
	if gateway.SpanID != spanID {
		t.Errorf("span_id = %q (%d chars), want %q", gateway.SpanID, len(gateway.SpanID), spanID)
	}
	if gateway.Service != "api-gateway" {
		t.Errorf("service = %q, want api-gateway (from the resource)", gateway.Service)
	}
	if gateway.Name != "POST /api/v1/payment" {
		t.Errorf("name = %q", gateway.Name)
	}
	if gateway.Status != "error" {
		t.Errorf("status = %q, want error", gateway.Status)
	}
	if gateway.DurationNS != 123_500_000 {
		t.Errorf("duration_ns = %d, want 123500000", gateway.DurationNS)
	}
	if got := gateway.DurationMS(); got != 123 {
		t.Errorf("duration_ms = %d, want 123", got)
	}
	if gateway.Attributes["http.response.status_code"] != "403" {
		t.Errorf("attributes lost the status code: %v", gateway.Attributes)
	}
	if gateway.Attributes["sampled"] != "true" {
		t.Errorf("bool attribute = %q, want true", gateway.Attributes["sampled"])
	}
	if !gateway.Start.Equal(time.Unix(0, 1758440000000000000).UTC()) {
		t.Errorf("start = %s", gateway.Start)
	}

	child := spans[1]
	if child.ParentSpanID != spanID {
		t.Errorf("parent_span_id = %q, want %q", child.ParentSpanID, spanID)
	}
	if child.Status != "ok" {
		t.Errorf("child status = %q, want ok", child.Status)
	}
	if child.TraceID != gateway.TraceID {
		t.Error("parent and child ended up on different traces")
	}
}

func TestDecodeAcceptsInstrumentationLibrarySpans(t *testing.T) {
	// The pre-1.0 spelling; some SDKs still emit it.
	body := strings.Replace(export, `"scopeSpans"`, `"instrumentationLibrarySpans"`, 1)
	spans, err := Decode([]byte(body), "unknown")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
}

func TestDecodeFallsBackToTheCollectorsServiceName(t *testing.T) {
	body := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"` + traceID + `","spanId":"` + spanID + `","name":"x"}]}]}]}`
	spans, err := Decode([]byte(body), "collector-supplied")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(spans) != 1 || spans[0].Service != "collector-supplied" {
		t.Fatalf("spans = %+v, want the default service name", spans)
	}
	if spans[0].Name != "x" {
		t.Errorf("name = %q", spans[0].Name)
	}
}

func TestDecodeDropsSpansThatCannotBeJoined(t *testing.T) {
	body := `{"resourceSpans":[{"scopeSpans":[{"spans":[
		{"traceId":"","spanId":"` + spanID + `","name":"no trace"},
		{"traceId":"` + traceID + `","spanId":"","name":"no span"},
		{"traceId":"not-hex!","spanId":"` + spanID + `","name":"garbage"}
	]}]}]}`
	spans, err := Decode([]byte(body), "svc")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(spans) != 0 {
		t.Fatalf("got %d spans, want 0: a span with no usable id cannot be joined "+
			"to anything, and inventing one would corrupt the trace view", len(spans))
	}
}

func TestDecodeRejectsMalformedPayloads(t *testing.T) {
	for _, body := range []string{"", "  ", "not json", "[1,2,3]", `{"resourceSpans": "nope"}`} {
		if _, err := Decode([]byte(body), "svc"); err == nil {
			t.Errorf("payload %q was accepted", body)
		}
	}
}

func TestDecodeAcceptsABareAttributesObject(t *testing.T) {
	// Everything is valid; there are just no spans in it.
	spans, err := Decode([]byte(`{"resourceSpans":[]}`), "svc")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(spans) != 0 {
		t.Errorf("got %d spans, want 0", len(spans))
	}
}

func TestNumberFormatsAreAccepted(t *testing.T) {
	// 64-bit integers arrive as strings in OTLP/JSON, as numbers from
	// hand-written payloads, and in seconds/ms/us/ns depending on the encoder.
	tests := []struct {
		name  string
		value string
		want  time.Time
	}{
		{"nanoseconds as a string", `"1758440000000000000"`, time.Unix(0, 1758440000000000000).UTC()},
		{"nanoseconds as a number", `1758440000000000000`, time.Unix(0, 1758440000000000000).UTC()},
		{"microseconds", `"1758440000000000"`, time.Unix(0, 1758440000000000*1000).UTC()},
		{"milliseconds", `1758440000000`, time.UnixMilli(1758440000000).UTC()},
		{"seconds", `1758440000`, time.Unix(1758440000, 0).UTC()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := unixNano(json.RawMessage(test.value)); !got.Equal(test.want) {
				t.Errorf("unixNano(%s) = %s, want %s", test.value, got, test.want)
			}
		})
	}

	for _, value := range []string{`""`, `null`, `0`, `-5`, `"abc"`} {
		if got := unixNano(json.RawMessage(value)); !got.IsZero() {
			t.Errorf("unixNano(%s) = %s, want the zero time", value, got)
		}
	}
}

func TestNormaliseID(t *testing.T) {
	raw, _ := hex.DecodeString(traceID)
	encoded := base64.StdEncoding.EncodeToString(raw)

	tests := []struct {
		name    string
		input   string
		wantHex int
		want    string
	}{
		{"trace id in hex", traceID, 32, traceID},
		{"uppercase hex is lowered", strings.ToUpper(traceID), 32, traceID},
		{"span id in hex", spanID, 16, spanID},
		{"trace id in base64", encoded, 32, traceID},
		{"short id is left-padded, not discarded", "f067aa0ba902b7", 16, "00f067aa0ba902b7"},
		{"empty stays empty", "", 32, ""},
		{"too long for the field is rejected", strings.Repeat("a", 40), 32, ""},
		{"not an id at all", "not-hex!", 32, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normaliseID(test.input, test.wantHex); got != test.want {
				t.Errorf("normaliseID(%q, %d) = %q, want %q", test.input, test.wantHex, got, test.want)
			}
		})
	}
}

func TestStatusName(t *testing.T) {
	tests := []struct {
		name   string
		status Status
		want   string
	}{
		{"enum name error", Status{Code: json.RawMessage(`"STATUS_CODE_ERROR"`)}, "error"},
		{"numeric error", Status{Code: json.RawMessage(`2`)}, "error"},
		{"enum name ok", Status{Code: json.RawMessage(`"STATUS_CODE_OK"`)}, "ok"},
		{"numeric ok", Status{Code: json.RawMessage(`1`)}, "ok"},
		{"unset", Status{Code: json.RawMessage(`"STATUS_CODE_UNSET"`)}, "unset"},
		{"absent", Status{}, "unset"},
		// A message without a code still means something went wrong.
		{"message only", Status{Message: "policy denied"}, "error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := statusName(test.status); got != test.want {
				t.Errorf("statusName = %q, want %q", got, test.want)
			}
		})
	}
}

func TestValueStringFlattensEveryAnyValueShape(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{`{"stringValue":"hello"}`, "hello"},
		{`{"intValue":"403"}`, "403"},
		{`{"doubleValue":1.5}`, "1.5"},
		{`{"boolValue":false}`, "false"},
		{`{"arrayValue":{"values":[{"stringValue":"a"},{"stringValue":"b"}]}}`, "a,b"},
		{`{"kvlistValue":{"values":[{"key":"k","value":{"stringValue":"v"}}]}}`, "k=v"},
		{`"bare scalar"`, "bare scalar"},
		{`42`, "42"},
		{``, ""},
		{`{"unknownShape":true}`, ""},
	}
	for _, test := range tests {
		if got := valueString(json.RawMessage(test.raw)); got != test.want {
			t.Errorf("valueString(%s) = %q, want %q", test.raw, got, test.want)
		}
	}
}

func TestForwarderPostsToTheOTLPHTTPEndpoint(t *testing.T) {
	var gotPath, gotContentType, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	forwarder := NewForwarder(server.URL+"/", 5*time.Second)
	if err := forwarder.Forward(context.Background(), []byte(export)); err != nil {
		t.Fatalf("Forward: %v", err)
	}

	if gotPath != "/v1/traces" {
		t.Errorf("path = %q, want /v1/traces", gotPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if gotBody != export {
		t.Error("the mirrored body differs from what was received")
	}
	if forwarder.Endpoint() != server.URL {
		t.Errorf("Endpoint = %q", forwarder.Endpoint())
	}
}

func TestForwarderReportsUpstreamFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "collector is down", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	forwarder := NewForwarder(server.URL, time.Second)
	err := forwarder.Forward(context.Background(), []byte(export))
	if err == nil {
		t.Fatal("a 503 from the mirror target was reported as success")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error = %v, want the status in the message", err)
	}
}

func TestForwarderIsOptional(t *testing.T) {
	// Mirroring is a configuration detail; with no endpoint configured the
	// audit copy is the whole job and nothing should fail.
	empty := NewForwarder("", time.Second)
	if err := empty.Forward(context.Background(), []byte(export)); err != nil {
		t.Errorf("Forward with no endpoint: %v", err)
	}
	if empty.Endpoint() != "" {
		t.Errorf("Endpoint = %q, want empty", empty.Endpoint())
	}

	var missing *Forwarder
	if err := missing.Forward(context.Background(), []byte(export)); err != nil {
		t.Errorf("nil forwarder: %v", err)
	}
	if missing.Endpoint() != "" {
		t.Errorf("nil Endpoint = %q", missing.Endpoint())
	}
}
