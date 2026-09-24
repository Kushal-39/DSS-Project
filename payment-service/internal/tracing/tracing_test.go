package tracing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// span is the subset of the OTLP/JSON payload the telemetry service reads
// (telemetry/internal/otlp/otlp.go), which is what makes a span joinable.
type received struct {
	Requests int
	Spans    []map[string]any
	Services []string
	Token    string
}

func receiver(t *testing.T, status int) (*httptest.Server, *received) {
	t.Helper()
	state := &received{}
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			ResourceSpans []struct {
				Resource struct {
					Attributes []struct {
						Key   string `json:"key"`
						Value struct {
							StringValue string `json:"stringValue"`
						} `json:"value"`
					} `json:"attributes"`
				} `json:"resource"`
				ScopeSpans []struct {
					Spans []map[string]any `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		mu.Lock()
		defer mu.Unlock()
		state.Requests++
		state.Token = r.Header.Get("X-Telemetry-Token")
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("the exported payload is not valid OTLP/JSON: %v (%s)", err, body)
			return
		}
		for _, group := range payload.ResourceSpans {
			for _, attribute := range group.Resource.Attributes {
				if attribute.Key == "service.name" {
					state.Services = append(state.Services, attribute.Value.StringValue)
				}
			}
			for _, scope := range group.ScopeSpans {
				state.Spans = append(state.Spans, scope.Spans...)
			}
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, state
}

func TestRecordExportsOTLPJSONTheTelemetryPipelineCanJoin(t *testing.T) {
	server, state := receiver(t, http.StatusOK)
	tracer := New(Options{
		Endpoint:    server.URL,
		Token:       "ingest-token",
		ServiceName: "payment-service",
		Timeout:     time.Second,
	})
	if !tracer.Enabled() {
		t.Fatal("a configured endpoint must enable export")
	}

	start := time.Now().Add(-20 * time.Millisecond)
	tracer.Record(Span{
		TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:       "00f067aa0ba902b7",
		ParentSpanID: "a3ce929d0e0e4736",
		Name:         "policy.authorize",
		Kind:         KindClient,
		Start:        start,
		End:          time.Now(),
		Status:       StatusOK,
		Attributes:   map[string]string{"policy.action": "TRANSFER", "policy.allow": "true"},
	})

	waitFor(t, func() bool {
		return len(state.Spans) == 1
	}, "the span to be exported")

	span := state.Spans[0]
	if span["traceId"] != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("traceId = %v", span["traceId"])
	}
	if span["spanId"] != "00f067aa0ba902b7" {
		t.Errorf("spanId = %v", span["spanId"])
	}
	if span["parentSpanId"] != "a3ce929d0e0e4736" {
		t.Errorf("parentSpanId = %v", span["parentSpanId"])
	}
	if span["name"] != "policy.authorize" {
		t.Errorf("name = %v", span["name"])
	}
	// OTLP/JSON encodes 64-bit integers as strings, and telemetry reads both
	// forms; the nanoseconds must be exact rather than float-rounded.
	timestamps := []string{"startTimeUnixNano", "endTimeUnixNano"}
	for _, field := range timestamps {
		value, ok := span[field].(string)
		if !ok {
			t.Fatalf("%s = %T, want a string-encoded nanosecond timestamp", field, span[field])
		}
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			t.Errorf("%s = %q is not an integer: %v", field, value, err)
		}
	}
	Cstatus, _ := span["status"].(map[string]any)
	if Cstatus["code"] != "STATUS_CODE_OK" {
		t.Errorf("status = %v", span["status"])
	}

	attributes, _ := span["attributes"].([]any)
	if len(attributes) != 2 {
		t.Errorf("attributes = %v", span["attributes"])
	}

	if len(state.Services) != 1 || state.Services[0] != "payment-service" {
		t.Errorf("resource service.name = %v", state.Services)
	}
	if state.Token != "ingest-token" {
		t.Errorf("X-Telemetry-Token = %q", state.Token)
	}
}

func TestAnErrorStatusIsReportedAsOTLPError(t *testing.T) {
	server, state := receiver(t, http.StatusOK)
	tracer := New(Options{Endpoint: server.URL, Timeout: time.Second})

	tracer.Record(Span{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "00f067aa0ba902b7",
		Name:    "account.deduct",
		Kind:    KindClient,
		Start:   time.Now(),
		End:     time.Now(),
		Status:  StatusError,
	})

	waitFor(t, func() bool { return len(state.Spans) == 1 }, "the span to be exported")
	status, _ := state.Spans[0]["status"].(map[string]any)
	if status["code"] != "STATUS_CODE_ERROR" {
		t.Errorf("status = %v", state.Spans[0]["status"])
	}
}

// Export is best-effort and never blocks the caller: a dead telemetry service
// must not add latency to a transfer, and must not grow this process without
// limit.
func TestRecordNeverBlocksOnADeadExporter(t *testing.T) {
	server, _ := receiver(t, http.StatusInternalServerError)
	tracer := New(Options{Endpoint: server.URL, Timeout: time.Second, QueueSize: 2})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			tracer.Record(Span{
				TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
				SpanID:  "00f067aa0ba902b7",
				Name:    "filler",
				Start:   time.Now(),
				End:     time.Now(),
			})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked: a full queue must drop spans, not wait")
	}
}

func TestDisabledTracerDoesNothing(t *testing.T) {
	tracer := New(Options{})
	if tracer.Enabled() {
		t.Fatal("an empty endpoint must disable export")
	}
	tracer.Record(Span{TraceID: "x", SpanID: "y", Name: "ignored"})
	if err := tracer.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestRecordIgnoresSpansWithoutATrace(t *testing.T) {
	server, state := receiver(t, http.StatusOK)
	tracer := New(Options{Endpoint: server.URL, Timeout: time.Second})

	// A span without a trace id cannot be joined to a flow, so exporting it
	// would only add noise to the trace view.
	tracer.Record(Span{SpanID: "00f067aa0ba902b7", Name: "orphan"})
	tracer.Record(Span{TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", Name: "orphan"})

	time.Sleep(150 * time.Millisecond)
	if state.Requests != 0 {
		t.Errorf("a span with no trace id was exported (%d requests)", state.Requests)
	}
}

func waitFor(t *testing.T, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
