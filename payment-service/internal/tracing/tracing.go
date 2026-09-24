// Package tracing exports this service's spans to Person 6's OTLP receiver.
//
// docs/flow.md §6 requires every component to emit OpenTelemetry spans, and the
// deliverable it serves is "trace flows across all components". The W3C trace id
// from the incoming `traceparent` header is the only identifier every component
// already shares, so it is the join key: this service exports one span per
// transfer plus a child span for each dependency call, all under the trace the
// gateway started.
//
// Two decisions worth stating:
//
//   - No OpenTelemetry SDK. The SDK would bring an exporter, a batching
//     pipeline, a context propagator and a dependency graph into the money
//     path, to emit three spans. The wire format (OTLP/JSON) is small and
//     documented, and telemetry accepts it directly, so this package writes it
//     by hand — the same trade-off the rest of this repository makes with
//     log/slog over an SDK.
//   - Export is best-effort and off the request path. Spans are handed to a
//     bounded queue and dropped when it is full: a slow or dead telemetry
//     service must never add latency to a transfer or grow this process's
//     memory without limit. The audit *decisions* are not exported this way —
//     they go to stdout, where the collector picks them up independently, so a
//     dropped span never means a lost decision.
package tracing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"paymentservice/internal/metrics"
)

// Status values for a span.
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// KindServer and KindClient are the OTLP SpanKind values this service uses:
// the transfer is a server span, each dependency call is a client span.
const (
	KindServer = 2
	KindClient = 3
)

// Span is one finished span.
type Span struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Name         string
	Kind         int
	Start        time.Time
	End          time.Time
	Status       string
	Attributes   map[string]string
}

// Options configure a Tracer.
type Options struct {
	// Endpoint is the OTLP/HTTP traces endpoint, e.g.
	// http://telemetry:8088/v1/traces. Empty disables export entirely (the
	// tracer becomes a no-op and never opens a connection).
	Endpoint string
	// Token authenticates the export (telemetry's TELEMETRY_INGEST_TOKEN).
	Token string
	// ServiceName is exported as the resource attribute `service.name`, which
	// is the label telemetry stores on every span.
	ServiceName string
	// Timeout bounds one export.
	Timeout time.Duration
	// TLS is used when the endpoint is https.
	TLS *tls.Config
	// QueueSize bounds queued spans.
	QueueSize int
	// Logger receives export failures at debug level.
	Logger *slog.Logger
	// Metrics counts dropped exports.
	Metrics *metrics.Registry
}

// Tracer exports spans asynchronously.
type Tracer struct {
	options Options
	client  *http.Client
	queue   chan Span
	done    chan struct{}
	wg      sync.WaitGroup
	closeMu sync.Mutex
	closed  bool
}

// New builds a Tracer. When no endpoint is configured it returns a tracer whose
// Record is a cheap no-op, so callers never need to branch.
func New(options Options) *Tracer {
	if options.QueueSize <= 0 {
		options.QueueSize = 512
	}
	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	if options.ServiceName == "" {
		options.ServiceName = "payment-service"
	}

	tracer := &Tracer{
		options: options,
		queue:   make(chan Span, options.QueueSize),
		done:    make(chan struct{}),
	}
	if options.Endpoint == "" {
		return tracer
	}

	tracer.client = &http.Client{
		Timeout: options.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        4,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 3 * time.Second,
			TLSClientConfig:     options.TLS,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	tracer.wg.Add(1)
	go tracer.run()
	return tracer
}

// Enabled reports whether spans are actually exported.
func (t *Tracer) Enabled() bool { return t != nil && t.options.Endpoint != "" }

// Record queues a span. It never blocks: when the queue is full the span is
// dropped and counted, because the alternative is a request that waits on the
// observability pipeline.
func (t *Tracer) Record(span Span) {
	if t == nil || !t.Enabled() || span.TraceID == "" || span.SpanID == "" {
		return
	}
	t.closeMu.Lock()
	closed := t.closed
	t.closeMu.Unlock()
	if closed {
		return
	}

	select {
	case t.queue <- span:
	default:
		if t.options.Metrics != nil {
			t.options.Metrics.Inc(metrics.SpanExportFailuresTotal, map[string]string{"stage": "queue"})
		}
	}
}

// Shutdown drains the queue and stops the exporter.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t == nil || !t.Enabled() {
		return nil
	}
	t.closeMu.Lock()
	if t.closed {
		t.closeMu.Unlock()
		return nil
	}
	t.closed = true
	t.closeMu.Unlock()

	close(t.queue)
	close(t.done)

	finished := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *Tracer) run() {
	defer t.wg.Done()
	for span := range t.queue {
		if err := t.export(span); err != nil {
			if t.options.Logger != nil {
				t.options.Logger.Debug("span_export_failed", "error", err, "name", span.Name)
			}
			if t.options.Metrics != nil {
				t.options.Metrics.Inc(metrics.SpanExportFailuresTotal, map[string]string{"stage": "export"})
			}
		}
	}
}

// otlpValue is an OTLP AnyValue.
type otlpValue struct {
	StringValue string `json:"stringValue,omitempty"`
	IntValue    string `json:"intValue,omitempty"`
	BoolValue   bool   `json:"boolValue,omitempty"`
}

type otlpKeyValue struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Status            otlpStatus     `json:"status"`
}

type otlpStatus struct {
	Code string `json:"code"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpScopeSpans struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpResourceSpans struct {
	Resource   otlpResource     `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpRequest struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

// export posts one span as an OTLP/JSON ExportTraceServiceRequest.
//
// Nanosecond timestamps are encoded as strings: OTLP/JSON does that because a
// JSON number cannot represent 1.7e18 exactly, and telemetry decodes both forms.
func (t *Tracer) export(span Span) error {
	attributes := make([]otlpKeyValue, 0, len(span.Attributes))
	for key, value := range span.Attributes {
		if value == "" {
			continue
		}
		attributes = append(attributes, otlpKeyValue{Key: key, Value: otlpValue{StringValue: value}})
	}

	status := "STATUS_CODE_OK"
	if span.Status == StatusError {
		status = "STATUS_CODE_ERROR"
	}

	request := otlpRequest{ResourceSpans: []otlpResourceSpans{{
		Resource: otlpResource{Attributes: []otlpKeyValue{
			// The resource attribute is how telemetry labels the span's service;
			// see internal/otlp/otlp.go in the telemetry service.
			{Key: "service.name", Value: otlpValue{StringValue: t.options.ServiceName}},
		}},
		ScopeSpans: []otlpScopeSpans{{
			Scope: otlpScope{Name: t.options.ServiceName},
			Spans: []otlpSpan{{
				TraceID:           span.TraceID,
				SpanID:            span.SpanID,
				ParentSpanID:      span.ParentSpanID,
				Name:              span.Name,
				Kind:              span.Kind,
				StartTimeUnixNano: strconv.FormatInt(span.Start.UnixNano(), 10),
				EndTimeUnixNano:   strconv.FormatInt(span.End.UnixNano(), 10),
				Attributes:        attributes,
				Status:            otlpStatus{Code: status},
			}},
		}},
	}}}

	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("tracing: encoding the span: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), t.options.Timeout)
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, t.options.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("tracing: building the export request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if t.options.Token != "" {
		// Telemetry's ingest authentication: X-Telemetry-Token or a bearer
		// token, per telemetry/docs/integration.md §1.
		httpRequest.Header.Set("X-Telemetry-Token", t.options.Token)
	}

	response, err := t.client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("tracing: exporting to %s: %w", t.options.Endpoint, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("tracing: %s returned %s", t.options.Endpoint, response.Status)
	}
	return nil
}
