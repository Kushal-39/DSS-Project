package otlp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Forwarder mirrors a received OTLP export to a second collector.
//
// Why: Jaeger's UI is the right place to browse spans visually, while the
// audit store needs the spans to join decisions to flows. Rather than ask five
// components to export twice (and drift), telemetry acts as a real collector —
// receive once, store what the audit view needs, mirror the rest onward.
//
// A mirror failure is never fatal. The audit copy has already been written, so
// failing the ingest request would only make the producer retry and duplicate
// work; the forwarder logs instead (see api.Server).
type Forwarder struct {
	endpoint string
	client   *http.Client
}

// NewForwarder returns a forwarder targeting an OTLP/HTTP base URL such as
// "http://jaeger:4318".
func NewForwarder(endpoint string, timeout time.Duration) *Forwarder {
	return &Forwarder{
		endpoint: strings.TrimSuffix(strings.TrimSpace(endpoint), "/"),
		client:   &http.Client{Timeout: timeout},
	}
}

// Forward posts the raw OTLP/JSON body to <endpoint>/v1/traces.
func (f *Forwarder) Forward(ctx context.Context, body []byte) error {
	if f == nil || f.endpoint == "" {
		return nil
	}
	url := f.endpoint + "/v1/traces"

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp: build forward request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := f.client.Do(request)
	if err != nil {
		return fmt.Errorf("otlp: forward to %s: %w", url, err)
	}
	defer response.Body.Close()

	if response.StatusCode >= http.StatusBadRequest {
		// Drain a bounded amount so the connection can be reused.
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return fmt.Errorf("otlp: forward to %s returned %d: %s",
			url, response.StatusCode, strings.TrimSpace(string(detail)))
	}
	_, _ = io.Copy(io.Discard, response.Body)
	return nil
}

// Endpoint reports the configured mirror target (empty when disabled).
func (f *Forwarder) Endpoint() string {
	if f == nil {
		return ""
	}
	return f.endpoint
}
