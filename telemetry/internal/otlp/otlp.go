// Package otlp decodes OTLP trace exports into the flattened span records the
// audit store understands.
//
// Person 6's deliverable is "trace flows across all components", and the only
// identifier every component already shares is the W3C trace id that
// docs/flow.md §3 has the gateway inject. Spans are how we learn what actually
// happened inside a trace, so the telemetry service accepts OTLP directly
// (OTLP/JSON, which every OpenTelemetry SDK can emit via
// OTEL_EXPORTER_OTLP_PROTOCOL=http/json) and optionally mirrors what it
// receives to another collector such as Jaeger for the visual span browser.
package otlp

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"telemetry/internal/audit"
)

// Request is an ExportTraceServiceRequest (the OTLP/JSON wire shape).
type Request struct {
	ResourceSpans []ResourceSpans `json:"resourceSpans"`
}

// ResourceSpans groups spans that share a resource (i.e. one process).
type ResourceSpans struct {
	Resource   Resource     `json:"resource"`
	ScopeSpans []ScopeSpans `json:"scopeSpans"`
	// InstrumentationLibrarySpans is the pre-1.0 spelling of scopeSpans. Some
	// SDKs still emit it, and accepting it costs one field.
	InstrumentationLibrarySpans []ScopeSpans `json:"instrumentationLibrarySpans"`
}

// Resource describes the emitting process.
type Resource struct {
	Attributes []KeyValue `json:"attributes"`
}

// ScopeSpans groups spans that share an instrumentation scope.
type ScopeSpans struct {
	Spans []WireSpan `json:"spans"`
}

// WireSpan is one span as it appears on the wire.
type WireSpan struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	ParentSpanID      string     `json:"parentSpanId"`
	Name              string     `json:"name"`
	Kind              jsonValue  `json:"kind"`
	StartTimeUnixNano jsonValue  `json:"startTimeUnixNano"`
	EndTimeUnixNano   jsonValue  `json:"endTimeUnixNano"`
	Attributes        []KeyValue `json:"attributes"`
	Status            Status     `json:"status"`
}

// Status is the span's status.
type Status struct {
	Code    jsonValue `json:"code"`
	Message string    `json:"message"`
}

// KeyValue is an OTLP attribute.
type KeyValue struct {
	Key   string    `json:"key"`
	Value jsonValue `json:"value"`
}

// jsonValue is a number-or-string field. The OTLP/JSON mapping encodes 64-bit
// integers as strings (JSON numbers cannot represent them exactly), while
// hand-written payloads and some SDKs send plain numbers — so accept both
// instead of rejecting a whole trace over its number formatting.
type jsonValue = json.RawMessage

// Decode parses an OTLP/JSON trace export into flat spans.
//
// Spans missing a trace id or span id are dropped rather than stored with a
// synthetic identity: a span that cannot be joined is not trace data, it is
// noise, and inventing an id would corrupt the trace-join view.
func Decode(body []byte, defaultService string) ([]audit.Span, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("otlp: empty payload")
	}
	if trimmed[0] != '{' {
		return nil, fmt.Errorf("otlp: payload must be an OTLP/JSON object (application/json)")
	}

	var request Request
	if err := json.Unmarshal(trimmed, &request); err != nil {
		return nil, fmt.Errorf("otlp: payload is not a valid ExportTraceServiceRequest: %w", err)
	}

	spans := []audit.Span{}
	for _, group := range request.ResourceSpans {
		service := defaultService
		if name := attributeString(group.Resource.Attributes, "service.name"); name != "" {
			service = name
		}

		scopes := group.ScopeSpans
		scopes = append(scopes, group.InstrumentationLibrarySpans...)
		for _, scope := range scopes {
			for _, wire := range scope.Spans {
				span, ok := flatten(wire, service)
				if ok {
					spans = append(spans, span)
				}
			}
		}
	}
	return spans, nil
}

func flatten(wire WireSpan, service string) (audit.Span, bool) {
	traceID := normaliseID(wire.TraceID, 32)
	spanID := normaliseID(wire.SpanID, 16)
	if traceID == "" || spanID == "" {
		return audit.Span{}, false
	}

	attributes := map[string]string{}
	for _, kv := range wire.Attributes {
		if kv.Key == "" {
			continue
		}
		attributes[kv.Key] = valueString(kv.Value)
	}

	start := unixNano(wire.StartTimeUnixNano)
	end := unixNano(wire.EndTimeUnixNano)
	if start.IsZero() && !end.IsZero() {
		start = end
	}

	span := audit.Span{
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: normaliseID(wire.ParentSpanID, 16),
		Service:      service,
		Name:         strings.TrimSpace(wire.Name),
		Start:        start,
		End:          end,
		Status:       statusName(wire.Status),
		Attributes:   attributes,
	}
	if span.Name == "" {
		span.Name = "span"
	}
	switch {
	case start.IsZero():
		span.Start = time.Now().UTC()
	case !end.IsZero() && !end.Before(start):
		span.DurationNS = end.Sub(start).Nanoseconds()
	}
	return span, true
}

// normaliseID returns an id as lowercase hex of exactly wantHex characters:
// 32 for a W3C trace id (16 bytes) and 16 for a span id (8 bytes).
//
// The unit here is hex characters, not bytes. Conflating the two is easy and
// silent: a 32 character trace id looks like "shorter than 64" and gets padded
// to 64, which still round-trips through ingest, still deduplicates correctly,
// and simply never joins to anything — every span ends up on its own private
// trace. That failure is invisible until the trace view is compared against a
// real component's decisions, which is exactly what the end-to-end test does.
//
// Input may be hex (the OTLP/JSON default) or base64, which the protobuf JSON
// mapping allows for bytes fields.
func normaliseID(raw string, wantHex int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if isHexString(raw) {
		switch {
		case len(raw) == wantHex:
			return strings.ToLower(raw)
		case len(raw) < wantHex:
			// An id written without its leading zeros still identifies the same
			// 16-byte value, so left-pad rather than discard it.
			return strings.Repeat("0", wantHex-len(raw)) + strings.ToLower(raw)
		}
		return ""
	}
	if decoded, err := decodeBytes(raw); err == nil && len(decoded)*2 == wantHex {
		return hex.EncodeToString(decoded)
	}
	return ""
}

func statusName(status Status) string {
	code := strings.ToUpper(strings.TrimSpace(valueString(status.Code)))
	switch code {
	case "STATUS_CODE_ERROR", "2", "ERROR":
		return "error"
	case "STATUS_CODE_OK", "1", "OK":
		return "ok"
	}
	if strings.TrimSpace(status.Message) != "" {
		// A message without a code still means something went wrong.
		return "error"
	}
	return "unset"
}

func attributeString(attributes []KeyValue, key string) string {
	for _, kv := range attributes {
		if kv.Key == key {
			return strings.TrimSpace(valueString(kv.Value))
		}
	}
	return ""
}

// valueString flattens any OTLP AnyValue into a readable string.
func valueString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		// A bare scalar (some hand-written payloads skip the AnyValue wrapper).
		return scalarString(raw)
	}
	for _, field := range []string{"stringValue", "boolValue", "intValue", "doubleValue", "bytesValue"} {
		if value, ok := decoded[field]; ok {
			return scalarString(value)
		}
	}
	if array, ok := decoded["arrayValue"]; ok {
		var wrapper struct {
			Values []json.RawMessage `json:"values"`
		}
		if err := json.Unmarshal(array, &wrapper); err == nil {
			parts := make([]string, 0, len(wrapper.Values))
			for _, item := range wrapper.Values {
				parts = append(parts, valueString(item))
			}
			return strings.Join(parts, ",")
		}
	}
	if list, ok := decoded["kvlistValue"]; ok {
		var wrapper struct {
			Values []KeyValue `json:"values"`
		}
		if err := json.Unmarshal(list, &wrapper); err == nil {
			parts := make([]string, 0, len(wrapper.Values))
			for _, kv := range wrapper.Values {
				parts = append(parts, kv.Key+"="+valueString(kv.Value))
			}
			return strings.Join(parts, ",")
		}
	}
	return ""
}

func scalarString(raw json.RawMessage) string {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return ""
	}
	if text[0] == '"' {
		var decoded string
		if err := json.Unmarshal(raw, &decoded); err == nil {
			return decoded
		}
		return ""
	}
	return text
}

// unixNano reads a nanosecond timestamp that may arrive as a string or a
// number, in nanoseconds, microseconds, milliseconds or seconds.
//
// The integer path is not an optimisation. An OTLP nanosecond timestamp is
// about 1.7e18, and float64 cannot represent integers above 2^53 — parsing one
// as a float loses the low nanoseconds (a real observed drift of 32ns), so the
// digits are kept as an integer whenever the encoding has no fraction.
func unixNano(raw json.RawMessage) time.Time {
	text := scalarString(raw)
	if text == "" || text == "null" {
		return time.Time{}
	}

	if value, err := strconv.ParseInt(text, 10, 64); err == nil {
		return fromUnixMagnitude(value)
	}

	// Fractional seconds, e.g. 1758440000.5.
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || value <= 0 {
		return time.Time{}
	}
	whole := int64(value)
	return time.Unix(whole, int64((value-float64(whole))*1e9)).UTC()
}

// fromUnixMagnitude interprets an integer timestamp by its magnitude: an OTLP
// nanosecond value is ~1e18, a microsecond one ~1e15, milliseconds ~1e12, and
// plain seconds anything smaller.
func fromUnixMagnitude(value int64) time.Time {
	switch {
	case value <= 0:
		return time.Time{}
	case value >= 1e18:
		return time.Unix(0, value).UTC()
	case value >= 1e15:
		return time.Unix(0, value*int64(time.Microsecond)).UTC()
	case value >= 1e12:
		return time.UnixMilli(value).UTC()
	default:
		return time.Unix(value, 0).UTC()
	}
}

func decodeBytes(raw string) ([]byte, error) {
	if isHexString(raw) && len(raw)%2 == 0 {
		return hex.DecodeString(raw)
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("otlp: %q is neither hex nor base64", raw)
}

func isHexString(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
