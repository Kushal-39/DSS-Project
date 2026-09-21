package otlp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"telemetry/internal/audit"
)

// The OTLP logs signal.
//
// Why this exists: the project's own contract is structured JSON on stdout
// (docs/flow.md §6), and that path needs no cooperation from any component.
// But a service instrumented with an OpenTelemetry SDK can also just export —
// and if it does, a decision recorded only as an OTel log record must not be
// invisible to the audit trail. Accepting the logs signal means "point your
// exporter at telemetry" is a complete integration, not half of one.
//
// A decoded record goes through exactly the same normaliser as a JSON log
// line, so an event means the same thing however it arrived.

// LogsRequest is an ExportLogsServiceRequest (the OTLP/JSON wire shape).
type LogsRequest struct {
	ResourceLogs []ResourceLogs `json:"resourceLogs"`
}

// ResourceLogs groups log records that share a resource (i.e. one process).
type ResourceLogs struct {
	Resource  Resource    `json:"resource"`
	ScopeLogs []ScopeLogs `json:"scopeLogs"`
	// InstrumentationLibraryLogs is the pre-1.0 spelling.
	InstrumentationLibraryLogs []ScopeLogs `json:"instrumentationLibraryLogs"`
}

// ScopeLogs groups records that share an instrumentation scope.
type ScopeLogs struct {
	LogRecords []WireLogRecord `json:"logRecords"`
}

// WireLogRecord is one log record as it appears on the wire.
type WireLogRecord struct {
	TimeUnixNano         jsonValue  `json:"timeUnixNano"`
	ObservedTimeUnixNano jsonValue  `json:"observedTimeUnixNano"`
	SeverityNumber       jsonValue  `json:"severityNumber"`
	SeverityText         string     `json:"severityText"`
	Body                 jsonValue  `json:"body"`
	Attributes           []KeyValue `json:"attributes"`
	TraceID              string     `json:"traceId"`
	SpanID               string     `json:"spanId"`
}

// DecodeLogs parses an OTLP/JSON log export into normalised audit events.
//
// The second return value counts records that were decoded successfully but
// carried no security signal (a debug line, a heartbeat). They are reported
// rather than rejected: a batch is not malformed because some of it is chatter.
func DecodeLogs(body []byte, defaultService string) ([]audit.Event, int, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, 0, fmt.Errorf("otlp: empty payload")
	}
	if trimmed[0] != '{' {
		return nil, 0, fmt.Errorf("otlp: payload must be an OTLP/JSON object (Content-Type: application/json)")
	}

	var request LogsRequest
	if err := json.Unmarshal(trimmed, &request); err != nil {
		return nil, 0, fmt.Errorf("otlp: payload is not a valid ExportLogsServiceRequest: %w", err)
	}

	events := []audit.Event{}
	skipped := 0
	for _, group := range request.ResourceLogs {
		service := defaultService
		if name := attributeString(group.Resource.Attributes, "service.name"); name != "" {
			service = name
		}

		scopes := group.ScopeLogs
		scopes = append(scopes, group.InstrumentationLibraryLogs...)
		for _, scope := range scopes {
			for _, record := range scope.LogRecords {
				event, ok := logRecordToEvent(record, service)
				if !ok {
					skipped++
					continue
				}
				events = append(events, event)
			}
		}
	}
	return events, skipped, nil
}

// logRecordToEvent flattens one record into the flat field map the normaliser
// reads, so an OTel record and a JSON log line take the same path.
func logRecordToEvent(record WireLogRecord, service string) (audit.Event, bool) {
	fields := map[string]any{}

	// The body holds the structured payload when a producer logs an object;
	// attributes then refine it.
	if body, ok := valueAny(record.Body).(map[string]any); ok {
		for key, value := range body {
			fields[key] = value
		}
	}
	for _, kv := range record.Attributes {
		if kv.Key == "" {
			continue
		}
		fields[kv.Key] = valueAny(kv.Value)
	}

	if level := severityLevel(record); level != "" {
		if _, exists := fields["level"]; !exists {
			fields["level"] = level
		}
	}
	// A string body is the record's message and, for this project's producers,
	// also its event name: every component logs {"msg":"http_request", ...}, so
	// an OTel export of the same decision writes "http_request" into body.
	// Promoting it to "msg" is what makes an OTel record and a stdout line
	// classify identically — without it, the same decision lands in a different
	// category purely because of how it was transported.
	if message, ok := valueAny(record.Body).(string); ok && message != "" {
		if _, exists := fields["message"]; !exists {
			fields["message"] = message
		}
		if !hasEventName(fields) {
			fields["msg"] = message
		}
	}

	// Timestamps are handed over as RFC3339 rather than as the raw nanosecond
	// value: the normaliser's numeric path reads a 1.7e18 magnitude as
	// milliseconds, which would place every event in the year 57000.
	when := unixNano(record.TimeUnixNano)
	if when.IsZero() {
		when = unixNano(record.ObservedTimeUnixNano)
	}
	if !when.IsZero() {
		fields["time"] = when.Format(time.RFC3339Nano)
	}

	// Rebuild a synthetic traceparent so the record goes through exactly the
	// same trace-context validation as a propagating HTTP header.
	if traceID := normaliseID(record.TraceID, 32); traceID != "" {
		spanID := normaliseID(record.SpanID, 16)
		if spanID == "" {
			spanID = strings.Repeat("0", 16)
		}
		fields["traceparent"] = "00-" + traceID + "-" + spanID + "-01"
	}

	return audit.FromMap(fields, service)
}

// hasEventName reports whether a record already names its own event type.
func hasEventName(fields map[string]any) bool {
	for _, key := range []string{"msg", "event", "event_type", "event_name", "event.name", "name"} {
		if value, exists := fields[key]; exists {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				return true
			}
		}
	}
	return false
}

// severityLevel renders an OTel severity as the textual level every other
// producer writes, so a record's severity is readable in the stored payload
// regardless of which of the two fields the SDK chose to populate.
//
// severityText wins when present because it is the producer's own wording; the
// number is the fallback for SDKs that fill only severityNumber. Without it the
// field would be decoded and then silently ignored, which is worse than not
// decoding it.
func severityLevel(record WireLogRecord) string {
	if text := strings.TrimSpace(record.SeverityText); text != "" {
		return text
	}

	text := scalarString(record.SeverityNumber)
	if text == "" || text == "null" {
		return ""
	}
	number, err := strconv.Atoi(text)
	if err != nil {
		return ""
	}
	switch {
	case number >= 21: // FATAL..FATAL4
		return "FATAL"
	case number >= 17: // ERROR..ERROR4
		return "ERROR"
	case number >= 13: // WARN..WARN4
		return "WARN"
	case number >= 9: // INFO..INFO4
		return "INFO"
	case number >= 5: // DEBUG..DEBUG4
		return "DEBUG"
	case number >= 1: // TRACE..TRACE4
		return "TRACE"
	}
	return ""
}

// valueAny converts an OTLP AnyValue into the Go value the normaliser's field
// helpers understand.
//
// 64-bit integers become json.Number rather than float64: OTLP encodes them as
// strings precisely because a JSON number cannot hold them, and a request id or
// a byte count that silently rounds would be a data integrity bug.
func valueAny(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		// A bare scalar: some hand-written payloads skip the AnyValue wrapper.
		var scalar any
		if err := json.Unmarshal(raw, &scalar); err == nil {
			return scalar
		}
		return nil
	}

	for _, field := range []string{"stringValue", "boolValue", "intValue", "doubleValue"} {
		value, ok := decoded[field]
		if !ok {
			continue
		}
		switch field {
		case "stringValue":
			var text string
			if json.Unmarshal(value, &text) == nil {
				return text
			}
		case "boolValue":
			var flag bool
			if json.Unmarshal(value, &flag) == nil {
				return flag
			}
		case "intValue":
			var text string
			if json.Unmarshal(value, &text) == nil {
				return json.Number(strings.TrimSpace(text))
			}
			var number json.Number
			if json.Unmarshal(value, &number) == nil {
				return number
			}
		case "doubleValue":
			var number float64
			if json.Unmarshal(value, &number) == nil {
				return number
			}
		}
	}

	if array, ok := decoded["arrayValue"]; ok {
		var wrapper struct {
			Values []json.RawMessage `json:"values"`
		}
		if json.Unmarshal(array, &wrapper) == nil {
			values := make([]any, 0, len(wrapper.Values))
			for _, item := range wrapper.Values {
				values = append(values, valueAny(item))
			}
			return values
		}
	}
	if list, ok := decoded["kvlistValue"]; ok {
		var wrapper struct {
			Values []KeyValue `json:"values"`
		}
		if json.Unmarshal(list, &wrapper) == nil {
			values := map[string]any{}
			for _, kv := range wrapper.Values {
				values[kv.Key] = valueAny(kv.Value)
			}
			return values
		}
	}
	return nil
}
