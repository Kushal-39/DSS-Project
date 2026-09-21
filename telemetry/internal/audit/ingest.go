package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrEmptyPayload is returned when a collector posts nothing.
var ErrEmptyPayload = errors.New("empty payload")

// ParseEvents decodes the audit ingest body, which may be a single event
// object, an array of events, or an envelope ("events" / "logs" arrays) —
// because a collector will not always post one record at a time.
func ParseEvents(body []byte, defaultService string) (events []Event, skipped int, err error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, 0, ErrEmptyPayload
	}

	switch trimmed[0] {
	case '[':
		var records []map[string]any
		if err := json.Unmarshal(trimmed, &records); err != nil {
			return nil, 0, fmt.Errorf("payload is not a JSON array of events: %w", err)
		}
		return classifyRecords(records, defaultService)

	case '{':
		var envelope struct {
			Events []map[string]any `json:"events"`
			Logs   []map[string]any `json:"logs"`
		}
		if err := json.Unmarshal(trimmed, &envelope); err == nil &&
			(len(envelope.Events) > 0 || len(envelope.Logs) > 0) {
			records := make([]map[string]any, 0, len(envelope.Events)+len(envelope.Logs))
			records = append(records, envelope.Events...)
			records = append(records, envelope.Logs...)
			return classifyRecords(records, defaultService)
		}

		var record map[string]any
		if err := json.Unmarshal(trimmed, &record); err != nil {
			return nil, 0, fmt.Errorf("payload is not a JSON object: %w", err)
		}
		return classifyRecords([]map[string]any{record}, defaultService)

	default:
		return nil, 0, errors.New("payload must be a JSON object or array")
	}
}

// ParseLogs decodes the log ingest body: structured JSON records from any
// component, either as a JSON array/envelope or as newline-delimited JSON
// (which is what a container log file or a collector's batch looks like).
//
// A batch is routinely a mixture: a collector ships whatever a container
// printed, and that includes startup banners and unstructured lines alongside
// the structured records. Those lines are counted as skipped, not treated as a
// payload error — rejecting a batch because one line in it was not JSON would
// discard the decisions in the same batch.
func ParseLogs(body []byte, defaultService string) (events []Event, skipped int, err error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, 0, ErrEmptyPayload
	}

	// Newline-delimited records come first, and deliberately before the array
	// case: a batch can hold one complete record per line (including a line
	// that is itself an array), and splitting is only correct if nothing is
	// decoded whole first.
	if bytes.ContainsRune(trimmed, '\n') {
		jsonLines := 0
		for _, line := range bytes.Split(trimmed, []byte("\n")) {
			if line = bytes.TrimSpace(line); len(line) == 0 {
				continue
			}
			if line[0] == '{' || line[0] == '[' {
				lineEvents, lineSkipped, lineErr := ParseEvents(line, defaultService)
				if lineErr == nil {
					jsonLines++
					events = append(events, lineEvents...)
					skipped += lineSkipped
					continue
				}
			}
			skipped++
		}
		if jsonLines > 0 {
			return events, skipped, nil
		}
		// Not one complete record per line: the body is a single JSON value
		// that happens to be pretty-printed, so fall through.
	}

	if trimmed[0] == '{' {
		// A single object is either one log line or an envelope; try the line
		// first because that is the common case.
		if event, ok := FromLogLine(trimmed, defaultService); ok {
			return []Event{event}, 0, nil
		}
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return ParseEvents(trimmed, defaultService)
	}

	return nil, 0, errors.New("payload must be newline-delimited JSON objects or a JSON array")
}

// classifyRecords normalises decoded records, counting the ones that carry no
// security signal rather than failing the whole batch for them.
func classifyRecords(records []map[string]any, defaultService string) ([]Event, int, error) {
	events := make([]Event, 0, len(records))
	skipped := 0
	for _, record := range records {
		event, ok := FromMap(record, defaultService)
		if !ok {
			skipped++
			continue
		}
		events = append(events, event)
	}
	if len(events) == 0 && skipped == 0 {
		return nil, 0, ErrEmptyPayload
	}
	return events, skipped, nil
}
