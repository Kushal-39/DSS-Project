package store

import (
	"context"
	"sync"
	"time"

	"telemetry/internal/audit"
)

// Memory is an in-process, volatile store.
//
// It exists for two reasons: the pipeline's tests need a backend with no
// database, and `TELEMETRY_STORE=memory` gives a reviewer a dashboard they can
// open in five seconds. It is explicitly not durable — the audit trail dies
// with the process — so Postgres remains the default and the service warns
// loudly when this is selected.
type Memory struct {
	mu       sync.RWMutex
	events   []audit.Event
	eventIDs map[string]struct{}
	spans    []audit.Span
	spanKeys map[string]struct{}
}

// NewMemory creates an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		eventIDs: map[string]struct{}{},
		spanKeys: map[string]struct{}{},
	}
}

var _ Store = (*Memory)(nil)

// InsertEvents appends events, skipping ones already present.
func (m *Memory) InsertEvents(_ context.Context, events []audit.Event) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	inserted := 0
	for _, event := range events {
		if event.ID == "" {
			event.ID = event.Fingerprint()
		}
		if _, exists := m.eventIDs[event.ID]; exists {
			continue
		}
		m.eventIDs[event.ID] = struct{}{}
		m.events = append(m.events, event)
		inserted++
	}
	return inserted, nil
}

// InsertSpans appends spans, skipping duplicates.
func (m *Memory) InsertSpans(_ context.Context, spans []audit.Span) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	inserted := 0
	for _, span := range spans {
		key := span.TraceID + ":" + span.SpanID
		if _, exists := m.spanKeys[key]; exists {
			continue
		}
		m.spanKeys[key] = struct{}{}
		m.spans = append(m.spans, span)
		inserted++
	}
	return inserted, nil
}

// QueryEvents returns matching events, newest first.
func (m *Memory) QueryEvents(_ context.Context, filter audit.Filter) ([]audit.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]audit.Event, 0, len(m.events))
	for _, event := range m.events {
		if filter.Matches(event) {
			matched = append(matched, event)
		}
	}
	audit.SortEvents(matched)

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= len(matched) {
		return []audit.Event{}, nil
	}
	end := offset + clampLimit(filter.Limit)
	if end > len(matched) {
		end = len(matched)
	}
	return matched[offset:end], nil
}

// Summary aggregates the window starting at since.
func (m *Memory) Summary(_ context.Context, since, now time.Time) (*audit.Summary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := make([]audit.Event, 0, len(m.events))
	for _, event := range m.events {
		if !event.OccurredAt.Before(since) && !event.OccurredAt.After(now) {
			events = append(events, event)
		}
	}
	spans := make([]audit.Span, 0, len(m.spans))
	for _, span := range m.spans {
		if !span.Start.Before(since) && !span.Start.After(now) {
			spans = append(spans, span)
		}
	}
	summary := audit.Summarise(events, spans, since, now)
	return &summary, nil
}

// Trace assembles one distributed flow, or nil when nothing is known about it.
func (m *Memory) Trace(_ context.Context, traceID string) (*audit.Trace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var spans []audit.Span
	for _, span := range m.spans {
		if span.TraceID == traceID {
			spans = append(spans, span)
		}
	}
	var events []audit.Event
	for _, event := range m.events {
		if event.TraceID == traceID {
			events = append(events, event)
		}
	}
	if len(spans) == 0 && len(events) == 0 {
		return nil, nil
	}
	return audit.BuildTrace(traceID, spans, events), nil
}

// Purge removes events older than the given time.
func (m *Memory) Purge(_ context.Context, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	kept := m.events[:0]
	removed := 0
	for _, event := range m.events {
		if event.OccurredAt.Before(before) {
			delete(m.eventIDs, event.ID)
			removed++
			continue
		}
		kept = append(kept, event)
	}
	m.events = kept
	return removed, nil
}

// Ping always succeeds for an in-process store.
func (m *Memory) Ping(context.Context) error { return nil }

// Len reports how many events are held (diagnostics and tests).
func (m *Memory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.events)
}
