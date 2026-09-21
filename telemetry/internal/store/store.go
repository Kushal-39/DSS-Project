// Package store persists the audit trail and the spans that trace flows are
// assembled from.
//
// The interface exists so the pipeline can be tested without a database and so
// the choice of backend stays a configuration detail: `postgres` is the real
// one (Database-per-Service — telemetry owns `audit_events` and `spans`, see
// docs/database.md), `memory` is the explicit, volatile dev mode.
package store

import (
	"context"
	"time"

	"telemetry/internal/audit"
)

// Store is the telemetry persistence contract.
type Store interface {
	// InsertEvents appends events, skipping ones already stored (the same
	// record re-ingested must not be counted twice). It returns how many rows
	// were newly written.
	InsertEvents(ctx context.Context, events []audit.Event) (int, error)
	// InsertSpans appends spans, skipping duplicates.
	InsertSpans(ctx context.Context, spans []audit.Span) (int, error)
	// QueryEvents returns events matching the filter, newest first.
	QueryEvents(ctx context.Context, filter audit.Filter) ([]audit.Event, error)
	// Summary aggregates the window that starts at `since`.
	Summary(ctx context.Context, since, now time.Time) (*audit.Summary, error)
	// Trace assembles one distributed flow.
	Trace(ctx context.Context, traceID string) (*audit.Trace, error)
	// Purge deletes everything older than the given time — both the decisions
	// and the spans — and reports what went, per table.
	Purge(ctx context.Context, before time.Time) (Purged, error)
	// Ping reports whether the backend is usable.
	Ping(ctx context.Context) error
}

// Purged is what one retention sweep removed.
//
// The two counts are kept apart because they are different things: an expired
// debug span and an expired security decision have different meanings, and a
// single total would report "removed 1" for a sweep that removed a decision and
// a span — or, when only spans expired, report nothing at all.
//
// Both backends must purge both tables. They did not: the in-memory store
// deleted events and left every span in place, so a demo instance's trace view
// grew without bound while the same sweep against Postgres stayed bounded.
type Purged struct {
	Events int
	Spans  int
}

// Total is the number of rows removed overall.
func (p Purged) Total() int { return p.Events + p.Spans }

// Empty reports whether the sweep removed nothing, which is the normal case and
// not worth a log line.
func (p Purged) Empty() bool { return p.Events == 0 && p.Spans == 0 }

// clampLimit keeps a caller-supplied page size inside sane bounds.
func clampLimit(limit int) int {
	switch {
	case limit <= 0:
		return 100
	case limit > 1000:
		return 1000
	default:
		return limit
	}
}
