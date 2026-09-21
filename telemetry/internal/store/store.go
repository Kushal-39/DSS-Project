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
	// Purge deletes events older than the given time, returning the count.
	Purge(ctx context.Context, before time.Time) (int, error)
	// Ping reports whether the backend is usable.
	Ping(ctx context.Context) error
}

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
