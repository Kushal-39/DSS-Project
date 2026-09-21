package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"telemetry/internal/audit"
	"telemetry/internal/db"
	"telemetry/migrations"
)

var clock = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func exampleEvent(at time.Time, service string, decision audit.Decision, reason string, traceID string) audit.Event {
	event := audit.Event{
		OccurredAt: at.UTC(),
		Category:   audit.CategoryAccess,
		Decision:   decision,
		Reason:     reason,
		Service:    service,
		Method:     "POST",
		Path:       "/login",
		Status:     401,
		TraceID:    traceID,
	}
	event.ID = event.Fingerprint()
	return event
}

func TestMemoryInsertIsIdempotent(t *testing.T) {
	ctx := context.Background()
	memory := NewMemory()

	events := []audit.Event{
		exampleEvent(clock, "idp", audit.DecisionDeny, "invalid_credentials", ""),
		exampleEvent(clock, "idp", audit.DecisionPermit, "ok", ""),
	}

	inserted, err := memory.InsertEvents(ctx, events)
	if err != nil || inserted != 2 {
		t.Fatalf("first insert: %d rows, err %v", inserted, err)
	}

	// A collector retry, a container restart re-reading its log file: the same
	// record arriving twice must not become two decisions.
	inserted, err = memory.InsertEvents(ctx, events)
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 0 {
		t.Errorf("second insert wrote %d rows, want 0", inserted)
	}
	if memory.Len() != 2 {
		t.Errorf("store holds %d events, want 2", memory.Len())
	}

	// An event with no id gets one derived from its content, so a producer that
	// omits it still cannot bypass the idempotency check.
	anonymous := exampleEvent(clock.Add(time.Minute), "idp", audit.DecisionDeny, "invalid_credentials", "")
	anonymous.ID = ""
	if _, err := memory.InsertEvents(ctx, []audit.Event{anonymous, anonymous}); err != nil {
		t.Fatal(err)
	}
	if memory.Len() != 3 {
		t.Errorf("store holds %d events, want 3", memory.Len())
	}
}

func TestMemoryQueryFiltersSortsAndPaginates(t *testing.T) {
	ctx := context.Background()
	memory := NewMemory()

	for i := 0; i < 5; i++ {
		if _, err := memory.InsertEvents(ctx, []audit.Event{
			exampleEvent(clock.Add(-time.Duration(i)*time.Minute), "idp", audit.DecisionDeny, "invalid_credentials", ""),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := memory.InsertEvents(ctx, []audit.Event{
		exampleEvent(clock.Add(-10*time.Minute), "api-gateway", audit.DecisionPermit, "ok", ""),
	}); err != nil {
		t.Fatal(err)
	}

	events, err := memory.QueryEvents(ctx, audit.Filter{Decision: "DENY", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want the requested 2", len(events))
	}
	if !events[0].OccurredAt.After(events[1].OccurredAt) && !events[0].OccurredAt.Equal(events[1].OccurredAt) {
		t.Error("events are not newest first")
	}

	page2, err := memory.QueryEvents(ctx, audit.Filter{Decision: "DENY", Limit: 2, Offset: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 2 || page2[0].ID == events[0].ID {
		t.Error("paging repeated the first page")
	}

	// Past the end is an empty page, not an error.
	empty, err := memory.QueryEvents(ctx, audit.Filter{Decision: "DENY", Limit: 2, Offset: 99})
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Errorf("got %d events past the end, want 0", len(empty))
	}

	// A negative offset and an absurd limit are clamped rather than rejected,
	// because they come from a query string a human typed.
	clamped, err := memory.QueryEvents(ctx, audit.Filter{Limit: 100000, Offset: -5})
	if err != nil {
		t.Fatal(err)
	}
	if len(clamped) != 6 {
		t.Errorf("got %d events, want all 6", len(clamped))
	}
}

func TestMemorySummaryHonoursTheWindow(t *testing.T) {
	ctx := context.Background()
	memory := NewMemory()

	inside := exampleEvent(clock.Add(-10*time.Minute), "idp", audit.DecisionDeny, "invalid_credentials", "")
	outside := exampleEvent(clock.Add(-5*time.Hour), "idp", audit.DecisionDeny, "invalid_credentials", "")
	if _, err := memory.InsertEvents(ctx, []audit.Event{inside, outside}); err != nil {
		t.Fatal(err)
	}
	if _, err := memory.InsertSpans(ctx, []audit.Span{
		{TraceID: "a", SpanID: "1", Service: "idp", Name: "x", Start: clock.Add(-time.Minute)},
		{TraceID: "b", SpanID: "2", Service: "idp", Name: "y", Start: clock.Add(-9 * time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}

	summary, err := memory.Summary(ctx, clock.Add(-time.Hour), clock)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 1 || summary.Denials != 1 {
		t.Errorf("summary = %d events / %d denials, want 1/1", summary.Total, summary.Denials)
	}
	if summary.SpanCount != 1 {
		t.Errorf("span_count = %d, want 1 (the other span is outside the window)", summary.SpanCount)
	}
	if summary.Window != time.Hour {
		t.Errorf("window = %s", summary.Window)
	}
}

func TestMemoryTraceAssemblesOneFlow(t *testing.T) {
	ctx := context.Background()
	memory := NewMemory()
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"

	if _, err := memory.InsertEvents(ctx, []audit.Event{
		exampleEvent(clock, "api-gateway", audit.DecisionDeny, "unauthorized", traceID),
		exampleEvent(clock, "idp", audit.DecisionPermit, "ok", "00000000000000000000000000000000"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := memory.InsertSpans(ctx, []audit.Span{
		{TraceID: traceID, SpanID: "00f067aa0ba902b7", Service: "api-gateway", Name: "POST /login",
			Start: clock, End: clock.Add(10 * time.Millisecond), DurationNS: int64(10 * time.Millisecond)},
	}); err != nil {
		t.Fatal(err)
	}

	trace, err := memory.Trace(ctx, traceID)
	if err != nil {
		t.Fatal(err)
	}
	if trace == nil {
		t.Fatal("Trace returned nil for a known trace")
	}
	if trace.SpanCount != 1 || trace.EventCount != 1 || trace.Denied != 1 {
		t.Errorf("trace = %d spans / %d events / %d denials, want 1/1/1",
			trace.SpanCount, trace.EventCount, trace.Denied)
	}

	unknown, err := memory.Trace(ctx, "ffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	if unknown != nil {
		t.Errorf("Trace invented a flow for an unknown id: %+v", unknown)
	}
}

func TestMemoryPurgeEnforcesRetention(t *testing.T) {
	ctx := context.Background()
	memory := NewMemory()

	if _, err := memory.InsertEvents(ctx, []audit.Event{
		exampleEvent(clock.Add(-400*24*time.Hour), "idp", audit.DecisionDeny, "invalid_credentials", ""),
		exampleEvent(clock.Add(-time.Minute), "idp", audit.DecisionPermit, "ok", ""),
	}); err != nil {
		t.Fatal(err)
	}

	removed, err := memory.Purge(ctx, clock.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("purged %d events, want 1", removed)
	}
	if memory.Len() != 1 {
		t.Errorf("store holds %d events, want the recent one kept", memory.Len())
	}

	// A purged record must not leave a stale id behind, or re-ingesting it
	// would be silently ignored forever.
	if _, err := memory.InsertEvents(ctx, []audit.Event{
		exampleEvent(clock.Add(-400*24*time.Hour), "idp", audit.DecisionDeny, "invalid_credentials", ""),
	}); err != nil {
		t.Fatal(err)
	}
	if memory.Len() != 2 {
		t.Errorf("store holds %d events, want the purged record to be insertable again", memory.Len())
	}

	if err := memory.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

func TestClampLimit(t *testing.T) {
	cases := map[int]int{0: 100, -1: 100, 10: 10, 1000: 1000, 100000: 1000}
	for input, want := range cases {
		if got := clampLimit(input); got != want {
			t.Errorf("clampLimit(%d) = %d, want %d", input, got, want)
		}
	}
}

// TestPostgresStore exercises the real SQL, including the aggregate query the
// dashboard depends on and the retention delete.
//
// It is opt-in because it writes to a live database:
//
//	TELEMETRY_TEST_DATABASE_URL=postgres://.../throwaway?sslmode=disable go test ./internal/store/...
//
// Every row it creates is tagged with a unique marker service and deleted
// afterwards, and its purge assertion only ever targets rows older than 30
// days, which nothing else in a test database has.
func TestPostgresStore(t *testing.T) {
	databaseURL := os.Getenv("TELEMETRY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set TELEMETRY_TEST_DATABASE_URL to a throwaway database to run the Postgres integration test")
	}

	ctx := context.Background()
	if err := db.Migrate(ctx, databaseURL, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := db.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Registered first so it runs last: the row cleanup below needs the pool.
	t.Cleanup(pool.Close)

	// The rows are tagged with a prefix rather than a fixed name, and cleanup
	// sweeps the whole prefix: a previous run that crashed before its cleanup
	// must not be able to satisfy (or break) this run's assertions.
	markerPrefix := "postgres-integration-test"
	marker := fmt.Sprintf("%s-%d", markerPrefix, time.Now().UnixNano())
	postgres := NewPostgres(pool)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanup, `DELETE FROM audit_events WHERE service LIKE $1`, markerPrefix+"%"); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		if _, err := pool.Exec(cleanup, `DELETE FROM spans WHERE service LIKE $1`, markerPrefix+"%"); err != nil {
			t.Errorf("cleanup spans: %v", err)
		}
	})

	// A fresh trace id per run: the assertions below count this trace's spans
	// and decisions exactly, so leftover rows from an earlier run (or from a
	// live service that happens to be running) must not be able to satisfy or
	// break them.
	now := time.Now().UTC()
	traceID := fmt.Sprintf("%032x", now.UnixNano())
	parentSpanID := fmt.Sprintf("%016x", now.UnixNano())
	childSpanID := fmt.Sprintf("%016x", now.UnixNano()+1)

	events := []audit.Event{
		exampleEvent(now.Add(-10*time.Minute), marker, audit.DecisionDeny, "invalid_credentials", traceID),
		exampleEvent(now.Add(-9*time.Minute), marker, audit.DecisionDeny, "rate_limited", ""),
		exampleEvent(now.Add(-8*time.Minute), marker, audit.DecisionPermit, "ok", ""),
	}
	events[0].Category = audit.CategoryAuth
	events[0].Subject = "admin"
	events[0].RemoteAddr = "203.0.113.7"
	events[1].Category = audit.CategoryRateLimit
	events[2].Category = audit.CategoryAccess
	for i := range events {
		events[i].Service = marker
		events[i].ID = events[i].Fingerprint()
	}

	inserted, err := postgres.InsertEvents(ctx, events)
	if err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}
	if inserted != len(events) {
		t.Errorf("inserted %d rows, want %d", inserted, len(events))
	}
	if again, err := postgres.InsertEvents(ctx, events); err != nil || again != 0 {
		t.Errorf("re-insert wrote %d rows (err %v), want 0: ON CONFLICT must deduplicate", again, err)
	}

	spans := []audit.Span{
		{TraceID: traceID, SpanID: parentSpanID, Service: marker, Name: "POST /login",
			Start: now.Add(-10 * time.Minute), End: now.Add(-10*time.Minute + 12*time.Millisecond),
			DurationNS: int64(12 * time.Millisecond), Status: "error",
			Attributes: map[string]string{"http.response.status_code": "401"}},
		// An in-flight span has no end time; it must not be stored as year 1.
		{TraceID: traceID, SpanID: childSpanID, ParentSpanID: parentSpanID,
			Service: marker, Name: "bcrypt compare", Start: now.Add(-9 * time.Minute), Status: "unset"},
	}
	if inserted, err := postgres.InsertSpans(ctx, spans); err != nil || inserted != 2 {
		t.Fatalf("InsertSpans: %d rows, err %v", inserted, err)
	}

	t.Run("query with every filter", func(t *testing.T) {
		for _, filter := range []audit.Filter{
			{Service: marker},
			{Decision: "DENY", Service: marker},
			{Category: "AUTH", Service: marker},
			{Reason: "rate_limited", Service: marker},
			{Subject: "admin", Service: marker},
			{Search: "invalid_credentials", Service: marker},
			{TraceID: traceID, Service: marker},
			{Since: now.Add(-time.Hour), Until: now, Service: marker},
			{Service: marker, Limit: 2},
			{Service: marker, Limit: 2, Offset: 2},
			{Service: marker, Search: "50%_literal"}, // no wildcard injection
		} {
			if _, err := postgres.QueryEvents(ctx, filter); err != nil {
				t.Errorf("filter %+v: %v", filter, err)
			}
		}

		matched, err := postgres.QueryEvents(ctx, audit.Filter{Service: marker, Search: "invalid_credentials"})
		if err != nil {
			t.Fatal(err)
		}
		if len(matched) != 1 {
			t.Fatalf("search matched %d events, want 1", len(matched))
		}
		if matched[0].Category != audit.CategoryAuth || matched[0].Subject != "admin" {
			t.Errorf("round-trip lost fields: %+v", matched[0])
		}

		page, err := postgres.QueryEvents(ctx, audit.Filter{Service: marker, Limit: 2, Offset: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) != 1 {
			t.Errorf("offset page returned %d events, want 1", len(page))
		}
	})

	t.Run("summary aggregates in SQL", func(t *testing.T) {
		summary, err := postgres.Summary(ctx, now.Add(-time.Hour), now)
		if err != nil {
			t.Fatalf("Summary: %v", err)
		}
		if summary.Denials < 2 || summary.Permits < 1 {
			t.Errorf("summary = %d denials / %d permits, want at least 2/1", summary.Denials, summary.Permits)
		}
		if summary.RateLimited < 1 {
			t.Error("the rate-limited event was not counted separately")
		}
		if summary.UnauthorizedAttempts < 1 {
			t.Error("the auth denial was not counted as an unauthorized attempt")
		}
		if summary.TraceCount < 1 || summary.SpanCount < 2 {
			t.Errorf("trace/span counts = %d/%d, want at least 1/2", summary.TraceCount, summary.SpanCount)
		}
		if len(summary.Timeline) == 0 {
			t.Error("the SQL timeline is empty, so the dashboard chart would have no axis")
		}
		var timelineTotal int
		for _, bucket := range summary.Timeline {
			timelineTotal += bucket.Total
		}
		if timelineTotal < 3 {
			t.Errorf("timeline totals %d events, want at least 3", timelineTotal)
		}
		if len(summary.ByReason) == 0 || len(summary.ByService) == 0 || len(summary.ByDecision) == 0 {
			t.Error("the dashboard panels came back empty")
		}
	})

	t.Run("trace join", func(t *testing.T) {
		trace, err := postgres.Trace(ctx, traceID)
		if err != nil {
			t.Fatalf("Trace: %v", err)
		}
		if trace == nil {
			t.Fatal("Trace returned nil for a stored trace")
		}
		if trace.SpanCount != 2 {
			t.Errorf("span_count = %d, want 2", trace.SpanCount)
		}
		if trace.EventCount == 0 {
			t.Error("the trace join lost its audit decisions")
		}
		if trace.DurationMS == 0 {
			t.Error("the trace has no duration, so its spans did not sort")
		}
		// An id that is not present is nil, not an empty trace.
		missing, err := postgres.Trace(ctx, "ffffffffffffffffffffffffffffffff")
		if err != nil {
			t.Fatal(err)
		}
		if missing != nil {
			t.Errorf("Trace invented a flow: %+v", missing)
		}
	})

	t.Run("retention", func(t *testing.T) {
		stale := exampleEvent(now.Add(-400*24*time.Hour), marker, audit.DecisionDeny, "invalid_credentials", "")
		if _, err := postgres.InsertEvents(ctx, []audit.Event{stale}); err != nil {
			t.Fatal(err)
		}
		removed, err := postgres.Purge(ctx, now.Add(-30*24*time.Hour))
		if err != nil {
			t.Fatalf("Purge: %v", err)
		}
		if removed < 1 {
			t.Errorf("purged %d rows, want at least the 400-day-old one", removed)
		}
		remaining, err := postgres.QueryEvents(ctx, audit.Filter{Service: marker, Since: now.Add(-400 * 24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range remaining {
			if event.OccurredAt.Before(now.Add(-30 * 24 * time.Hour)) {
				t.Errorf("a record older than the retention window survived: %s", event.OccurredAt)
			}
		}
	})

	if err := postgres.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}
}
