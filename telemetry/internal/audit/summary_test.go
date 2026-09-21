package audit

import (
	"testing"
	"time"
)

func TestSummariseSeparatesThrottlingFromUnusualAuthentication(t *testing.T) {
	// The distinction that matters: a burst of rate limiting must not be able
	// to drown out an intrusion attempt, so the two are counted separately.
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	since := now.Add(-time.Hour)

	// An access denial is an intrusion attempt when the producer recorded the
	// status that rejected it (401/403), which is exactly what the gateway and
	// the IdP emit. A bare reason with no status is a decision record, not an
	// observed rejection.
	rejectedCredentials := event(now, "api-gateway", CategoryAccess, DecisionDeny, "unauthorized", "", "203.0.113.7")
	rejectedCredentials.Status = 401
	forbidden := event(now, "api-gateway", CategoryAccess, DecisionDeny, "forbidden", "customer", "203.0.113.9")
	forbidden.Status = 403

	events := []Event{
		event(now, "idp", CategoryAuth, DecisionDeny, "invalid_credentials", "admin", "203.0.113.7"),
		event(now, "idp", CategoryAuth, DecisionDeny, "invalid_credentials", "admin", "203.0.113.7"),
		rejectedCredentials,
		forbidden,
		event(now, "api-gateway", CategoryRateLimit, DecisionDeny, "rate_limited", "customer", "203.0.113.9"),
		event(now, "api-gateway", CategoryRateLimit, DecisionDeny, "rate_limited", "customer", "203.0.113.9"),
		event(now, "policy-engine", CategoryAuthz, DecisionDeny, "threat_level_high", "customer", ""),
		event(now, "account-service", CategoryAuthz, DecisionPermit, "policy_allowed", "customer", ""),
		event(now, "idp", CategoryAccess, DecisionPermit, "ok", "", "172.20.0.1"),
		event(now, "payment-service", CategoryError, DecisionError, "upstream_error", "", ""),
	}

	summary := Summarise(events, nil, since, now)

	if summary.Total != 10 {
		t.Errorf("total = %d, want 10", summary.Total)
	}
	if summary.Permits != 2 || summary.Denials != 7 || summary.Errors != 1 {
		t.Errorf("permits/denials/errors = %d/%d/%d, want 2/7/1",
			summary.Permits, summary.Denials, summary.Errors)
	}
	if summary.RateLimited != 2 {
		t.Errorf("rate_limited = %d, want 2", summary.RateLimited)
	}
	// 7 denials minus the 2 that are throttling.
	if summary.UnauthorizedAttempts != 5 {
		t.Errorf("unauthorized_attempts = %d, want 5 (throttling excluded)", summary.UnauthorizedAttempts)
	}
	if summary.ActiveServices != 5 {
		t.Errorf("active_services = %d, want 5", summary.ActiveServices)
	}
	// 7 denials out of 10 decided requests.
	if got := summary.DenialRate; got < 0.69 || got > 0.71 {
		t.Errorf("denial_rate = %v, want ~0.7", got)
	}
	if len(summary.ByReason) == 0 || summary.ByReason[0].Key != "invalid_credentials" || summary.ByReason[0].Count != 2 {
		t.Errorf("by_reason = %+v, want invalid_credentials first", summary.ByReason)
	}
	if len(summary.TopClients) == 0 || summary.TopClients[0].Key != "203.0.113.7" || summary.TopClients[0].Count != 3 {
		t.Errorf("top_clients = %+v, want 203.0.113.7 with 3", summary.TopClients)
	}
	if len(summary.LatestDenials) != 7 {
		t.Errorf("latest_denials = %d, want 7", len(summary.LatestDenials))
	}
	for _, denial := range summary.LatestDenials {
		if denial.Decision != DecisionDeny {
			t.Errorf("latest_denials contains a %s event", denial.Decision)
		}
	}
}

func TestSummariseHandlesAnEmptyWindow(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	summary := Summarise(nil, nil, now.Add(-time.Hour), now)

	if summary.Total != 0 || summary.DenialRate != 0 {
		t.Errorf("empty window produced %d events, rate %v", summary.Total, summary.DenialRate)
	}
	// A reviewer opening a fresh install must still see an empty chart, not a
	// missing one.
	if len(summary.Timeline) == 0 {
		t.Error("empty window produced no timeline buckets, so the chart has no axis")
	}
}

func TestBuildTimelineHasNoGapsAndCountsPerDecision(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	since := now.Add(-3 * time.Hour)

	events := []Event{
		event(now.Add(-2*time.Hour-30*time.Minute), "idp", CategoryAuth, DecisionPermit, "authenticated", "a", ""),
		event(now.Add(-2*time.Hour-10*time.Minute), "idp", CategoryAuth, DecisionDeny, "invalid_credentials", "b", ""),
		event(now.Add(-10*time.Minute), "idp", CategoryAuth, DecisionDeny, "invalid_credentials", "b", ""),
		event(now.Add(-5*time.Minute), "idp", CategoryError, DecisionError, "upstream_error", "", ""),
	}

	timeline := BuildTimeline(events, since, now, time.Hour)
	if len(timeline) < 3 {
		t.Fatalf("timeline has %d buckets, want at least 3", len(timeline))
	}
	// Contiguous, ascending, and hour-aligned.
	for i, bucket := range timeline {
		if bucket.Start.Minute() != 0 || bucket.Start.Second() != 0 {
			t.Errorf("bucket %d starts at %s, not on an hour boundary", i, bucket.Start)
		}
		if i > 0 && !bucket.Start.After(timeline[i-1].Start) {
			t.Errorf("bucket %d does not follow bucket %d", i, i-1)
		}
	}

	var totals, denies, errors int
	for _, bucket := range timeline {
		totals += bucket.Total
		denies += bucket.Deny
		errors += bucket.Errored
	}
	if totals != len(events) || denies != 2 || errors != 1 {
		t.Errorf("timeline totals = %d/%d/%d, want %d/2/1", totals, denies, errors, len(events))
	}
}

func TestBucketSizeScalesWithTheWindow(t *testing.T) {
	cases := []struct {
		window time.Duration
		want   time.Duration
	}{
		{30 * time.Minute, time.Minute},
		{2 * time.Hour, time.Minute},
		{12 * time.Hour, time.Hour},
		{48 * time.Hour, time.Hour},
		{7 * 24 * time.Hour, 6 * time.Hour},
		{90 * 24 * time.Hour, 24 * time.Hour},
	}
	for _, test := range cases {
		if got := BucketSize(test.window); got != test.want {
			t.Errorf("BucketSize(%s) = %s, want %s", test.window, got, test.want)
		}
	}
}

func TestFillTimelineCapsTheNumberOfPoints(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	// A 30-day window at minute resolution would be 43200 points.
	timeline := BuildTimeline(nil, now.Add(-30*24*time.Hour), now, time.Minute)
	if len(timeline) > 720 {
		t.Errorf("timeline returned %d points, want it capped near 720", len(timeline))
	}
	if len(timeline) == 0 {
		t.Error("timeline is empty")
	}
}

func TestFillTimelineRejectsAnInvertedWindow(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	if got := FillTimeline(nil, now, now.Add(-time.Hour), time.Minute); got != nil {
		t.Errorf("inverted window produced %d buckets, want none", len(got))
	}
	if got := FillTimeline(nil, now.Add(-time.Hour), now, 0); got != nil {
		t.Errorf("zero-sized bucket produced %d buckets, want none", len(got))
	}
}

func TestFilterMatches(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	subject := event(now, "api-gateway", CategoryAccess, DecisionDeny, "unauthorized", "customer", "203.0.113.7")
	subject.TraceID = traceID
	subject.EventType = "http_request"
	subject.Path = "/api/v1/payment"

	tests := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{"empty filter matches everything", Filter{}, true},
		{"case-insensitive decision", Filter{Decision: "deny"}, true},
		{"wrong decision", Filter{Decision: "PERMIT"}, false},
		{"category", Filter{Category: "access"}, true},
		{"service", Filter{Service: "api-gateway"}, true},
		{"reason", Filter{Reason: "unauthorized"}, true},
		{"subject", Filter{Subject: "customer"}, true},
		{"trace id", Filter{TraceID: traceID}, true},
		{"search in path", Filter{Search: "/api/v1/payment"}, true},
		{"search in client", Filter{Search: "203.0.113"}, true},
		{"search miss", Filter{Search: "nonexistent"}, false},
		{"window contains the event", Filter{Since: now.Add(-time.Hour), Until: now.Add(time.Minute)}, true},
		{"window ends before the event", Filter{Until: now.Add(-time.Minute)}, false},
		{"window starts after the event", Filter{Since: now.Add(time.Minute)}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.filter.Matches(subject); got != test.want {
				t.Errorf("Matches = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSortEventsIsStableForPagination(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	older := event(now.Add(-time.Hour), "idp", CategoryAccess, DecisionPermit, "ok", "", "")
	newer := event(now, "idp", CategoryAccess, DecisionPermit, "ok", "", "")

	events := []Event{older, newer}
	SortEvents(events)
	if events[0].ID != newer.ID {
		t.Error("events are not newest first")
	}

	// Equal timestamps must order deterministically, or the same record could
	// appear on two pages and another on none.
	same := []Event{
		{ID: "aaa", OccurredAt: now},
		{ID: "bbb", OccurredAt: now},
		{ID: "ccc", OccurredAt: now},
	}
	SortEvents(same)
	if same[0].ID != "ccc" || same[2].ID != "aaa" {
		t.Errorf("equal timestamps tie-break unpredictably: %s %s %s", same[0].ID, same[1].ID, same[2].ID)
	}
}

func TestTopCountsOrdersDeterministically(t *testing.T) {
	counts := topCounts(map[string]int{"b": 2, "a": 2, "c": 5}, 2)
	if len(counts) != 2 {
		t.Fatalf("got %d counts, want 2", len(counts))
	}
	if counts[0].Key != "c" || counts[0].Count != 5 {
		t.Errorf("first entry = %+v, want c=5", counts[0])
	}
	// Equal counts fall back to alphabetical order, so the panel does not
	// reshuffle between refreshes.
	if counts[1].Key != "a" {
		t.Errorf("second entry = %+v, want a=2", counts[1])
	}
}

func TestBuildTraceJoinsSpansAndDecisions(t *testing.T) {
	start := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

	spans := []Span{
		{TraceID: traceID, SpanID: "00f067aa0ba902b7", Service: "api-gateway", Name: "POST /api/v1/payment",
			Start: start, End: start.Add(120 * time.Millisecond), DurationNS: int64(120 * time.Millisecond), Status: "unset"},
		{TraceID: traceID, SpanID: "1111111111111111", ParentSpanID: "00f067aa0ba902b7", Service: "idp",
			Start: start.Add(10 * time.Millisecond), End: start.Add(40 * time.Millisecond), Status: "error"},
	}
	events := []Event{
		event(start.Add(20*time.Millisecond), "policy-engine", CategoryAuthz, DecisionDeny, "threat_level_high", "customer", ""),
		event(start.Add(30*time.Millisecond), "api-gateway", CategoryAccess, DecisionPermit, "ok", "customer", ""),
	}

	trace := BuildTrace(traceID, spans, events)

	if trace.TraceID != traceID {
		t.Errorf("trace_id = %q", trace.TraceID)
	}
	if trace.SpanCount != 2 || trace.EventCount != 2 {
		t.Errorf("span/event counts = %d/%d, want 2/2", trace.SpanCount, trace.EventCount)
	}
	if trace.Denied != 1 {
		t.Errorf("denied = %d, want 1", trace.Denied)
	}
	if len(trace.Services) != 3 {
		t.Errorf("services = %v, want api-gateway, idp, policy-engine", trace.Services)
	}
	if trace.Services[0] != "api-gateway" || trace.Services[2] != "policy-engine" {
		t.Errorf("services are not sorted: %v", trace.Services)
	}
	if !trace.StartedAt.Equal(start) {
		t.Errorf("started_at = %s, want the earliest span start", trace.StartedAt)
	}
	if trace.DurationMS != 120 {
		t.Errorf("duration_ms = %d, want 120 (end of the last span)", trace.DurationMS)
	}
}

func TestBuildTraceHandlesAnEmptyFlow(t *testing.T) {
	trace := BuildTrace(traceID, nil, nil)
	if trace.SpanCount != 0 || trace.EventCount != 0 || trace.Denied != 0 {
		t.Errorf("empty trace = %+v", trace)
	}
	if trace.DurationMS != 0 || !trace.StartedAt.IsZero() {
		t.Errorf("empty trace has a duration or start time: %v / %s", trace.DurationMS, trace.StartedAt)
	}
}

func TestSpanDurationMilliseconds(t *testing.T) {
	if got := (Span{DurationNS: 1_500_000}).DurationMS(); got != 1 {
		t.Errorf("DurationMS = %d, want 1", got)
	}
}

// event builds a minimal event for aggregation tests.
func event(at time.Time, service string, category Category, decision Decision, reason, subject, client string) Event {
	return Event{
		ID:         DeterministicID(service, reason, subject, client, at.Format(time.RFC3339Nano)),
		OccurredAt: at,
		Category:   category,
		Decision:   decision,
		Reason:     reason,
		Service:    service,
		Subject:    subject,
		RemoteAddr: client,
	}
}
