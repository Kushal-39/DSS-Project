package audit

import (
	"sort"
	"strings"
	"time"
)

// BucketSize picks a timeline resolution that keeps a chart readable without
// returning thousands of points for a week-long window.
func BucketSize(window time.Duration) time.Duration {
	switch {
	case window <= 2*time.Hour:
		return time.Minute
	case window <= 48*time.Hour:
		return time.Hour
	case window <= 30*24*time.Hour:
		return 6 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// bucketStart snaps an instant to an epoch-aligned bucket boundary.
//
// It is epoch-aligned rather than time.Truncate because the SQL backend
// computes buckets with floor(extract(epoch ...) / size) * size; both sides
// must agree exactly or the same data would chart differently depending on
// which store is behind the API.
func bucketStart(moment time.Time, size time.Duration) time.Time {
	seconds := int64(size / time.Second)
	if seconds <= 0 {
		return moment
	}
	return time.Unix((moment.Unix()/seconds)*seconds, 0).UTC()
}

// Matches reports whether an event satisfies a filter. Both stores use it, so
// the read API behaves identically whatever the backend.
func (f Filter) Matches(event Event) bool {
	if f.Decision != "" && !strings.EqualFold(f.Decision, string(event.Decision)) {
		return false
	}
	if f.Category != "" && !strings.EqualFold(f.Category, string(event.Category)) {
		return false
	}
	if f.Service != "" && !strings.EqualFold(f.Service, event.Service) {
		return false
	}
	if f.Reason != "" && !strings.EqualFold(f.Reason, event.Reason) {
		return false
	}
	if f.Subject != "" && !strings.EqualFold(f.Subject, event.Subject) {
		return false
	}
	if f.TraceID != "" && !strings.EqualFold(f.TraceID, event.TraceID) {
		return false
	}
	if !f.Since.IsZero() && event.OccurredAt.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && event.OccurredAt.After(f.Until) {
		return false
	}
	if f.Search != "" && !searchMatches(f.Search, event) {
		return false
	}
	return true
}

func searchMatches(needle string, event Event) bool {
	needle = strings.ToLower(needle)
	haystack := strings.ToLower(strings.Join([]string{
		event.Service, event.EventType, event.Path, event.Message,
		event.Subject, event.Reason, event.RemoteAddr, event.TraceID, event.Action,
	}, " "))
	return strings.Contains(haystack, needle)
}

// SortEvents orders events newest first, with a stable tie-break so pagination
// cannot shuffle equal timestamps between requests.
func SortEvents(events []Event) {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].ID > events[j].ID
		}
		return events[i].OccurredAt.After(events[j].OccurredAt)
	})
}

// Summarise aggregates events and spans into the numbers the audit dashboard
// shows.
func Summarise(events []Event, spans []Span, since, now time.Time) Summary {
	summary := Summary{
		Since:  since,
		Until:  now,
		Window: now.Sub(since),
	}

	reasonCounts := map[string]int{}
	serviceCounts := map[string]int{}
	categoryCounts := map[string]int{}
	decisionCounts := map[string]int{}
	subjectCounts := map[string]int{}
	clientCounts := map[string]int{}
	traces := map[string]struct{}{}

	for _, event := range events {
		summary.Total++
		decisionCounts[string(event.Decision)]++
		categoryCounts[string(event.Category)]++
		serviceCounts[event.Service]++

		switch event.Decision {
		case DecisionPermit:
			summary.Permits++
		case DecisionDeny:
			summary.Denials++
			reasonCounts[event.Reason]++
			if event.Subject != "" {
				subjectCounts[event.Subject]++
			}
			if event.RemoteAddr != "" {
				clientCounts[event.RemoteAddr]++
			}
			if isUnauthorizedAttempt(event) {
				summary.UnauthorizedAttempts++
			}
		case DecisionError:
			summary.Errors++
		default:
			summary.Info++
		}

		if isRateLimited(event) {
			summary.RateLimited++
		}
		if event.TraceID != "" {
			traces[event.TraceID] = struct{}{}
		}
	}

	summary.ActiveServices = len(serviceCounts)
	summary.TraceCount = len(traces)
	summary.SpanCount = len(spans)

	if decisions := summary.Permits + summary.Denials + summary.Errors; decisions > 0 {
		summary.DenialRate = float64(summary.Denials) / float64(decisions)
	}

	summary.ByReason = topCounts(reasonCounts, 10)
	summary.ByService = topCounts(serviceCounts, 10)
	summary.ByCategory = topCounts(categoryCounts, 10)
	summary.ByDecision = topCounts(decisionCounts, 10)
	summary.TopSubjects = topCounts(subjectCounts, 5)
	summary.TopClients = topCounts(clientCounts, 5)
	summary.Timeline = BuildTimeline(events, since, now, BucketSize(summary.Window))
	summary.LatestDenials = latestDenials(events, 10)
	return summary
}

// isUnauthorizedAttempt counts rejected credentials and policy denials — the
// "unauthorized access attempts" the deliverable asks for. Throttling is
// deliberately excluded so a burst of rate limiting cannot drown out an
// intrusion attempt.
func isUnauthorizedAttempt(event Event) bool {
	if event.Decision != DecisionDeny {
		return false
	}
	if isRateLimited(event) {
		return false
	}
	if event.Category == CategoryAuth || event.Category == CategoryAuthz {
		return true
	}
	return event.Status == 401 || event.Status == 403
}

func isRateLimited(event Event) bool {
	return event.Category == CategoryRateLimit || event.Reason == "rate_limited"
}

// topCounts returns the highest counts, with a deterministic tie-break.
func topCounts(counts map[string]int, limit int) []Count {
	if len(counts) == 0 {
		return nil
	}
	result := make([]Count, 0, len(counts))
	for key, count := range counts {
		result = append(result, Count{Key: key, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count == result[j].Count {
			return result[i].Key < result[j].Key
		}
		return result[i].Count > result[j].Count
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result
}

// BuildTimeline buckets events over the window. It is the in-process
// equivalent of the SQL backend's timeline query.
func BuildTimeline(events []Event, since, now time.Time, size time.Duration) []Bucket {
	sparse := map[int64]Bucket{}
	for _, event := range events {
		key := bucketStart(event.OccurredAt, size).Unix()
		bucket := sparse[key]
		bucket.Start = time.Unix(key, 0).UTC()
		bucket.Total++
		switch event.Decision {
		case DecisionPermit:
			bucket.Permit++
		case DecisionDeny:
			bucket.Deny++
		case DecisionError:
			bucket.Errored++
		}
		sparse[key] = bucket
	}
	return FillTimeline(sparse, since, now, size)
}

// FillTimeline expands sparse per-bucket counts into a contiguous series so
// the dashboard chart has no misleading gaps.
func FillTimeline(sparse map[int64]Bucket, since, now time.Time, size time.Duration) []Bucket {
	if size <= 0 || !now.After(since) {
		return nil
	}

	start := bucketStart(since, size)
	keys := []int64{}
	for moment := start; !moment.After(now); moment = moment.Add(size) {
		keys = append(keys, moment.Unix())
	}
	// Cap the number of points regardless of the requested window.
	if len(keys) > 720 && size < 24*time.Hour {
		return FillTimeline(sparse, since, now, size*time.Duration(len(keys)/720+1))
	}

	timeline := make([]Bucket, 0, len(keys))
	for _, key := range keys {
		bucket := Bucket{Start: time.Unix(key, 0).UTC()}
		if filled, ok := sparse[key]; ok {
			bucket.Total = filled.Total
			bucket.Permit = filled.Permit
			bucket.Deny = filled.Deny
			bucket.Errored = filled.Errored
		}
		timeline = append(timeline, bucket)
	}
	return timeline
}

func latestDenials(events []Event, limit int) []Event {
	denials := make([]Event, 0, limit)
	for _, event := range events {
		if event.Decision == DecisionDeny {
			denials = append(denials, event)
		}
	}
	SortEvents(denials)
	if len(denials) > limit {
		denials = denials[:limit]
	}
	if len(denials) == 0 {
		return nil
	}
	return denials
}

// BuildTrace joins the spans and audit decisions of one distributed flow.
// This is the "trace flows across all components" view: the W3C trace id is
// the only identifier every component already shares (docs/flow.md §3).
func BuildTrace(traceID string, spans []Span, events []Event) *Trace {
	trace := &Trace{TraceID: traceID, Spans: spans, Events: events}
	services := map[string]struct{}{}

	var started, ended time.Time
	for _, span := range spans {
		services[span.Service] = struct{}{}
		if started.IsZero() || span.Start.Before(started) {
			started = span.Start
		}
		if span.End.After(ended) {
			ended = span.End
		}
	}
	for _, event := range events {
		services[event.Service] = struct{}{}
		if started.IsZero() || event.OccurredAt.Before(started) {
			started = event.OccurredAt
		}
		if event.OccurredAt.After(ended) {
			ended = event.OccurredAt
		}
		if event.IsDenial() {
			trace.Denied++
		}
	}

	sort.SliceStable(trace.Spans, func(i, j int) bool { return trace.Spans[i].Start.Before(trace.Spans[j].Start) })
	SortEvents(trace.Events)
	trace.SpanCount = len(trace.Spans)
	trace.EventCount = len(trace.Events)
	trace.StartedAt = started
	if !started.IsZero() && !ended.IsZero() && ended.After(started) {
		trace.DurationMS = ended.Sub(started).Milliseconds()
	}
	trace.Services = make([]string, 0, len(services))
	for service := range services {
		trace.Services = append(trace.Services, service)
	}
	sort.Strings(trace.Services)
	return trace
}
