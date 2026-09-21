package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"telemetry/internal/audit"
)

// Postgres is the durable audit store. Telemetry owns these two tables
// (Database-per-Service, docs/database.md §2); no other service reads or
// writes them, and it never reaches into anyone else's schema.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres wraps a connection pool.
func NewPostgres(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

var _ Store = (*Postgres)(nil)

const eventColumns = `event_id, occurred_at, category, decision, reason, service, event_type,
	subject, roles, method, path, status, remote_addr, trace_id, span_id, request_id,
	duration_ms, message, action, resource, ingested_via, raw`

const insertEventSQL = `INSERT INTO audit_events (` + eventColumns + `)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
ON CONFLICT (event_id) DO NOTHING`

const insertSpanSQL = `INSERT INTO spans
	(trace_id, span_id, parent_span_id, service, name, started_at, ended_at, duration_ns, status, attributes)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (trace_id, span_id) DO NOTHING`

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// InsertEvents writes a batch, ignoring rows already stored.
func (p *Postgres) InsertEvents(ctx context.Context, events []audit.Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	batch := &pgx.Batch{}
	for _, event := range events {
		batch.Queue(insertEventSQL, eventArgs(event)...)
	}
	return p.execBatch(ctx, batch, len(events), "audit event")
}

// InsertSpans writes a batch of spans, ignoring duplicates.
func (p *Postgres) InsertSpans(ctx context.Context, spans []audit.Span) (int, error) {
	if len(spans) == 0 {
		return 0, nil
	}
	batch := &pgx.Batch{}
	for _, span := range spans {
		attributes, err := json.Marshal(span.Attributes)
		if err != nil {
			attributes = []byte("{}")
		}
		batch.Queue(insertSpanSQL,
			span.TraceID, span.SpanID, span.ParentSpanID, span.Service, span.Name,
			span.Start, nullTime(span.End), span.DurationNS, span.Status, attributes)
	}
	return p.execBatch(ctx, batch, len(spans), "span")
}

func (p *Postgres) execBatch(ctx context.Context, batch *pgx.Batch, count int, what string) (int, error) {
	results := p.pool.SendBatch(ctx, batch)
	defer results.Close()

	inserted := 0
	for i := 0; i < count; i++ {
		tag, err := results.Exec()
		if err != nil {
			return inserted, fmt.Errorf("store: insert %s: %w", what, err)
		}
		inserted += int(tag.RowsAffected())
	}
	return inserted, nil
}

func eventArgs(event audit.Event) []any {
	if event.ID == "" {
		event.ID = event.Fingerprint()
	}
	raw := []byte("{}")
	if len(event.Raw) > 0 {
		if encoded, err := json.Marshal(event.Raw); err == nil {
			raw = encoded
		}
	}
	roles := event.Roles
	if roles == nil {
		roles = []string{}
	}
	return []any{
		event.ID, event.OccurredAt, string(event.Category), string(event.Decision),
		event.Reason, event.Service, event.EventType, event.Subject, roles,
		event.Method, event.Path, event.Status, event.RemoteAddr, event.TraceID,
		event.SpanID, event.RequestID, event.DurationMS, event.Message, event.Action,
		event.Resource, event.IngestedVia, raw,
	}
}

// QueryEvents returns matching events, newest first.
func (p *Postgres) QueryEvents(ctx context.Context, filter audit.Filter) ([]audit.Event, error) {
	args := []any{}
	clauses := []string{}
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}

	if filter.Decision != "" {
		add("decision = $%d", strings.ToUpper(filter.Decision))
	}
	if filter.Category != "" {
		add("category = $%d", strings.ToUpper(filter.Category))
	}
	if filter.Service != "" {
		add("service = $%d", filter.Service)
	}
	if filter.Reason != "" {
		add("reason = $%d", filter.Reason)
	}
	if filter.Subject != "" {
		add("subject = $%d", filter.Subject)
	}
	if filter.TraceID != "" {
		add("trace_id = $%d", strings.ToLower(filter.TraceID))
	}
	if !filter.Since.IsZero() {
		add("occurred_at >= $%d", filter.Since)
	}
	if !filter.Until.IsZero() {
		add("occurred_at <= $%d", filter.Until)
	}
	if filter.Search != "" {
		// The ESCAPE clause has to appear after every pattern, or PostgreSQL
		// treats the backslashes written by likePattern as literal characters.
		add(`(path ILIKE $%[1]d ESCAPE '\' OR message ILIKE $%[1]d ESCAPE '\'`+
			` OR subject ILIKE $%[1]d ESCAPE '\' OR reason ILIKE $%[1]d ESCAPE '\'`+
			` OR service ILIKE $%[1]d ESCAPE '\' OR event_type ILIKE $%[1]d ESCAPE '\')`,
			likePattern(filter.Search))
	}

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, clampLimit(filter.Limit), offset)

	query := "SELECT " + eventColumns + " FROM audit_events"
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY occurred_at DESC, event_id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query audit events: %w", err)
	}
	defer rows.Close()

	events := []audit.Event{}
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan audit event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// Summary aggregates the audit window that starts at since.
func (p *Postgres) Summary(ctx context.Context, since, now time.Time) (*audit.Summary, error) {
	summary := &audit.Summary{Since: since, Until: now, Window: now.Sub(since)}
	size := audit.BucketSize(summary.Window)

	// Scalar aggregates in one pass; FILTER keeps it to a single table scan
	// instead of a dozen round trips on every dashboard refresh.
	err := p.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE decision = 'PERMIT'),
			COUNT(*) FILTER (WHERE decision = 'DENY'),
			COUNT(*) FILTER (WHERE decision = 'ERROR'),
			COUNT(*) FILTER (WHERE decision = 'INFO'),
			COUNT(*) FILTER (WHERE decision = 'DENY' AND reason <> 'rate_limited'
				AND category <> 'RATE_LIMIT' AND (category IN ('AUTH','AUTHZ') OR status IN (401,403))),
			COUNT(*) FILTER (WHERE category = 'RATE_LIMIT' OR reason = 'rate_limited'),
			COUNT(DISTINCT service),
			COUNT(DISTINCT trace_id) FILTER (WHERE trace_id <> '')
		FROM audit_events
		WHERE occurred_at >= $1 AND occurred_at <= $2`, since, now).Scan(
		&summary.Total, &summary.Permits, &summary.Denials, &summary.Errors, &summary.Info,
		&summary.UnauthorizedAttempts, &summary.RateLimited, &summary.ActiveServices, &summary.TraceCount,
	)
	if err != nil {
		return nil, fmt.Errorf("store: summary totals: %w", err)
	}

	if decisions := summary.Permits + summary.Denials + summary.Errors; decisions > 0 {
		summary.DenialRate = float64(summary.Denials) / float64(decisions)
	}

	panels := []struct {
		target *[]audit.Count
		query  string
	}{
		{&summary.ByReason,
			`SELECT reason, COUNT(*) FROM audit_events
			 WHERE occurred_at >= $1 AND occurred_at <= $2 AND decision = 'DENY'
			 GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 10`},
		{&summary.ByService,
			`SELECT service, COUNT(*) FROM audit_events
			 WHERE occurred_at >= $1 AND occurred_at <= $2
			 GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 10`},
		{&summary.ByCategory,
			`SELECT category, COUNT(*) FROM audit_events
			 WHERE occurred_at >= $1 AND occurred_at <= $2
			 GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 10`},
		{&summary.ByDecision,
			`SELECT decision, COUNT(*) FROM audit_events
			 WHERE occurred_at >= $1 AND occurred_at <= $2
			 GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 10`},
		{&summary.TopSubjects,
			`SELECT subject, COUNT(*) FROM audit_events
			 WHERE occurred_at >= $1 AND occurred_at <= $2 AND decision = 'DENY' AND subject <> ''
			 GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 5`},
		{&summary.TopClients,
			`SELECT remote_addr, COUNT(*) FROM audit_events
			 WHERE occurred_at >= $1 AND occurred_at <= $2 AND decision = 'DENY' AND remote_addr <> ''
			 GROUP BY 1 ORDER BY 2 DESC, 1 ASC LIMIT 5`},
	}
	for _, panel := range panels {
		counts, err := p.counts(ctx, panel.query, since, now)
		if err != nil {
			return nil, err
		}
		*panel.target = counts
	}

	if summary.Timeline, err = p.timeline(ctx, since, now, size); err != nil {
		return nil, err
	}
	if summary.LatestDenials, err = p.queryEventsLimited(ctx, since, now); err != nil {
		return nil, err
	}
	if err := p.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM spans WHERE started_at >= $1 AND started_at <= $2`, since, now,
	).Scan(&summary.SpanCount); err != nil {
		return nil, fmt.Errorf("store: span count: %w", err)
	}
	return summary, nil
}

func (p *Postgres) counts(ctx context.Context, query string, args ...any) ([]audit.Count, error) {
	rows, err := p.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: summary panel: %w", err)
	}
	defer rows.Close()

	counts := []audit.Count{}
	for rows.Next() {
		var count audit.Count
		if err := rows.Scan(&count.Key, &count.Count); err != nil {
			return nil, fmt.Errorf("store: scan summary panel: %w", err)
		}
		counts = append(counts, count)
	}
	return counts, rows.Err()
}

// timeline buckets counts in SQL, epoch-aligned so the buckets line up with
// the in-process implementation.
func (p *Postgres) timeline(ctx context.Context, since, now time.Time, size time.Duration) ([]audit.Bucket, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT to_timestamp(floor(extract(epoch FROM occurred_at) / $3) * $3) AS bucket,
		       decision, COUNT(*)
		FROM audit_events
		WHERE occurred_at >= $1 AND occurred_at <= $2
		GROUP BY 1, 2
		ORDER BY 1`, since, now, size.Seconds())
	if err != nil {
		return nil, fmt.Errorf("store: summary timeline: %w", err)
	}
	defer rows.Close()

	sparse := map[int64]audit.Bucket{}
	for rows.Next() {
		var bucket time.Time
		var decision string
		var count int
		if err := rows.Scan(&bucket, &decision, &count); err != nil {
			return nil, fmt.Errorf("store: scan summary timeline: %w", err)
		}
		key := bucket.UTC().Unix()
		entry := sparse[key]
		entry.Start = time.Unix(key, 0).UTC()
		entry.Total += count
		switch audit.Decision(decision) {
		case audit.DecisionPermit:
			entry.Permit += count
		case audit.DecisionDeny:
			entry.Deny += count
		case audit.DecisionError:
			entry.Errored += count
		}
		sparse[key] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return audit.FillTimeline(sparse, since, now, size), nil
}

func (p *Postgres) queryEventsLimited(ctx context.Context, since, now time.Time) ([]audit.Event, error) {
	rows, err := p.pool.Query(ctx,
		"SELECT "+eventColumns+" FROM audit_events WHERE occurred_at >= $1 AND occurred_at <= $2"+
			" AND decision = 'DENY' ORDER BY occurred_at DESC, event_id DESC LIMIT 10", since, now)
	if err != nil {
		return nil, fmt.Errorf("store: latest denials: %w", err)
	}
	defer rows.Close()

	events := []audit.Event{}
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan latest denial: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// Trace assembles one distributed flow from spans plus audit decisions.
func (p *Postgres) Trace(ctx context.Context, traceID string) (*audit.Trace, error) {
	spans, err := p.traceSpans(ctx, traceID)
	if err != nil {
		return nil, err
	}
	events, err := p.traceEvents(ctx, traceID)
	if err != nil {
		return nil, err
	}
	if len(spans) == 0 && len(events) == 0 {
		return nil, nil
	}
	return audit.BuildTrace(traceID, spans, events), nil
}

func (p *Postgres) traceSpans(ctx context.Context, traceID string) ([]audit.Span, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT trace_id, span_id, parent_span_id, service, name, started_at, ended_at,
		       duration_ns, status, attributes
		FROM spans WHERE trace_id = $1 ORDER BY started_at`, traceID)
	if err != nil {
		return nil, fmt.Errorf("store: trace spans: %w", err)
	}
	defer rows.Close()

	spans := []audit.Span{}
	for rows.Next() {
		var span audit.Span
		var attributes []byte
		// ended_at is nullable: a span that arrives before it finishes (a
		// process killed mid-request, a streaming collector) is stored with
		// NULL. Scanning it straight into a time.Time fails the whole trace
		// lookup, so the pointer is what makes an in-flight span survivable.
		var endedAt *time.Time
		if err := rows.Scan(&span.TraceID, &span.SpanID, &span.ParentSpanID, &span.Service,
			&span.Name, &span.Start, &endedAt, &span.DurationNS, &span.Status, &attributes); err != nil {
			return nil, fmt.Errorf("store: scan span: %w", err)
		}
		if endedAt != nil {
			span.End = *endedAt
		}
		if len(attributes) > 0 {
			_ = json.Unmarshal(attributes, &span.Attributes)
		}
		spans = append(spans, span)
	}
	return spans, rows.Err()
}

func (p *Postgres) traceEvents(ctx context.Context, traceID string) ([]audit.Event, error) {
	rows, err := p.pool.Query(ctx,
		"SELECT "+eventColumns+" FROM audit_events WHERE trace_id = $1 ORDER BY occurred_at DESC", traceID)
	if err != nil {
		return nil, fmt.Errorf("store: trace events: %w", err)
	}
	defer rows.Close()

	events := []audit.Event{}
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan trace event: %w", err)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// Purge enforces the retention window on both tables.
func (p *Postgres) Purge(ctx context.Context, before time.Time) (Purged, error) {
	events, err := p.pool.Exec(ctx, `DELETE FROM audit_events WHERE occurred_at < $1`, before)
	if err != nil {
		return Purged{}, fmt.Errorf("store: purge audit events: %w", err)
	}
	spans, err := p.pool.Exec(ctx, `DELETE FROM spans WHERE started_at < $1`, before)
	if err != nil {
		// The events are already gone. Reporting the error by table says which
		// half succeeded, and the next sweep retries the other.
		return Purged{Events: int(events.RowsAffected())}, fmt.Errorf("store: purge spans: %w", err)
	}
	return Purged{Events: int(events.RowsAffected()), Spans: int(spans.RowsAffected())}, nil
}

// Ping reports whether the database is reachable.
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func scanEvent(row rowScanner) (audit.Event, error) {
	var event audit.Event
	var category, decision string
	var raw []byte

	if err := row.Scan(&event.ID, &event.OccurredAt, &category, &decision, &event.Reason,
		&event.Service, &event.EventType, &event.Subject, &event.Roles, &event.Method,
		&event.Path, &event.Status, &event.RemoteAddr, &event.TraceID, &event.SpanID,
		&event.RequestID, &event.DurationMS, &event.Message, &event.Action, &event.Resource,
		&event.IngestedVia, &raw); err != nil {
		return audit.Event{}, err
	}
	event.Category = audit.Category(category)
	event.Decision = audit.Decision(decision)
	if len(event.Roles) == 0 {
		event.Roles = nil
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &event.Raw)
	}
	return event, nil
}

// nullTime maps the zero time onto SQL NULL: a span collected mid-flight has
// no end yet, and storing year 1 would poison every duration calculation.
func nullTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

// likePattern escapes the wildcards a user might type so a search for "50%"
// searches for a literal percent sign rather than matching everything.
//
// The ESCAPE clause is on the query side (see the search clause in
// QueryEvents): without it, a backslash is an ordinary character in LIKE and
// the escaping here would make every search containing an underscore match
// nothing.
func likePattern(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + replacer.Replace(value) + "%"
}
