// Package audit defines the security event model that the telemetry pipeline
// is built around.
//
// Person 6's job (docs/division.md) is to be the place every component's
// decision lands: the IdP's login outcomes, the API Gateway's PERMIT/DENY
// access decisions, the Policy Engine's authorisation verdicts, and the
// microservices' policy re-checks. Those components already emit structured
// JSON logs and OpenTelemetry spans (docs/flow.md §6), so this package's job
// is to classify and normalise what they emit rather than to invent a new
// format they would have to adopt.
package audit

import "time"

// Category says what kind of security question an event answers.
type Category string

const (
	// CategoryAuth is authentication: who are you? (login, token issuance)
	CategoryAuth Category = "AUTH"
	// CategoryAuthz is authorisation: may you do this? (policy decisions)
	CategoryAuthz Category = "AUTHZ"
	// CategoryAccess is request admission at the perimeter.
	CategoryAccess Category = "ACCESS"
	// CategoryRateLimit is perimeter throttling.
	CategoryRateLimit Category = "RATE_LIMIT"
	// CategoryError is an operational failure worth auditing.
	CategoryError Category = "ERROR"
	// CategoryLog is an explicitly submitted, non-security log record.
	CategoryLog Category = "LOG"
)

// Decision is the verdict the audit trail exists to record.
type Decision string

const (
	DecisionPermit Decision = "PERMIT"
	DecisionDeny   Decision = "DENY"
	DecisionError  Decision = "ERROR"
	// DecisionInfo is used for events that carry no verdict (health checks,
	// startup, trace-only records).
	DecisionInfo Decision = "INFO"
)

// Event is one security-relevant record, normalised from whatever shape the
// emitting component produced.
type Event struct {
	// ID is stable for the same underlying record, which makes re-ingestion
	// (container restart, collector retry) idempotent.
	ID          string    `json:"event_id"`
	OccurredAt  time.Time `json:"occurred_at"`
	Category    Category  `json:"category"`
	Decision    Decision  `json:"decision"`
	Reason      string    `json:"reason,omitempty"`
	Service     string    `json:"service"`
	EventType   string    `json:"event_type"`
	Subject     string    `json:"subject,omitempty"`
	Roles       []string  `json:"roles,omitempty"`
	Method      string    `json:"method,omitempty"`
	Path        string    `json:"path,omitempty"`
	Status      int       `json:"status,omitempty"`
	RemoteAddr  string    `json:"remote_addr,omitempty"`
	TraceID     string    `json:"trace_id,omitempty"`
	SpanID      string    `json:"span_id,omitempty"`
	RequestID   string    `json:"request_id,omitempty"`
	DurationMS  int64     `json:"duration_ms,omitempty"`
	Message     string    `json:"message,omitempty"`
	Action      string    `json:"action,omitempty"`
	Resource    string    `json:"resource,omitempty"`
	IngestedVia string    `json:"ingested_via,omitempty"`
	// Raw is the original payload, kept for forensics. It is truncated when a
	// producer sends something unexpectedly large.
	Raw map[string]any `json:"raw,omitempty"`
}

// IsDenial reports whether the event blocked something.
func (e Event) IsDenial() bool { return e.Decision == DecisionDeny }

// Span is one OpenTelemetry span, flattened from the OTLP wire format.
type Span struct {
	TraceID      string            `json:"trace_id"`
	SpanID       string            `json:"span_id"`
	ParentSpanID string            `json:"parent_span_id,omitempty"`
	Service      string            `json:"service"`
	Name         string            `json:"name"`
	Start        time.Time         `json:"start"`
	End          time.Time         `json:"end"`
	DurationNS   int64             `json:"duration_ns"`
	Status       string            `json:"status"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

// DurationMS is the span's wall-clock duration in milliseconds.
func (s Span) DurationMS() int64 { return s.DurationNS / int64(time.Millisecond) }

// Trace is the joined view of one distributed flow: the spans the services
// reported plus the audit decisions taken during them, both keyed by the W3C
// trace id that flows through every component.
type Trace struct {
	TraceID    string    `json:"trace_id"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	SpanCount  int       `json:"span_count"`
	EventCount int       `json:"event_count"`
	Services   []string  `json:"services"`
	Denied     int       `json:"denied"`
	Spans      []Span    `json:"spans"`
	Events     []Event   `json:"events"`
}

// Filter selects events for the read API. Zero values mean "no restriction".
type Filter struct {
	Decision string
	Category string
	Service  string
	Reason   string
	Subject  string
	TraceID  string
	// Search matches loosely against path, message, subject and reason.
	Search string
	Since  time.Time
	Until  time.Time
	Limit  int
	Offset int
}

// Count is one labelled tally.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Bucket is one interval of the activity timeline.
type Bucket struct {
	Start   time.Time `json:"start"`
	Total   int       `json:"total"`
	Permit  int       `json:"permit"`
	Deny    int       `json:"deny"`
	Errored int       `json:"error"`
}

// Summary is what the audit dashboard puts on screen: the numbers that answer
// "is something going wrong right now?".
type Summary struct {
	Since   time.Time     `json:"since"`
	Until   time.Time     `json:"until"`
	Window  time.Duration `json:"window"`
	Total   int           `json:"total"`
	Permits int           `json:"permits"`
	Denials int           `json:"denials"`
	Errors  int           `json:"errors"`
	Info    int           `json:"info"`
	// DenialRate is denials as a fraction of all decisions (0..1).
	DenialRate float64 `json:"denial_rate"`
	// UnauthorizedAttempts counts rejected credentials and policy denials —
	// the "unauthorized access attempts" the deliverable asks for. Rate
	// limiting is counted separately so throttling noise cannot mask an attack.
	UnauthorizedAttempts int `json:"unauthorized_attempts"`
	// RateLimited counts requests shed by perimeter throttling.
	RateLimited int `json:"rate_limited"`
	// ActiveServices is how many components reported in this window.
	ActiveServices int `json:"active_services"`
	TraceCount     int `json:"trace_count"`
	SpanCount      int `json:"span_count"`

	ByReason      []Count  `json:"by_reason"`
	ByService     []Count  `json:"by_service"`
	ByCategory    []Count  `json:"by_category"`
	ByDecision    []Count  `json:"by_decision"`
	TopSubjects   []Count  `json:"top_subjects"`
	TopClients    []Count  `json:"top_clients"`
	Timeline      []Bucket `json:"timeline"`
	LatestDenials []Event  `json:"latest_denials"`
}
