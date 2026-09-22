// Package audit emits the security decisions this service makes, in the field
// vocabulary Person 6's pipeline classifies (see
// telemetry/docs/integration.md §2 and §3 "Person 5").
//
// The integration rule for this project is that a component is audited by
// existing: the collector follows container stdout over the Docker API, so one
// structured JSON line per decision is the whole integration. There is no
// library to install and no endpoint to reach, which also means the audit
// channel cannot fail a transfer — an audit line that cannot be written is not
// worth refusing a payment over (and the same line is still in Loki).
//
// Two properties matter more than the rest:
//
//  1. One record per decision, not per request. A `http_request` line is
//     access evidence; an `access_decision` line with the OPA input and result
//     is the authorization evidence. Both are emitted; they are classified
//     into different categories (ACCESS and AUTHZ).
//  2. The verdict field (`decision`) is always present and always one of
//     PERMIT / DENY / ERROR. A record with no recognisable verdict is dropped
//     by the pipeline as noise, so a decision that is not labelled is a
//     decision that never reaches the dashboard.
package audit

import (
	"context"
	"log/slog"
	"time"
)

// Verdicts. The audit store's columns are constrained to exactly these values
// (telemetry/migrations/001_init.up.sql), so emitting anything else would be
// rejected at ingest.
const (
	VerdictPermit = "PERMIT"
	VerdictDeny   = "DENY"
	VerdictError  = "ERROR"
	VerdictInfo   = "INFO"
)

// Event names the pipeline recognises by name (no extra fields needed for
// classification). Inventing a name is allowed only when it ends in an
// unambiguous outcome word (`..._rejected`, `..._denied`), so the names below
// stick to the documented vocabulary.
const (
	// EventHTTPRequest is the per-request access line. Classified ACCESS and
	// graded from the status code.
	EventHTTPRequest = "http_request"
	// EventAccessDecision is the authorization verdict — what the policy engine
	// was asked and what it answered. Classified AUTHZ.
	EventAccessDecision = "access_decision"
	// EventRequestBlocked is a request this service refused before any
	// authorization question was asked (bad token, malformed body, wrong
	// sender, missing client certificate).
	EventRequestBlocked = "request_blocked"
	// EventTokenRejected is a failed JWT verification. Classified AUTH / DENY.
	EventTokenRejected = "token_rejected"
	// EventMTLSRejected is a refused TLS handshake: a client presented no
	// certificate, or one that does not chain to the shared CA. It never
	// reaches a handler, so the listener emits it.
	EventMTLSRejected = "mtls_handshake_rejected"
	// EventUpstreamError is a failure of a dependency this service called
	// (account service unreachable, ledger write failed).
	EventUpstreamError = "upstream_error"
	// EventVerificationUnavailable is a guard that could not render a verdict:
	// the JWKS endpoint or the policy engine could not be reached.
	EventVerificationUnavailable = "verification_unavailable"
	// EventTransferCommitted is the business outcome. It ends in no outcome
	// word, so it always carries an explicit verdict.
	EventTransferCommitted = "transfer_committed"
)

// Reasons. These are what the dashboard's "denials by reason" panel groups on,
// so each one names a distinct, actionable failure rather than "denied".
const (
	ReasonAllowed         = "allowed"
	ReasonPolicyDenied    = "policy_denied"
	ReasonPolicyDown      = "policy_engine_unavailable"
	ReasonTokenExpired    = "token_expired"
	ReasonTokenInvalid    = "token_invalid"
	ReasonTokenMissing    = "token_missing"
	ReasonJWKSUnavailable = "jwks_unavailable"
	ReasonMTLSRequired    = "mtls_required"
	ReasonMTLSIdentity    = "mtls_identity_denied"
	ReasonInvalidAmount   = "invalid_amount"
	ReasonInvalidSender   = "invalid_sender"
	ReasonInvalidReceiver = "invalid_receiver"
	ReasonInvalidBody     = "invalid_request_body"
	ReasonSenderMismatch  = "sender_mismatch"
	ReasonSelfTransfer    = "self_transfer_refused"
	ReasonDeductDenied    = "deduction_denied"
	ReasonDeductUnavail   = "account_service_unavailable"
	ReasonLedgerFailed    = "ledger_write_failed"
)

// Recorder writes decision records to stdout.
type Recorder struct {
	logger  *slog.Logger
	service string
}

// New builds a Recorder. The service name is the label the dashboard groups
// by, so it must be the component's own name ("payment-service"), not the
// container's.
func New(logger *slog.Logger, service string) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{logger: logger, service: service}
}

// Record is one security record.
type Record struct {
	// Event is the `msg` field: the event type the pipeline keys on.
	Event string
	// Verdict is PERMIT / DENY / ERROR / INFO. Always set by the helpers.
	Verdict string
	// Reason is a short machine-readable label (audit.Reason*).
	Reason string

	// Who and what.
	UserID   string
	Roles    []string
	Action   string
	Resource string

	// Request shape, for ACCESS classification.
	Method     string
	Path       string
	Status     int
	RemoteAddr string

	// Trace context: the join key for the distributed flow (docs/flow.md §3).
	TraceParent string
	SpanID      string
	RequestID   string
	Duration    time.Duration

	// Envelope, kept for forensics. For an authorization decision this is the
	// exact OPA input and result: the pipeline promotes subject, roles and
	// client address out of the nested envelope, which is why it is passed as
	// the structured object rather than a flattened string.
	Input  any
	Result any

	// Detail is free-form evidence (upstream status, error text). It is logged
	// as its own group so it cannot collide with the classified fields.
	Detail map[string]any
}

// Log writes the record as a single structured JSON line.
func (r *Recorder) Log(ctx context.Context, rec Record) {
	attrs := make([]slog.Attr, 0, 20)

	// Order matters for a human reading the trail: what happened, what was
	// decided, why.
	attrs = append(attrs, slog.String("service", r.service))
	if rec.Verdict != "" {
		attrs = append(attrs, slog.String("decision", rec.Verdict))
	}
	if rec.Reason != "" {
		attrs = append(attrs, slog.String("reason", rec.Reason))
	}
	if rec.UserID != "" {
		attrs = append(attrs, slog.String("user_id", rec.UserID))
	}
	if len(rec.Roles) > 0 {
		attrs = append(attrs, slog.Any("roles", rec.Roles))
	}
	if rec.Action != "" {
		attrs = append(attrs, slog.String("action", rec.Action))
	}
	if rec.Resource != "" {
		attrs = append(attrs, slog.String("resource", rec.Resource))
	}
	if rec.Method != "" {
		attrs = append(attrs, slog.String("method", rec.Method))
	}
	if rec.Path != "" {
		attrs = append(attrs, slog.String("path", rec.Path))
	}
	if rec.Status != 0 {
		attrs = append(attrs, slog.Int("status", rec.Status))
	}
	if rec.RemoteAddr != "" {
		attrs = append(attrs, slog.String("remote_addr", rec.RemoteAddr))
	}
	if rec.TraceParent != "" {
		attrs = append(attrs, slog.String("traceparent", rec.TraceParent))
	}
	if rec.SpanID != "" {
		attrs = append(attrs, slog.String("span_id", rec.SpanID))
	}
	if rec.RequestID != "" {
		attrs = append(attrs, slog.String("request_id", rec.RequestID))
	}
	if rec.Duration > 0 {
		attrs = append(attrs, slog.Int64("duration_ms", rec.Duration.Milliseconds()))
	}
	if rec.Input != nil {
		attrs = append(attrs, slog.Any("input", rec.Input))
	}
	if rec.Result != nil {
		attrs = append(attrs, slog.Any("result", rec.Result))
	}
	if len(rec.Detail) > 0 {
		detail := make([]slog.Attr, 0, len(rec.Detail))
		for key, value := range rec.Detail {
			detail = append(detail, slog.Any(key, value))
		}
		attrs = append(attrs, slog.Attr{Key: "detail", Value: slog.GroupValue(detail...)})
	}

	level := levelFor(rec.Verdict)
	// The message is the event type. log/slog's JSON handler also emits `time`
	// (always UTC) and `level`, which is the rest of the required vocabulary.
	r.logger.LogAttrs(ctx, level, rec.Event, attrs...)
}

// levelFor keeps the console usable: refusals are what an operator greps for,
// successes are not.
func levelFor(verdict string) slog.Level {
	switch verdict {
	case VerdictDeny:
		return slog.LevelWarn
	case VerdictError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Outcome is the authorization verdict of one policy evaluation, in the shape
// the Policy Engine contract uses, so it can be logged verbatim as `result`.
type Outcome struct {
	Allow bool `json:"allow"`
}
