// Package payments is the transfer orchestration: the ordered sequence of
// checks and calls that stands between a request and a ledger row.
//
// The order is the security design, and it is deliberately the same order as
// docs/flow.md:
//
//	mTLS  (transport: is this a service inside the trust domain?)      — API layer
//	JWT   (identity: who is calling?)                                  — API layer
//	body  (syntax: is this a well-formed transfer?)                    — here
//	binding (authority: may this principal name this sender?)          — here
//	policy (authorization: does Person 3 allow this action, amount,
//	        resource and connection?)                                  — here
//	deduct (business: Person 4 debits the account)                     — here
//	ledger (this service records the immutable row)                    — here
//
// Nothing above the ledger writes anything, and every refusal returns before
// the next step runs. In particular no money moves before the policy engine has
// answered, and no ledger row is written unless the debit succeeded.
//
// The one irreducible gap is documented rather than hidden: the debit happens in
// another service's database, so if this service dies between "Person 4 said
// 200" and "the ledger row is committed", the debit exists with no ledger row.
// See decisions.md §"The distributed transaction gap" — it is the reason the
// ledger insert is the *last* step and why its failure is logged at ERROR with
// the exact evidence needed to reconcile.
package payments

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"paymentservice/internal/account"
	"paymentservice/internal/audit"
	"paymentservice/internal/config"
	"paymentservice/internal/ids"
	"paymentservice/internal/metrics"
	"paymentservice/internal/money"
	"paymentservice/internal/policy"
	"paymentservice/internal/store"
	"paymentservice/internal/tracecontext"
	"paymentservice/internal/tracing"
)

// Principal is the authenticated caller, taken from the verified token.
type Principal struct {
	UserID   string
	Roles    []string
	DeviceID string
}

// HasRole reports whether the principal carries a role, case-insensitively.
func (p Principal) HasRole(role string) bool {
	for _, held := range p.Roles {
		if equalFold(held, role) {
			return true
		}
	}
	return false
}

// Envelope is the per-request context a transfer is evaluated in.
type Envelope struct {
	// TraceParent is the W3C traceparent header for this request, carrying this
	// service's own span id (sent on outgoing calls so the flow nests
	// correctly).
	TraceParent string
	// Span is this service's span for the request. Child spans for the calls
	// this service makes hang off it, which is what turns a set of spans into a
	// trace tree.
	Span tracecontext.Trace
	// RemoteAddr is the client address this service observed.
	RemoteAddr string
	// RequestID correlates this service's logs with the Account Service's.
	RequestID string
	// Bearer is the original Authorization header value, forwarded to Person 4
	// so it re-authorizes the same principal (docs/flow.md §5).
	Bearer string
	// MTLSVerified is the *verified* state of this connection's client
	// certificate: it comes from the TLS handshake, never from a header.
	MTLSVerified bool
	// MTLSIdentity is the client certificate's service identity, when one was
	// verified. Recorded for attribution.
	MTLSIdentity string
}

// Transfer is a validated transfer request.
type Transfer struct {
	SenderID   string
	ReceiverID string
	Amount     money.Amount
}

// Failure is a refusal, with everything the API layer needs to answer and to
// explain itself. Returning it instead of an error keeps "the caller was
// refused" (4xx, DENY) and "something broke" (5xx, ERROR) distinguishable at
// the boundary — the audit trail's whole value depends on that distinction.
type Failure struct {
	// Status is the HTTP status code for the response.
	Status int
	// Code is the machine-readable error code in the response envelope.
	Code string
	// Message is the human-readable message in the response envelope. It never
	// contains upstream internals.
	Message string
	// Reason is the audit reason (audit.Reason*).
	Reason string
	// Detail is extra evidence for the audit record.
	Detail map[string]any
	// Err is the underlying cause, for the log line.
	Err error
}

func (f *Failure) Error() string {
	if f.Err != nil {
		return f.Message + ": " + f.Err.Error()
	}
	return f.Message
}

// Service orchestrates transfers.
type Service struct {
	cfg      *config.Config
	store    store.Store
	policy   *policy.Client
	accounts *account.Client
	audit    *audit.Recorder
	metrics  *metrics.Registry
	tracer   *tracing.Tracer
	logger   *slog.Logger
	now      func() time.Time
	newTxnID func() (string, error)
}

// Options configure a Service. Every collaborator is an interface-free
// concrete type except the store; the policy and account clients are concrete
// because their behaviour *is* the contract, and a test double for them would
// test the double.
type Options struct {
	Config   *config.Config
	Store    store.Store
	Policy   *policy.Client
	Accounts *account.Client
	Audit    *audit.Recorder
	Metrics  *metrics.Registry
	Tracer   *tracing.Tracer
	Logger   *slog.Logger

	// Now and NewTxnID are injectable for deterministic tests.
	Now      func() time.Time
	NewTxnID func() (string, error)
}

// New builds a Service.
func New(options Options) *Service {
	service := &Service{
		cfg:      options.Config,
		store:    options.Store,
		policy:   options.Policy,
		accounts: options.Accounts,
		audit:    options.Audit,
		metrics:  options.Metrics,
		tracer:   options.Tracer,
		logger:   options.Logger,
		now:      options.Now,
		newTxnID: options.NewTxnID,
	}
	if service.logger == nil {
		service.logger = slog.Default()
	}
	if service.now == nil {
		service.now = func() time.Time { return time.Now().UTC() }
	}
	if service.newTxnID == nil {
		service.newTxnID = ids.NewUUIDv4
	}
	return service
}

// Result is a recorded transfer.
type Result struct {
	Transaction store.Transaction
}

// Transfer runs the orchestration described in the package comment.
func (s *Service) Transfer(ctx context.Context, transfer Transfer, principal Principal, envelope Envelope) (*Result, *Failure) {
	// ---- syntax ---------------------------------------------------------

	if failure := s.validate(transfer, envelope); failure != nil {
		s.logRefusal(ctx, failure, principal, envelope)
		return nil, failure
	}

	// ---- authority: bind the token to the sender account ----------------

	if failure := s.checkSenderBinding(transfer, principal, envelope); failure != nil {
		s.logRefusal(ctx, failure, principal, envelope)
		return nil, failure
	}

	// ---- authorization: ask the Policy Engine ---------------------------

	resource := Resource(transfer.SenderID)
	input := policy.Request{Input: policy.Input{
		Subject:  policy.Subject{UserID: principal.UserID, Roles: principal.Roles},
		Action:   policy.ActionTransfer,
		Resource: resource,
		Context: policy.Context{
			Amount:       transfer.Amount,
			IPAddress:    envelope.RemoteAddr,
			MTLSVerified: envelope.MTLSVerified,
			ReceiverID:   transfer.ReceiverID,
			DeviceID:     principal.DeviceID,
			TraceParent:  envelope.TraceParent,
		},
	}}

	started := s.now()
	decision, err := s.policy.Authorize(ctx, input)
	s.recordPolicyDecision(ctx, input, decision, err, envelope, started)
	s.recordSpan(envelope, "policy.authorize", tracing.KindClient, started, s.now(), spanStatus(err == nil && decision.Allow), map[string]string{
		"policy.action":      input.Input.Action,
		"policy.resource":    input.Input.Resource,
		"policy.allow":       strconv.FormatBool(decision.Allow),
		"policy.reason":      decision.Reason,
		"policy.duration_ms": strconv.FormatInt(decision.Duration.Milliseconds(), 10),
	})
	if err != nil {
		// Fail closed, with the status the integration guidance asks for:
		// policy-engine/README.md §4 says "Return 403 Forbidden otherwise; fail
		// closed if the engine is down". The error code and the *audit*
		// category carry the distinction the status code cannot — the record is
		// an ERROR, not a DENY, so "we could not ask" never gets counted as "the
		// policy said no" on Person 6's dashboard.
		return nil, &Failure{
			Status:  statusForbidden,
			Code:    "policy_unavailable",
			Message: "the authorization service could not be reached; the transfer was not attempted",
			Reason:  audit.ReasonPolicyDown,
			Detail:  map[string]any{"engine_error": err.Error()},
			Err:     err,
		}
	}
	if !decision.Allow {
		return nil, &Failure{
			Status:  statusForbidden,
			Code:    "policy_denied",
			Message: "the authorization policy denied this transfer",
			Reason:  firstNonEmpty(decision.Reason, audit.ReasonPolicyDenied),
			Detail:  map[string]any{"engine_duration_ms": decision.Duration.Milliseconds()},
		}
	}

	// ---- business: let Person 4 move the money --------------------------

	deductStarted := s.now()
	deduction, deductErr := s.accounts.Deduct(ctx, account.Request{
		UserID: transfer.SenderID,
		Amount: transfer.Amount,
	}, account.Credentials{
		Bearer:      envelope.Bearer,
		TraceParent: envelope.TraceParent,
		RequestID:   envelope.RequestID,
	})
	s.recordSpan(envelope, "account.deduct", tracing.KindClient, deductStarted, s.now(),
		spanStatus(deductErr == nil && deduction.Succeeded()), map[string]string{
			"http.request.method":       "POST",
			"http.response.status_code": strconv.Itoa(deduction.StatusCode),
			"payment.amount":            transfer.Amount.String(),
			"payment.dependency":        "account-service",
		})

	if deductErr != nil {
		// No answer, or a 5xx: the deduction's outcome is unknown, and the
		// contract's answer for "Person 4 returned an error" is 400 Bad
		// Request. The audit reason and category carry the distinction the
		// status code cannot.
		s.audit.Log(ctx, audit.Record{
			Event:       audit.EventUpstreamError,
			Verdict:     audit.VerdictError,
			Reason:      audit.ReasonDeductUnavail,
			UserID:      principal.UserID,
			Roles:       principal.Roles,
			Action:      policy.ActionTransfer,
			Resource:    resource,
			TraceParent: envelope.TraceParent,
			RequestID:   envelope.RequestID,
			Detail: map[string]any{
				"dependency":      "account-service",
				"error":           deductErr.Error(),
				"upstream_status": deduction.StatusCode,
				"note":            "deduction outcome unknown; do not retry automatically",
			},
		})
		s.countUpstreamFailure("account-service", "unavailable")
		return nil, &Failure{
			Status:  statusBadRequest,
			Code:    "deduction_unavailable",
			Message: "the account service could not be reached; the transfer was not recorded",
			Reason:  audit.ReasonDeductUnavail,
			Err:     deductErr,
		}
	}

	if !deduction.Succeeded() {
		// An answer, and the answer was no (insufficient balance, or Person 4's
		// own policy check refused). Nothing was debited.
		//
		// The event is `request_blocked`, not `access_decision`: the AUTHZ
		// category is this service's own policy verdicts (which Person 6's
		// vocabulary documents as the `access_decision` line with the OPA input
		// and result), while this refusal is an upstream one. Classifying it as
		// ACCESS / DENY keeps "this service's authorization decision" separate
		// from "the Account Service would not debit".
		reason := audit.ReasonDeductDenied
		if deduction.RateLimited() {
			reason = "upstream_rate_limited"
		}
		s.audit.Log(ctx, audit.Record{
			Event:       audit.EventRequestBlocked,
			Verdict:     audit.VerdictDeny,
			Reason:      reason,
			UserID:      principal.UserID,
			Roles:       principal.Roles,
			Action:      policy.ActionTransfer,
			Resource:    resource,
			TraceParent: envelope.TraceParent,
			RequestID:   envelope.RequestID,
			Duration:    deduction.Duration,
			Detail: map[string]any{
				"dependency":      "account-service",
				"upstream_status": deduction.StatusCode,
				"upstream_body":   deduction.Snippet(),
			},
		})
		s.countUpstreamFailure("account-service", "denied")
		return nil, &Failure{
			Status:  statusBadRequest,
			Code:    "deduction_failed",
			Message: "the account service refused the deduction; the transfer was not recorded",
			Reason:  reason,
			Detail:  map[string]any{"upstream_status": deduction.StatusCode},
		}
	}

	// ---- ledger: record the transfer ------------------------------------

	txnID, err := s.newTxnID()
	if err != nil {
		return nil, s.ledgerFailure(ctx, transfer, principal, envelope, resource, nil, err)
	}

	ledgerStarted := s.now()
	recorded, err := s.store.RecordTransaction(ctx, store.Transaction{
		TxnID:      txnID,
		SenderID:   transfer.SenderID,
		ReceiverID: transfer.ReceiverID,
		Amount:     transfer.Amount,
	})
	s.recordSpan(envelope, "ledger.insert", tracing.KindClient, ledgerStarted, s.now(), spanStatus(err == nil), map[string]string{
		"payment.txn_id": txnID,
		"payment.amount": transfer.Amount.String(),
	})
	if err != nil {
		return nil, s.ledgerFailure(ctx, transfer, principal, envelope, resource, &txnID, err)
	}

	s.audit.Log(ctx, audit.Record{
		Event:       audit.EventTransferCommitted,
		Verdict:     audit.VerdictPermit,
		Reason:      audit.ReasonAllowed,
		UserID:      principal.UserID,
		Roles:       principal.Roles,
		Action:      policy.ActionTransfer,
		Resource:    resource,
		TraceParent: envelope.TraceParent,
		RequestID:   envelope.RequestID,
		Duration:    s.now().Sub(started),
		Detail: map[string]any{
			"txn_id":      recorded.TxnID,
			"receiver_id": recorded.ReceiverID,
			"amount":      recorded.Amount.String(),
		},
	})
	if s.metrics != nil {
		s.metrics.Inc(metrics.TransfersTotal, map[string]string{"outcome": "committed"})
		s.metrics.Inc(metrics.LedgerWritesTotal, nil)
	}
	return &Result{Transaction: recorded}, nil
}

// validate enforces the shape of a transfer before anything is asked of another
// service. Malformed input never reaches the policy engine's decision log or
// the Account Service's SQL.
func (s *Service) validate(transfer Transfer, envelope Envelope) *Failure {
	if err := ids.Validate("sender_id", transfer.SenderID); err != nil {
		return &Failure{
			Status: statusBadRequest, Code: "invalid_sender_id",
			Message: "sender_id must be a UUID", Reason: audit.ReasonInvalidSender, Err: err,
		}
	}
	if err := ids.Validate("receiver_id", transfer.ReceiverID); err != nil {
		return &Failure{
			Status: statusBadRequest, Code: "invalid_receiver_id",
			Message: "receiver_id must be a UUID", Reason: audit.ReasonInvalidReceiver, Err: err,
		}
	}
	if transfer.Amount.IsZero() {
		return &Failure{
			Status: statusBadRequest, Code: "invalid_amount",
			Message: "amount must be greater than zero", Reason: audit.ReasonInvalidAmount,
		}
	}
	if transfer.Amount.Cents() > s.cfg.MaxTransfer.Cents() {
		return &Failure{
			Status: statusBadRequest, Code: "amount_too_large",
			Message: fmt.Sprintf("amount must not exceed %s", s.cfg.MaxTransfer.String()),
			Reason:  audit.ReasonInvalidAmount,
			Detail:  map[string]any{"limit": s.cfg.MaxTransfer.String()},
		}
	}
	if equalFold(transfer.SenderID, transfer.ReceiverID) {
		// Not a policy question: a self-transfer moves no money, and its only
		// uses are ledger noise and probing for a race in the debit/credit
		// pair. Refused before the policy engine is asked.
		return &Failure{
			Status: statusBadRequest, Code: "self_transfer_refused",
			Message: "sender_id and receiver_id must differ", Reason: audit.ReasonSelfTransfer,
			Detail: map[string]any{"mtls_verified": envelope.MTLSVerified},
		}
	}
	return nil
}

// checkSenderBinding is the difference between "an authenticated user" and "the
// owner of the account being debited".
//
// Without it, any customer with a valid token could name any sender_id and
// debit an account that is not theirs — the policy engine's Rego rule cannot
// catch it either, because the rule is about the *action*, not about ownership
// of the named resource.
func (s *Service) checkSenderBinding(transfer Transfer, principal Principal, envelope Envelope) *Failure {
	if !s.cfg.EnforceSenderBinding {
		return nil
	}
	// An admin may act on behalf of a customer: the policy engine's baseline
	// grants admins an override, and this mirrors it.
	if principal.HasRole("admin") {
		return nil
	}
	if equalFold(principal.UserID, transfer.SenderID) {
		return nil
	}
	return &Failure{
		Status: statusForbidden, Code: "sender_mismatch",
		Message: "sender_id must be the authenticated user's own account",
		Reason:  audit.ReasonSenderMismatch,
		Detail: map[string]any{
			"authenticated_user": principal.UserID,
			"requested_sender":   transfer.SenderID,
		},
	}
}

// ledgerFailure handles the worst outcome this service can produce: the debit
// succeeded and the ledger row did not. It is logged at ERROR with the exact
// evidence needed to reconcile, and it is never swallowed.
func (s *Service) ledgerFailure(
	ctx context.Context,
	transfer Transfer,
	principal Principal,
	envelope Envelope,
	resource string,
	txnID *string,
	cause error,
) *Failure {
	detail := map[string]any{
		"dependency":  "ledger",
		"error":       cause.Error(),
		"sender_id":   transfer.SenderID,
		"receiver_id": transfer.ReceiverID,
		"amount":      transfer.Amount.String(),
		"request_id":  envelope.RequestID,
		"note": "the account was debited by the account service but no ledger row was written; " +
			"this transfer must be reconciled manually",
	}
	if txnID != nil {
		detail["txn_id"] = *txnID
	}
	s.audit.Log(ctx, audit.Record{
		Event:       audit.EventUpstreamError,
		Verdict:     audit.VerdictError,
		Reason:      audit.ReasonLedgerFailed,
		UserID:      principal.UserID,
		Roles:       principal.Roles,
		Action:      policy.ActionTransfer,
		Resource:    resource,
		TraceParent: envelope.TraceParent,
		RequestID:   envelope.RequestID,
		Detail:      detail,
	})
	s.logger.Error("transfer_ledger_write_failed",
		"error", cause,
		"reason", audit.ReasonLedgerFailed,
		"txn_id", detail["txn_id"],
		"sender_id", transfer.SenderID,
		"receiver_id", transfer.ReceiverID,
		"amount", transfer.Amount.String(),
		"request_id", envelope.RequestID,
	)
	if s.metrics != nil {
		s.metrics.Inc(metrics.TransfersTotal, map[string]string{"outcome": "ledger_failed"})
	}
	return &Failure{
		Status:  statusInternalServerError,
		Code:    "ledger_write_failed",
		Message: "the transfer could not be recorded and requires manual reconciliation",
		Reason:  audit.ReasonLedgerFailed,
		Err:     cause,
	}
}

// recordPolicyDecision writes the authorization evidence: the exact input the
// engine evaluated and the exact document it answered with.
//
// This is the line Person 6's pipeline reads for Person 5 (the nested envelope
// is promoted: subject, roles and client address become first-class columns),
// and it is the reason a denied transfer is explainable months later.
func (s *Service) recordPolicyDecision(
	ctx context.Context,
	input policy.Request,
	decision policy.Decision,
	err error,
	envelope Envelope,
	started time.Time,
) {
	record := audit.Record{
		Event:       audit.EventAccessDecision,
		Action:      input.Input.Action,
		Resource:    input.Input.Resource,
		UserID:      input.Input.Subject.UserID,
		Roles:       input.Input.Subject.Roles,
		TraceParent: envelope.TraceParent,
		RequestID:   envelope.RequestID,
		Input:       input.Input,
		Duration:    s.now().Sub(started),
	}
	if err != nil {
		// The engine could not be asked. Classified as an ERROR, not a denial:
		// "the guard was down" and "the caller was refused" are different
		// incidents, and conflating them hides an outage inside the deny rate.
		record.Event = audit.EventVerificationUnavailable
		record.Verdict = audit.VerdictError
		record.Reason = audit.ReasonPolicyDown
		record.Result = audit.Outcome{Allow: false}
		record.Detail = map[string]any{"engine_error": err.Error()}
		if s.metrics != nil {
			s.metrics.Inc(metrics.PolicyDecisionsTotal, map[string]string{"decision": "unavailable"})
		}
		s.audit.Log(ctx, record)
		return
	}

	record.Result = audit.Outcome{Allow: decision.Allow}
	record.Reason = audit.ReasonAllowed
	if !decision.Allow {
		record.Verdict = audit.VerdictDeny
		record.Reason = firstNonEmpty(decision.Reason, audit.ReasonPolicyDenied)
	} else {
		record.Verdict = audit.VerdictPermit
	}
	if s.metrics != nil {
		s.metrics.Inc(metrics.PolicyDecisionsTotal, map[string]string{"decision": strings.ToLower(record.Verdict)})
	}
	s.audit.Log(ctx, record)
}

// logRefusal records a transfer this service refused before asking anyone
// else. Nothing was evaluated by the policy engine and nothing was debited, so
// there is no authorization decision to log — but the refusal itself is a
// security event and belongs in the trail with its reason.
func (s *Service) logRefusal(ctx context.Context, failure *Failure, principal Principal, envelope Envelope) {
	s.audit.Log(ctx, audit.Record{
		Event:       audit.EventRequestBlocked,
		Verdict:     audit.VerdictDeny,
		Reason:      failure.Reason,
		UserID:      principal.UserID,
		Roles:       principal.Roles,
		Action:      policy.ActionTransfer,
		TraceParent: envelope.TraceParent,
		RequestID:   envelope.RequestID,
		Detail:      failure.Detail,
	})
	if s.metrics != nil {
		s.metrics.Inc(metrics.TransfersTotal, map[string]string{"outcome": "refused"})
	}
}

// recordSpan exports one child span of the current request. It is a no-op when
// span export is disabled, and it never affects the request: the exporter
// queues and returns.
func (s *Service) recordSpan(
	envelope Envelope,
	name string,
	kind int,
	start time.Time,
	end time.Time,
	status string,
	attributes map[string]string,
) {
	if s.tracer == nil || !s.tracer.Enabled() || envelope.Span.TraceID == "" {
		return
	}
	child := envelope.Span.Child()
	if child.SpanID == "" {
		return
	}
	s.tracer.Record(tracing.Span{
		TraceID:      child.TraceID,
		SpanID:       child.SpanID,
		ParentSpanID: envelope.Span.SpanID,
		Name:         name,
		Kind:         kind,
		Start:        start,
		End:          end,
		Status:       status,
		Attributes:   attributes,
	})
}

func spanStatus(ok bool) string {
	if ok {
		return tracing.StatusOK
	}
	return tracing.StatusError
}

func (s *Service) countUpstreamFailure(dependency, outcome string) {
	if s.metrics == nil {
		return
	}
	s.metrics.Inc(metrics.UpstreamFailuresTotal, map[string]string{"dependency": dependency, "outcome": outcome})
}

// Resource renders the policy resource identifier for an account, in the shape
// the contract's example uses ("account_987").
func Resource(accountID string) string { return "account_" + accountID }

// Status codes are named here so the API layer's mapping and the orchestration
// cannot drift apart.
const (
	statusBadRequest          = 400
	statusForbidden           = 403
	statusInternalServerError = 500
	statusServiceUnavailable  = 503
)

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := 0; index < len(a); index++ {
		ca, cb := a[index], b[index]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
