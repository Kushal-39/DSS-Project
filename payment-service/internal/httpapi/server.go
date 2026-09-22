// Package httpapi is the payment service's HTTP surface, using only the
// standard library net/http mux (Go 1.22 method+path routing — no framework,
// matching the IdP and telemetry services).
//
// Routes:
//
//	POST /api/v1/payments/transfer   the contract endpoint (docs/contacts.md)
//	GET  /healthz                    liveness
//	GET  /readyz                     readiness (ledger reachable + guard keyed)
//	GET  /metrics                    Prometheus text counters
//
// Every route is behind mutual TLS. The two guards are deliberately not the
// same check:
//
//	guardPeer      a client certificate that chains to the shared CA. Applies to
//	               everything, including the probes: "validate client
//	               certificates on every incoming connection" (docs/division.md,
//	               Person 5) has no exception for a health check.
//	guardBusiness  additionally requires the certificate's identity to be in
//	               the caller allowlist (gateway, account-service). A CA-signed
//	               certificate says the caller is inside the trust domain; only
//	               the allowlist says it is allowed to move money. The probe
//	               certificate therefore cannot call /transfer, and a compromised
//	               unrelated service cannot either.
//
// The two guards fail differently on purpose: a refused *credential* is a 403
// DENY, while a guard that cannot render a verdict (JWKS unreachable, policy
// engine down) is a 5xx ERROR. Collapsing those two into one status is how an
// outage hides inside a deny rate.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"paymentservice/internal/audit"
	"paymentservice/internal/config"
	"paymentservice/internal/jwtauth"
	"paymentservice/internal/metrics"
	"paymentservice/internal/money"
	"paymentservice/internal/mtls"
	"paymentservice/internal/payments"
	"paymentservice/internal/store"
	"paymentservice/internal/tracecontext"
	"paymentservice/internal/tracing"
)

// Paths. The transfer path is the contract; the probes are the platform's.
const (
	TransferPath = "/api/v1/payments/transfer"
	healthzPath  = "/healthz"
	readyzPath   = "/readyz"
	metricsPath  = "/metrics"
)

// Deps are the server's collaborators.
type Deps struct {
	Config   *config.Config
	Logger   *slog.Logger
	Verifier *jwtauth.Verifier
	Payments *payments.Service
	Store    store.Store
	Audit    *audit.Recorder
	Metrics  *metrics.Registry
	Tracer   *tracing.Tracer
	Now      func() time.Time
}

// Server wires the dependencies into an http.Handler.
type Server struct {
	cfg      *config.Config
	logger   *slog.Logger
	verifier *jwtauth.Verifier
	payments *payments.Service
	store    store.Store
	audit    *audit.Recorder
	metrics  *metrics.Registry
	tracer   *tracing.Tracer
	now      func() time.Time
}

// New builds the handler tree with middleware applied.
func New(deps Deps) http.Handler {
	server := &Server{
		cfg:      deps.Config,
		logger:   deps.Logger,
		verifier: deps.Verifier,
		payments: deps.Payments,
		store:    deps.Store,
		audit:    deps.Audit,
		metrics:  deps.Metrics,
		tracer:   deps.Tracer,
		now:      deps.Now,
	}
	if server.logger == nil {
		server.logger = slog.Default()
	}
	if server.now == nil {
		server.now = func() time.Time { return time.Now().UTC() }
	}

	mux := http.NewServeMux()
	mux.Handle("POST "+TransferPath, server.guardBusiness(http.HandlerFunc(server.handleTransfer)))
	mux.Handle("GET "+healthzPath, server.guardPeer(http.HandlerFunc(server.handleHealthz)))
	mux.Handle("GET "+readyzPath, server.guardPeer(http.HandlerFunc(server.handleReadyz)))
	mux.Handle("GET "+metricsPath, server.guardPeer(http.HandlerFunc(server.handleMetrics)))

	// Outermost first: a panic is contained (with the response already logged by
	// the observer, so the access line shows the 500 it produced), then response
	// headers, then tracing/logging, then routing.
	return server.recoverPanics(server.securityHeaders(server.observe(mux)))
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// An internal financial endpoint's responses are never cacheable.
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// recoverPanics converts a handler panic into a 500 rather than dropping the
// connection and leaking a stack trace to the caller.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("http_panic", "panic", recovered, "path", r.URL.Path)
				s.audit.Log(r.Context(), audit.Record{
					Event:   audit.EventUpstreamError,
					Verdict: audit.VerdictError,
					Reason:  "handler_panic",
					Path:    r.URL.Path,
					Method:  r.Method,
				})
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestState is the per-request context the observer establishes and the
// handlers read.
type requestState struct {
	// span is this service's own span for the request: same trace id as the
	// caller's, new span id, so everything this service emits nests under the
	// caller's span.
	span tracecontext.Trace
	// parentSpanID is the caller's span id, used as the exported span's parent.
	parentSpanID string
	requestID    string
	start        time.Time
	identity     string
	mtlsVerified bool
}

type stateKey struct{}

// observe establishes the trace context, then records the outcome of every
// request: one access line (ACCESS), one span, and the counters.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()

		incoming, parsed := tracecontext.Parse(r.Header.Get("traceparent"))
		span := tracecontext.New()
		parentSpanID := ""
		if parsed {
			span = incoming.Child()
			parentSpanID = incoming.SpanID
		}

		state := &requestState{
			span:         span,
			parentSpanID: parentSpanID,
			requestID:    span.SpanID,
			start:        start,
		}
		if peer, ok := mtls.PeerIdentity(r.TLS); ok {
			state.identity = peer.Identity
			state.mtlsVerified = peer.Verified
		}

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		// The trace context travels with the response so a caller can join its
		// own logs to this service's decisions.
		recorder.Header().Set("traceparent", span.Header())
		recorder.Header().Set("X-Request-ID", state.requestID)

		next.ServeHTTP(recorder, r.WithContext(context.WithValue(r.Context(), stateKey{}, state)))

		duration := s.now().Sub(start)
		route := routeLabel(r)
		remoteAddr := remoteHost(r.RemoteAddr)

		if s.metrics != nil {
			s.metrics.Inc(metrics.RequestsTotal, map[string]string{
				"route":  route,
				"method": r.Method,
				"status": metrics.StatusClass(recorder.status),
			})
		}

		s.audit.Log(r.Context(), audit.Record{
			Event:       audit.EventHTTPRequest,
			Method:      r.Method,
			Path:        r.URL.Path,
			Status:      recorder.status,
			RemoteAddr:  remoteAddr,
			TraceParent: span.Header(),
			SpanID:      span.SpanID,
			RequestID:   state.requestID,
			Duration:    duration,
			Detail: map[string]any{
				"mtls_identity": state.identity,
				"mtls_verified": state.mtlsVerified,
				"route":         route,
			},
		})

		if s.tracer != nil && s.tracer.Enabled() {
			status := tracing.StatusOK
			if recorder.status >= 500 {
				status = tracing.StatusError
			}
			s.tracer.Record(tracing.Span{
				TraceID:      span.TraceID,
				SpanID:       span.SpanID,
				ParentSpanID: parentSpanID,
				Name:         strings.TrimSpace(r.Method + " " + route),
				Kind:         tracing.KindServer,
				Start:        start,
				End:          s.now(),
				Status:       status,
				Attributes: map[string]string{
					"http.request.method":       r.Method,
					"url.path":                  r.URL.Path,
					"http.response.status_code": fmt.Sprint(recorder.status),
					"client.address":            remoteAddr,
					"mtls.identity":             state.identity,
					"mtls.verified":             fmt.Sprint(state.mtlsVerified),
					"service.name":              s.cfg.ServiceName,
				},
			})
		}
	})
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

// guardPeer requires a client certificate that chained to the shared CA on this
// connection.
func (s *Server) guardPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := mtls.PeerIdentity(r.TLS)
		if !ok || !peer.Verified {
			s.refusePeer(w, r, audit.ReasonMTLSRequired,
				"a client certificate signed by the shared CA is required on every connection")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// guardBusiness additionally requires an allowlisted client identity.
func (s *Server) guardBusiness(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := mtls.PeerIdentity(r.TLS)
		if !ok || !peer.Verified {
			s.refusePeer(w, r, audit.ReasonMTLSRequired,
				"a client certificate signed by the shared CA is required on every connection")
			return
		}
		if !peer.Allowed(s.cfg.AllowedClientIDs) {
			s.logger.Warn("mtls_identity_denied",
				"identity", peer.Identity,
				"serial", peer.SerialNumber,
				"allowed", s.cfg.AllowedClientIDs,
				"traceparent", r.Header.Get("traceparent"))
			s.audit.Log(r.Context(), audit.Record{
				Event:       audit.EventRequestBlocked,
				Verdict:     audit.VerdictDeny,
				Reason:      audit.ReasonMTLSIdentity,
				Method:      r.Method,
				Path:        r.URL.Path,
				RemoteAddr:  remoteHost(r.RemoteAddr),
				TraceParent: r.Header.Get("traceparent"),
				Detail: map[string]any{
					"mtls_identity": peer.Identity,
					"mtls_subject":  peer.Subject,
					"allowed":       s.cfg.AllowedClientIDs,
				},
			})
			writeError(w, http.StatusForbidden, "client_not_authorized",
				"this client certificate is not authorized to call the payment API")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) refusePeer(w http.ResponseWriter, r *http.Request, reason, message string) {
	s.audit.Log(r.Context(), audit.Record{
		Event:       audit.EventRequestBlocked,
		Verdict:     audit.VerdictDeny,
		Reason:      reason,
		Method:      r.Method,
		Path:        r.URL.Path,
		RemoteAddr:  remoteHost(r.RemoteAddr),
		TraceParent: r.Header.Get("traceparent"),
		Detail:      map[string]any{"tls": r.TLS != nil, "scheme": schemeOf(r)},
	})
	writeError(w, http.StatusForbidden, "mtls_required",
		"a client certificate signed by the shared CA is required on every connection")
}

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

// transferRequest is the contract body from docs/contacts.md. Unknown fields
// are rejected: a caller that misspells `sender_id` should be told so, not
// silently have it treated as empty.
//
// Amount is kept raw rather than decoded into a Go numeric type, because every
// numeric type has already made a decision this service must make itself:
// float64 loses cents, and encoding/json will happily accept the *quoted* form
// `"50.00"` into a json.Number — which the contract does not allow, and which
// would let a caller send an amount this service then has to interpret.
type transferRequest struct {
	SenderID   string          `json:"sender_id"`
	ReceiverID string          `json:"receiver_id"`
	Amount     json.RawMessage `json:"amount"`
}

// transferResponse is what a committed transfer returns.
//
// The status is 200 (not 201): the contract speaks in 200s everywhere it names
// a success, and the body already carries the new ledger row's identity, so the
// extra status code would be a surprise for the integration tests of Persons 2
// and 4 rather than an improvement.
type transferResponse struct {
	TxnID      string       `json:"txn_id"`
	SenderID   string       `json:"sender_id"`
	ReceiverID string       `json:"receiver_id"`
	Amount     money.Amount `json:"amount"`
	CreatedAt  string       `json:"created_at"`
}

func (s *Server) handleTransfer(w http.ResponseWriter, r *http.Request) {
	state := stateFrom(r.Context())

	// ---- identity --------------------------------------------------------
	//
	// The gateway verified this token before forwarding it (docs/flow.md §2).
	// This service verifies it again: the perimeter's word is not a substitute
	// for the callee's own check, and this is the boundary that actually
	// authorizes the debit.

	token, ok := bearerToken(r)
	if !ok {
		s.refuseTransfer(w, r, state, http.StatusUnauthorized, "token_missing",
			audit.ReasonTokenMissing, "an Authorization: Bearer <jwt> header is required")
		return
	}

	claims, err := s.verifier.Verify(r.Context(), token)
	switch {
	case err == nil:
	case errors.Is(err, jwtauth.ErrTokenExpired):
		s.refuseTransfer(w, r, state, http.StatusUnauthorized, "token_expired",
			audit.ReasonTokenExpired, "the bearer token has expired")
		return
	case errors.Is(err, jwtauth.ErrVerificationUnavailable):
		// The guard could not check the credential. Fail closed, and say so:
		// this is an ERROR, not a denial.
		s.audit.Log(r.Context(), audit.Record{
			Event:       audit.EventVerificationUnavailable,
			Verdict:     audit.VerdictError,
			Reason:      audit.ReasonJWKSUnavailable,
			Method:      r.Method,
			Path:        r.URL.Path,
			RemoteAddr:  remoteHost(r.RemoteAddr),
			TraceParent: state.span.Header(),
			SpanID:      state.span.SpanID,
			RequestID:   state.requestID,
			Detail:      map[string]any{"error": err.Error(), "jwks_url": s.cfg.JWKSURL},
		})
		writeError(w, http.StatusServiceUnavailable, "verification_unavailable",
			"the identity provider's keys could not be reached; the request was not authorized")
		return
	default:
		s.refuseTransfer(w, r, state, http.StatusUnauthorized, "token_invalid",
			audit.ReasonTokenInvalid, "the bearer token is not valid")
		return
	}

	// ---- syntax ----------------------------------------------------------

	transfer, failure := s.decodeTransfer(w, r, state)
	if failure != nil {
		s.refuseTransfer(w, r, state, failure.status, failure.code, failure.reason, failure.message)
		return
	}

	// ---- orchestration ---------------------------------------------------

	principal := payments.Principal{
		UserID:   claims.Subject,
		Roles:    claims.Roles,
		DeviceID: claims.DeviceID,
	}
	envelope := payments.Envelope{
		TraceParent:  state.span.Header(),
		Span:         state.span,
		RemoteAddr:   remoteHost(r.RemoteAddr),
		RequestID:    state.requestID,
		Bearer:       "Bearer " + token,
		MTLSVerified: true, // guardBusiness proved it on this connection
		MTLSIdentity: state.identity,
	}

	result, refusal := s.payments.Transfer(r.Context(), transfer, principal, envelope)
	if refusal != nil {
		writeError(w, refusal.Status, refusal.Code, refusal.Message)
		return
	}

	writeJSON(w, http.StatusOK, transferResponse{
		TxnID:      result.Transaction.TxnID,
		SenderID:   result.Transaction.SenderID,
		ReceiverID: result.Transaction.ReceiverID,
		Amount:     result.Transaction.Amount,
		CreatedAt:  result.Transaction.CreatedAt.UTC().Format(time.RFC3339),
	})
}

// refusal is a request rejected before the orchestration ran.
type refusal struct {
	status  int
	code    string
	reason  string
	message string
}

// decodeTransfer reads and validates the body. Malformed input is refused here
// so it never reaches the policy engine's decision log or the Account Service's
// SQL.
func (s *Server) decodeTransfer(w http.ResponseWriter, r *http.Request, state *requestState) (payments.Transfer, *refusal) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var request transferRequest
	if err := decoder.Decode(&request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return payments.Transfer{}, &refusal{
				status: http.StatusRequestEntityTooLarge, code: "request_too_large",
				reason:  audit.ReasonInvalidBody,
				message: fmt.Sprintf("the request body must not exceed %d bytes", tooLarge.Limit),
			}
		}
		return payments.Transfer{}, &refusal{
			status: http.StatusBadRequest, code: "invalid_request_body",
			reason:  audit.ReasonInvalidBody,
			message: "the body must be JSON with exactly sender_id, receiver_id and amount",
		}
	}
	// Reject trailing content: two JSON documents in one request means the
	// caller and this service disagree about what was sent.
	if decoder.More() {
		return payments.Transfer{}, &refusal{
			status: http.StatusBadRequest, code: "invalid_request_body",
			reason:  audit.ReasonInvalidBody,
			message: "the body must contain exactly one JSON object",
		}
	}

	amount, err := money.Parse(string(request.Amount))
	if err != nil {
		return payments.Transfer{}, &refusal{
			status: http.StatusBadRequest, code: "invalid_amount",
			reason:  audit.ReasonInvalidAmount,
			message: "amount must be a positive decimal with at most two fraction digits",
		}
	}

	return payments.Transfer{
		SenderID:   strings.TrimSpace(request.SenderID),
		ReceiverID: strings.TrimSpace(request.ReceiverID),
		Amount:     amount,
	}, nil
}

// refuseTransfer records and answers a refusal that happened before the
// orchestration (identity or body).
func (s *Server) refuseTransfer(
	w http.ResponseWriter,
	r *http.Request,
	state *requestState,
	status int,
	code string,
	reason string,
	message string,
) {
	s.audit.Log(r.Context(), audit.Record{
		Event:       audit.EventRequestBlocked,
		Verdict:     audit.VerdictDeny,
		Reason:      reason,
		Method:      r.Method,
		Path:        r.URL.Path,
		Status:      status,
		RemoteAddr:  remoteHost(r.RemoteAddr),
		TraceParent: traceOf(state, r),
		RequestID:   requestIDOf(state),
		Detail:      map[string]any{"code": code, "mtls_identity": identityOf(state)},
	})
	writeError(w, status, code, message)
}

// ---------------------------------------------------------------------------
// Probes and metrics
// ---------------------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": s.cfg.ServiceName})
}

// handleReadyz answers "can this service actually serve a transfer?": the
// ledger must be reachable and the guard must hold key material to verify
// tokens with. A service that can reach neither is up but useless, and reporting
// it as healthy would take it out of the operator's view at exactly the moment
// they need it.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	details := map[string]any{"store": s.store.Kind()}

	if err := s.store.Ping(ctx); err != nil {
		s.logger.Warn("readiness_check_failed", "dependency", "ledger", "error", err)
		details["ledger"] = "unreachable"
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unready", "detail": details})
		return
	}
	details["ledger"] = "ok"

	if s.verifier.KeyCount() == 0 {
		// Nothing cached yet: try once so the probe reflects a live IdP rather
		// than the accident of this process having just started.
		if err := s.verifier.Refresh(ctx); err != nil {
			s.logger.Warn("readiness_check_failed", "dependency", "jwks", "error", err)
			details["jwks"] = "unreachable"
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unready", "detail": details})
			return
		}
	}
	details["jwks_keys"] = s.verifier.KeyCount()

	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "detail": details})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := s.metrics.Write(w); err != nil {
		slog.Error("metrics write failed", "error", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	envelope := errorEnvelope{}
	envelope.Error.Code = code
	envelope.Error.Message = message
	writeJSON(w, status, envelope)
}

// bearerToken extracts the contract's `Authorization: Bearer <JWT>` header
// (docs/division.md §1). The scheme is matched case-insensitively because
// clients disagree about `Bearer` and none of them are wrong to.
func bearerToken(r *http.Request) (string, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return "", false
	}
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	token := strings.TrimSpace(value)
	return token, token != ""
}

// routeLabel maps a request onto a bounded set of labels. Nothing user-supplied
// becomes a metric label: an unbounded label value is a memory leak with extra
// steps.
func routeLabel(r *http.Request) string {
	switch {
	case r.URL.Path == TransferPath:
		return "transfer"
	case r.URL.Path == healthzPath:
		return "healthz"
	case r.URL.Path == readyzPath:
		return "readyz"
	case r.URL.Path == metricsPath:
		return "metrics"
	default:
		return "other"
	}
}

// remoteHost strips the port from a remote address, so the audit trail records
// a client rather than a client's ephemeral port.
func remoteHost(addr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.TrimSpace(addr)
	}
	return host
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func stateFrom(ctx context.Context) *requestState {
	if state, ok := ctx.Value(stateKey{}).(*requestState); ok {
		return state
	}
	return &requestState{span: tracecontext.New(), start: time.Now().UTC()}
}

func traceOf(state *requestState, r *http.Request) string {
	if state != nil && state.span.TraceID != "" {
		return state.span.Header()
	}
	return r.Header.Get("traceparent")
}

func requestIDOf(state *requestState) string {
	if state == nil {
		return ""
	}
	return state.requestID
}

func identityOf(state *requestState) string {
	if state == nil {
		return ""
	}
	return state.identity
}
