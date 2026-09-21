// Package api is the telemetry service's HTTP surface.
//
// It has three jobs, matching Person 6's deliverable (docs/division.md):
//
//   - Ingest: collect security decision logs from every component. Producers
//     either push explicitly (/v1/audit/events), have their structured stdout
//     shipped by the collector (/v1/audit/logs), or export OpenTelemetry
//     spans (/v1/traces).
//   - Read: answer the dashboard's questions — how many requests were blocked,
//     how many unauthorized attempts were seen, and what happened inside a
//     given distributed trace.
//   - Operate: /healthz, /readyz and /metrics so the pipeline itself is
//     observable. An observability service nobody can observe is a joke.
//
// The ingest endpoints are authenticated: an unauthenticated audit endpoint
// lets anyone forge or flood the security record. Comparison is constant-time
// so the token cannot be recovered by timing.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"telemetry/internal/audit"
	"telemetry/internal/config"
	"telemetry/internal/otlp"
	"telemetry/internal/store"
)

// SpanForwarder mirrors received spans to another OTLP collector (Jaeger).
type SpanForwarder interface {
	Forward(ctx context.Context, body []byte) error
}

// Server holds the API dependencies.
type Server struct {
	logger    *slog.Logger
	cfg       *config.Config
	store     store.Store
	forwarder SpanForwarder
	// now is injectable so tests can freeze the clock.
	now func() time.Time

	// Counters, mirroring what /metrics exposes.
	eventsIngested   atomic.Int64
	eventsDuplicate  atomic.Int64
	eventsRejected   atomic.Int64
	logsSkipped      atomic.Int64
	futureDated      atomic.Int64
	spansIngested    atomic.Int64
	ingestRejections atomic.Int64
	readRejections   atomic.Int64
	requestsIngested atomic.Int64
	requestsRead     atomic.Int64
}

// New builds the HTTP handler for the telemetry service.
func New(logger *slog.Logger, cfg *config.Config, st store.Store, forwarder SpanForwarder, now func() time.Time) *Server {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Server{logger: logger, cfg: cfg, store: st, forwarder: forwarder, now: now}
}

// Handler returns the fully wired handler chain.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Ingest — authenticated with the collector token.
	mux.Handle("POST /v1/audit/events", s.requireIngestAuth(http.HandlerFunc(s.handleIngestEvents)))
	mux.Handle("POST /v1/audit/logs", s.requireIngestAuth(http.HandlerFunc(s.handleIngestLogs)))
	// The OTLP signal paths keep their standard names so a service can point an
	// OpenTelemetry exporter at this base URL and be audited without any
	// log-shape matching.
	mux.Handle("POST /v1/traces", s.requireIngestAuth(http.HandlerFunc(s.handleIngestTraces)))
	mux.Handle("POST /v1/logs", s.requireIngestAuth(http.HandlerFunc(s.handleIngestOTLPLogs)))

	// Read — optionally authenticated, open by default for a local reviewer.
	mux.Handle("GET /v1/audit/summary", s.requireReadAuth(s.countRead(s.handleSummary)))
	mux.Handle("GET /v1/audit/events", s.requireReadAuth(s.countRead(s.handleEvents)))
	mux.Handle("GET /v1/audit/traces/{traceID}", s.requireReadAuth(s.countRead(s.handleTrace)))
	mux.Handle("GET /dashboard", s.requireReadAuth(s.countRead(s.handleDashboard)))
	mux.Handle("GET /", http.HandlerFunc(s.handleIndex))

	// Operations — deliberately unauthenticated so Docker and the platform can
	// probe them without holding service tokens.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	return s.recoverPanics(s.logRequests(mux))
}

// --- middleware -----------------------------------------------------------

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Health probes would otherwise drown the log at container scale.
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}

		// Same field names the IdP emits (idp/internal/httpapi), so the audit
		// collector can read this service's own logs with the same normaliser
		// it applies to everyone else's.
		s.logger.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"traceparent", r.Header.Get("traceparent"),
			"user_agent", r.UserAgent(),
		)
	})
}

func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("http_panic", "panic", rec, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireIngestAuth(next http.Handler) http.Handler {
	if !s.cfg.RequiresIngestAuth() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !constantTimeEqual(presentedToken(r), s.cfg.IngestToken) {
			s.ingestRejections.Add(1)
			s.logger.Warn("ingest_rejected",
				"reason", "invalid_token",
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
				"traceparent", r.Header.Get("traceparent"),
			)
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing ingest token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// countRead records read traffic, so the pipeline's own load is visible in the
// same place as everything else it measures.
func (s *Server) countRead(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.requestsRead.Add(1)
		next(w, r)
	}
}

// readTokenCookie is the cookie the dashboard exchanges a URL token for.
const readTokenCookie = "telemetry_read_token"

func (s *Server) requireReadAuth(next http.Handler) http.Handler {
	if s.cfg.ReadToken == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := presentedToken(r)
		if presented == "" {
			// Fall back to a cookie so a human can open /dashboard in a
			// browser without putting the token in the URL (where it would
			// land in access logs and referrer headers).
			if cookie, err := r.Cookie(readTokenCookie); err == nil {
				presented = cookie.Value
			}
		}

		// ?token= is the documented way in for a browser (see .env.example). A
		// correct one is exchanged for the cookie and the request is redirected
		// to the same URL without the query string, so the token does not stay
		// in the address bar, the browser history or any Referer header. This
		// applies only to the human-facing pages: an API caller sends a header,
		// and a token in a query string is exactly what we are avoiding.
		if presented == "" && !strings.HasPrefix(r.URL.Path, "/v1/") {
			if token := strings.TrimSpace(r.URL.Query().Get("token")); token != "" {
				if constantTimeEqual(token, s.cfg.ReadToken) {
					http.SetCookie(w, &http.Cookie{
						Name:     readTokenCookie,
						Value:    token,
						Path:     "/",
						HttpOnly: true,
						SameSite: http.SameSiteStrictMode,
						Secure:   requestIsTLS(r),
					})
					http.Redirect(w, r, strippedTokenURL(r), http.StatusFound)
					return
				}
				s.readRejections.Add(1)
				http.Error(w, "unauthorized: that token is not the read token", http.StatusUnauthorized)
				return
			}
		}

		if !constantTimeEqual(presented, s.cfg.ReadToken) {
			s.readRejections.Add(1)
			if strings.HasPrefix(r.URL.Path, "/v1/") {
				writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing read token")
			} else {
				http.Error(w, "unauthorized: set the telemetry_read_token cookie to view the dashboard", http.StatusUnauthorized)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// presentedToken reads the token from Authorization: Bearer or the
// X-Telemetry-Token header. A dedicated header exists because collectors are
// not always able to set Authorization.
func presentedToken(r *http.Request) string {
	if header := r.Header.Get("Authorization"); header != "" {
		if _, value, ok := strings.Cut(header, " "); ok && strings.EqualFold(strings.TrimSpace(header[:strings.Index(header, " ")]), "bearer") {
			return strings.TrimSpace(value)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Telemetry-Token"))
}

// requestIsTLS reports whether the browser reached us over TLS. A terminating
// proxy is the common case in a deployment, so the forwarded header counts too.
func requestIsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// strippedTokenURL is the same request without its token query parameter.
func strippedTokenURL(r *http.Request) string {
	query := r.URL.Query()
	query.Del("token")
	target := *r.URL
	target.Scheme, target.Host = "", ""
	target.RawQuery = query.Encode()
	if target.Path == "" {
		target.Path = "/"
	}
	return target.String()
}

func constantTimeEqual(presented, expected string) bool {
	if presented == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

// --- ingest ---------------------------------------------------------------

// ingestResult is the receipt handed back to a collector.
type ingestResult struct {
	Accepted   int    `json:"accepted"`
	Duplicates int    `json:"duplicates"`
	Skipped    int    `json:"skipped"`
	Message    string `json:"message,omitempty"`
}

func (s *Server) handleIngestEvents(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}

	events, skipped, err := audit.ParseEvents(body, s.cfg.DefaultService)
	if err != nil {
		s.reject(w, "audit", err)
		return
	}
	for i := range events {
		events[i].IngestedVia = "push"
	}
	s.storeEvents(w, r, events, skipped)
}

func (s *Server) handleIngestLogs(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}

	events, skipped, err := audit.ParseLogs(body, s.cfg.DefaultService)
	if err != nil {
		s.reject(w, "log", err)
		return
	}
	for i := range events {
		events[i].IngestedVia = "docker"
	}
	s.storeEvents(w, r, events, skipped)
}

func (s *Server) storeEvents(w http.ResponseWriter, r *http.Request, events []audit.Event, skipped int) {
	s.requestsIngested.Add(1)
	s.logsSkipped.Add(int64(skipped))
	s.checkClockSkew(events)

	inserted, err := s.store.InsertEvents(r.Context(), events)
	if err != nil {
		s.logger.Error("ingest_store_failed", "error", err, "count", len(events))
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "audit store is unavailable")
		return
	}

	s.eventsIngested.Add(int64(inserted))
	s.eventsDuplicate.Add(int64(len(events) - inserted))

	// Record acceptances as audit events in their own right: a gap in the
	// trail is only detectable if the collector's health is part of the trail.
	s.logger.Info("ingest_accepted",
		"count", inserted,
		"duplicates", len(events)-inserted,
		"skipped", skipped,
		"traceparent", r.Header.Get("traceparent"),
	)

	writeJSON(w, http.StatusOK, ingestResult{
		Accepted:   inserted,
		Duplicates: len(events) - inserted,
		Skipped:    skipped,
	})
}

// clockSkewTolerance is how far ahead of its own clock a record's timestamp may
// be before the pipeline assumes the producer is wrong rather than merely
// imprecise.
const clockSkewTolerance = 5 * time.Minute

// checkClockSkew reports records dated in the future.
//
// A producer that logs local time with a "Z" suffix (or with a clock that is
// simply wrong) has its decisions stored and then excluded from every dashboard
// window, because a window ends at now. The record is not rejected — the
// producer said what it said, and forensics should keep it — but a decision
// that is stored and invisible is exactly the failure this pipeline exists to
// prevent, so it is counted and named rather than left to be discovered.
func (s *Server) checkClockSkew(events []audit.Event) {
	now := s.now()
	future := 0
	var worst time.Duration
	service := ""
	for _, event := range events {
		if ahead := event.OccurredAt.Sub(now); ahead > clockSkewTolerance {
			future++
			if ahead > worst {
				worst, service = ahead, event.Service
			}
		}
	}
	if future == 0 {
		return
	}
	s.futureDated.Add(int64(future))
	s.logger.Warn("ingest_future_dated",
		"count", future,
		"service", service,
		"ahead", worst.Round(time.Second).String(),
		"hint", "the record is stored, but a future timestamp falls outside every dashboard window: the producer is probably logging local time instead of UTC",
	)
}

// handleIngestOTLPLogs accepts the OTLP logs signal (ExportLogsServiceRequest),
// so a service instrumented with an OpenTelemetry SDK can export its security
// decisions instead of — or as well as — printing structured JSON.
func (s *Server) handleIngestOTLPLogs(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}

	events, skipped, err := otlp.DecodeLogs(body, s.cfg.DefaultService)
	if err != nil {
		s.reject(w, "otlp-log", err)
		return
	}
	for i := range events {
		events[i].IngestedVia = "otlp"
	}
	s.storeEvents(w, r, events, skipped)
}

func (s *Server) handleIngestTraces(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}

	spans, err := otlp.Decode(body, s.cfg.DefaultService)
	if err != nil {
		s.reject(w, "trace", err)
		return
	}

	inserted, err := s.store.InsertSpans(r.Context(), spans)
	if err != nil {
		s.logger.Error("span_store_failed", "error", err, "count", len(spans))
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "span store is unavailable")
		return
	}
	s.spansIngested.Add(int64(inserted))
	s.requestsIngested.Add(1)

	// Mirror to the visual span browser (Jaeger) when configured. A failed
	// mirror is logged, never fatal: the audit trail's copy already landed,
	// and rejecting the export would make the collector retry and duplicate.
	if s.forwarder != nil {
		if err := s.forwarder.Forward(r.Context(), body); err != nil {
			s.logger.Warn("otlp_forward_failed", "error", err, "endpoint", s.cfg.ForwardOTLPEndpoint)
		}
	}

	writeJSON(w, http.StatusOK, ingestResult{
		Accepted:   inserted,
		Duplicates: len(spans) - inserted,
	})
}

func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	// OTLP/protobuf is the OpenTelemetry SDK's default encoding. Supporting it
	// would mean taking on the OTLP protobuf definitions for a signal the
	// pipeline already accepts as JSON, so the request is refused with the exact
	// setting that makes it work — a 400 that says "payload must be JSON" would
	// send the reader looking in the wrong place.
	if contentType := strings.ToLower(r.Header.Get("Content-Type")); strings.Contains(contentType, "protobuf") {
		s.eventsRejected.Add(1)
		writeError(w, http.StatusUnsupportedMediaType, "protobuf_not_supported",
			"this collector accepts OTLP/JSON: set OTEL_EXPORTER_OTLP_PROTOCOL=http/json "+
				"(or OTEL_EXPORTER_OTLP_TRACES_PROTOCOL / OTEL_EXPORTER_OTLP_LOGS_PROTOCOL)")
		return nil, false
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.eventsRejected.Add(1)
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("payload exceeds %d bytes", s.cfg.MaxBodyBytes))
			return nil, false
		}
		s.reject(w, "ingest", err)
		return nil, false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		s.reject(w, "ingest", audit.ErrEmptyPayload)
		return nil, false
	}
	return body, true
}

func (s *Server) reject(w http.ResponseWriter, what string, err error) {
	s.eventsRejected.Add(1)
	s.logger.Warn("ingest_rejected", "reason", err.Error(), "kind", what)
	writeError(w, http.StatusBadRequest, "invalid_payload", err.Error())
}

// --- read -----------------------------------------------------------------

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	window, err := s.window(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_window", err.Error())
		return
	}
	now := s.now()
	summary, err := s.store.Summary(r.Context(), now.Add(-window), now)
	if err != nil {
		s.logger.Error("summary_failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "audit store is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window":       window.String(),
		"generated_at": s.now(),
		"summary":      summary,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	filter := audit.Filter{
		Decision: query.Get("decision"),
		Category: query.Get("category"),
		Service:  query.Get("service"),
		Reason:   query.Get("reason"),
		Subject:  query.Get("subject"),
		TraceID:  query.Get("trace_id"),
		Search:   query.Get("q"),
	}
	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be an integer")
			return
		}
		filter.Limit = limit
	}
	if raw := query.Get("offset"); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			writeError(w, http.StatusBadRequest, "invalid_offset", "offset must be a non-negative integer")
			return
		}
		filter.Offset = offset
	}

	// An explicit since/until window wins; otherwise fall back to `window`.
	if query.Get("since") != "" || query.Get("until") != "" {
		since, err := parseTime(query.Get("since"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_since", err.Error())
			return
		}
		until, err := parseTime(query.Get("until"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_until", err.Error())
			return
		}
		filter.Since, filter.Until = since, until
	} else {
		window, err := s.window(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_window", err.Error())
			return
		}
		now := s.now()
		filter.Since, filter.Until = now.Add(-window), now
	}

	events, err := s.store.QueryEvents(r.Context(), filter)
	if err != nil {
		s.logger.Error("query_failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "audit store is unavailable")
		return
	}
	if events == nil {
		events = []audit.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":        len(events),
		"generated_at": s.now(),
		"events":       events,
	})
}

func (s *Server) handleTrace(w http.ResponseWriter, r *http.Request) {
	traceID := strings.TrimSpace(r.PathValue("traceID"))
	if len(traceID) != 32 || !isHex(traceID) {
		writeError(w, http.StatusBadRequest, "invalid_trace_id",
			"a W3C trace id is 32 lowercase hex characters (docs/flow.md §3)")
		return
	}

	trace, err := s.store.Trace(r.Context(), strings.ToLower(traceID))
	if err != nil {
		s.logger.Error("trace_failed", "error", err, "trace_id", traceID)
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "audit store is unavailable")
		return
	}
	if trace == nil {
		writeError(w, http.StatusNotFound, "trace_not_found",
			"no spans or audit events are stored for that trace id")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": s.now(),
		"trace":        trace,
	})
}

// window resolves the requested aggregation window, clamped to MaxWindow so a
// public read endpoint cannot be used to make the database scan everything.
func (s *Server) window(r *http.Request) (time.Duration, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("window"))
	if raw == "" {
		return s.cfg.DashboardWindow, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("window=%q is not a duration such as \"1h\" or \"7d\" (use \"168h\")", raw)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("window must be positive")
	}
	if parsed > s.cfg.MaxWindow {
		return s.cfg.MaxWindow, nil
	}
	return parsed, nil
}

func parseTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UTC(), nil
	}
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(seconds, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%q is not RFC3339 or a unix timestamp", raw)
}

// --- operations -----------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	if err := s.store.Ping(ctx); err != nil {
		s.logger.Warn("readiness_check_failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "store": string(s.cfg.Store)})
}

// handleMetrics exposes the pipeline's own counters in Prometheus text format
// so the collector is monitored by the same tooling as everything else.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintf(w, "# HELP telemetry_events_ingested_total Audit events newly written to the store.\n")
	fmt.Fprintf(w, "# TYPE telemetry_events_ingested_total counter\n")
	fmt.Fprintf(w, "telemetry_events_ingested_total %d\n", s.eventsIngested.Load())

	fmt.Fprintf(w, "# HELP telemetry_events_duplicate_total Re-ingested events skipped by the idempotency check.\n")
	fmt.Fprintf(w, "# TYPE telemetry_events_duplicate_total counter\n")
	fmt.Fprintf(w, "telemetry_events_duplicate_total %d\n", s.eventsDuplicate.Load())

	fmt.Fprintf(w, "# HELP telemetry_records_skipped_total Records classified as carrying no security signal.\n")
	fmt.Fprintf(w, "# TYPE telemetry_records_skipped_total counter\n")
	fmt.Fprintf(w, "telemetry_records_skipped_total %d\n", s.logsSkipped.Load())

	fmt.Fprintf(w, "# HELP telemetry_payloads_rejected_total Ingest payloads rejected as invalid.\n")
	fmt.Fprintf(w, "# TYPE telemetry_payloads_rejected_total counter\n")
	fmt.Fprintf(w, "telemetry_payloads_rejected_total %d\n", s.eventsRejected.Load())

	fmt.Fprintf(w, "# HELP telemetry_events_future_dated_total Records stored with a timestamp ahead of the pipeline's clock, which no dashboard window will show.\n")
	fmt.Fprintf(w, "# TYPE telemetry_events_future_dated_total counter\n")
	fmt.Fprintf(w, "telemetry_events_future_dated_total %d\n", s.futureDated.Load())

	fmt.Fprintf(w, "# HELP telemetry_spans_ingested_total Spans newly written to the store.\n")
	fmt.Fprintf(w, "# TYPE telemetry_spans_ingested_total counter\n")
	fmt.Fprintf(w, "telemetry_spans_ingested_total %d\n", s.spansIngested.Load())

	fmt.Fprintf(w, "# HELP telemetry_ingest_rejections_total Ingest requests rejected for a bad token.\n")
	fmt.Fprintf(w, "# TYPE telemetry_ingest_rejections_total counter\n")
	fmt.Fprintf(w, "telemetry_ingest_rejections_total %d\n", s.ingestRejections.Load())

	fmt.Fprintf(w, "# HELP telemetry_read_rejections_total Read requests rejected for a bad token.\n")
	fmt.Fprintf(w, "# TYPE telemetry_read_rejections_total counter\n")
	fmt.Fprintf(w, "telemetry_read_rejections_total %d\n", s.readRejections.Load())

	fmt.Fprintf(w, "# HELP telemetry_read_requests_total Read API and dashboard requests served.\n")
	fmt.Fprintf(w, "# TYPE telemetry_read_requests_total counter\n")
	fmt.Fprintf(w, "telemetry_read_requests_total %d\n", s.requestsRead.Load())

	fmt.Fprintf(w, "# HELP telemetry_ready Whether the audit store is reachable.\n")
	fmt.Fprintf(w, "# TYPE telemetry_ready gauge\n")
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	ready := 0
	if err := s.store.Ping(ctx); err == nil {
		ready = 1
	}
	fmt.Fprintf(w, "telemetry_ready %d\n", ready)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint")
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// --- helpers --------------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

func isHex(value string) bool {
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return value != ""
}
