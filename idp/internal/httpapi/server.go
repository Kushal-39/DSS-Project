// Package httpapi exposes the IdP's HTTP surface using only the standard
// library net/http mux (Go 1.22 method+path routing — no framework).
//
// Routes:
//
//	POST /login                           authenticate and issue an RS256 JWT
//	GET  /.well-known/jwks.json           public RSA key for the API Gateway
//	GET  /.well-known/openid-configuration  minimal discovery document
//	GET  /healthz                         liveness probe
//	GET  /readyz                          readiness probe (pings the database)
//
// All responses are JSON; every request is logged as one structured JSON
// line (docs/flow.md §6) including the inbound traceparent header so Person
// 6's pipeline can correlate the IdP's spans.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"idp/internal/auth"
	"idp/internal/keys"
)

// Server wires the IdP's dependencies into an http.Handler.
type Server struct {
	logger  *slog.Logger
	store   auth.Store
	issuer  *auth.Issuer
	signKey *keys.Key
	pool    pinger
	now     func() time.Time
}

// pinger is the minimal database surface the readiness probe needs, so
// tests can substitute a stub.
type pinger interface {
	Ping(ctx context.Context) error
}

// New builds the handler tree with middleware applied.
func New(logger *slog.Logger, store auth.Store, issuer *auth.Issuer, signKey *keys.Key, pool pinger) http.Handler {
	s := &Server{
		logger:  logger,
		store:   store,
		issuer:  issuer,
		signKey: signKey,
		pool:    pool,
		now:     time.Now,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /token", s.handleLogin)
	mux.HandleFunc("GET /jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleOpenIDConfig)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	return s.middleware(mux)
}

// middleware applies, in order: panic recovery (outermost), request logging,
// then security response headers.
func (s *Server) middleware(next http.Handler) http.Handler {
	return s.traceRequests(s.recoverPanics(s.logRequests(s.securityHeaders(next))))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// logRequests emits one structured JSON line per request with the fields
// Person 6's pipeline expects, including traceparent when the caller sent it.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		s.logger.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"traceparent", r.Header.Get("traceparent"),
			"user_agent", r.Header.Get("User-Agent"),
		)
	})
}

// recoverPanics converts a panicking handler into a 500 JSON response
// instead of dropping the connection (and leaking a stack trace).
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

// statusRecorder captures the response status for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// loginRequest is the accepted payload for POST /login. device_id is
// optional (docs/flow.md requires the claim; a UUID v4 is generated when the
// client omits it).
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	DeviceID string `json:"device_id"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}

	// The gateway's rate limiting protects against brute force at the edge;
	// here we only enforce a sane body size bound.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

	var req loginRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must contain one JSON object")
		return
	}

	if strings.TrimSpace(req.Username) == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return
	}

	now := s.now()
	user, err := auth.Authenticate(r.Context(), s.store, req.Username, req.Password)
	if err != nil {
		s.logger.Info("login_attempt",
			"outcome", "denied",
			"username", req.Username,
			"traceparent", r.Header.Get("traceparent"),
		)
		// Identical message for unknown user vs wrong password: never
		// reveal which usernames exist.
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}

	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		deviceID = newUUIDv4()
	}

	token, expiresAt, err := s.issuer.Issue(user, deviceID, now)
	if err != nil {
		s.logger.Error("token_issue_failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}

	s.logger.Info("login_attempt",
		"outcome", "permit",
		"user_id", user.UserID,
		"role", user.Role,
		"traceparent", r.Header.Get("traceparent"),
	)

	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(expiresAt.Sub(now).Seconds()),
		"user": map[string]string{
			"id":       user.UserID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

// handleJWKS serves the public signing key in RFC 7517 JSON Web Key Set
// format. The API Gateway (Person 2) fetches this to verify token
// signatures. Keys are long-lived in this phase, so a modest cache header
// is safe and saves the gateway a round trip.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{s.signKey.PublicJWK()},
	})
}

// handleOpenIDConfig exposes a minimal discovery document (docs/division.md
// lists it as a Person 1 deliverable). It advertises the JWKS URI so the
// gateway can auto-discover keys instead of hardcoding the path.
func (s *Server) handleOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer.Issuer,
		"jwks_uri":                              s.issuer.Issuer + "/.well-known/jwks.json",
		"token_endpoint":                        s.issuer.Issuer + "/login",
		"response_types_supported":              []string{"token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz reports whether the service can serve traffic: it pings the
// database with a short timeout so Compose health checks see a meaningful
// signal during startup.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.pool.Ping(ctx); err != nil {
		s.logger.Warn("readiness_check_failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "database not reachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// errorEnvelope is the consistent error shape across all endpoints.
type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	env := errorEnvelope{}
	env.Error.Code = code
	env.Error.Message = message
	writeJSON(w, status, env)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// Response already committed; nothing more we can do but log.
		slog.Error("failed to encode response", "error", err)
	}
}

// newUUIDv4 generates a random UUID v4 from crypto/rand. The IdP needs a
// device identity when the client does not supply one; pulling in a UUID
// library for one call is not justified.
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().Format("20060102150405.000000000")
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
