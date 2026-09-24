// Package config loads and validates the payment service's runtime
// configuration from environment variables.
//
// Same rules as the rest of the monorepo (see idp/internal/config and
// telemetry/internal/config): nothing is hardcoded, secrets arrive through the
// git-crypt-encrypted .env file, and a missing or malformed required variable
// aborts startup with a message that says how to fix it.
//
// Two defaults here are deliberately *stricter* than the other services,
// because Person 5's mandate (docs/division.md) is strict mTLS enforcement and
// a financial service that half-works is worse than one that refuses to boot:
//
//   - TLS 1.3 with verified client certificates is the norm, and starting
//     without it requires the explicit PAYMENT_ALLOW_INSECURE_HTTP=true.
//   - The downstream Account Service must be reached over https (i.e. over the
//     project's Transport Contract, docs/division.md §2); plain http needs the
//     explicit PAYMENT_ALLOW_INSECURE_UPSTREAM=true.
//
// The Policy Engine is the documented exception: docs/policymaker.md specifies
// its endpoint as `http://policy-engine:8181/...`, so plain HTTP there is the
// contract rather than a lapse. It supports https the moment Person 3 adds a
// TLS listener.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"paymentservice/internal/money"
)

// StoreKind selects the ledger persistence backend.
type StoreKind string

const (
	// StorePostgres is the durable backend and the default. The service owns
	// the `transactions` table in the shared instance (docs/database.md §2).
	StorePostgres StoreKind = "postgres"
	// StoreMemory is a volatile, explicitly-selected demo mode. It exists so
	// the mTLS, policy and deduct paths can be exercised end to end on a
	// machine that has no database credentials, without pretending to be
	// durable.
	StoreMemory StoreKind = "memory"
)

// Defaults documented in .env.example.
const (
	DefaultAddr         = ":8081"
	DefaultServiceName  = "payment-service"
	DefaultJWKSPath     = "http://idp:8080/.well-known/jwks.json"
	DefaultJWTAudience  = "zerotrust-api-gateway"
	DefaultPolicyURL    = "http://policy-engine:8181/v1/data/authz/allow"
	DefaultAccountURL   = "https://account-service:8082"
	DefaultMaxTransfer  = "99999999.99"
	DefaultMaxBodyBytes = 64 << 10
)

// Config is the validated runtime configuration.
type Config struct {
	// Addr is the HTTP listen address (PAYMENT_ADDR, default ":8081").
	Addr string
	// ServiceName is the audit label for this component.
	ServiceName string
	// LogLevel is the slog level (PAYMENT_LOG_LEVEL).
	LogLevel slog.Level

	// Store selects the backend (PAYMENT_STORE, default "postgres").
	Store StoreKind
	// DatabaseURL is the shared PostgreSQL instance. Under
	// Database-per-Service (docs/database.md §2) this service owns the
	// `transactions` table and reads no other service's tables.
	DatabaseURL string
	// DatabaseMaxConns bounds the pool so this service cannot starve the
	// others on a shared instance.
	DatabaseMaxConns int

	// MaxBodyBytes bounds a request body (PAYMENT_MAX_BODY_BYTES, default
	// 64 KiB). A transfer is three fields; anything larger is not one.
	MaxBodyBytes int64
	// ShutdownGrace bounds graceful shutdown.
	ShutdownGrace time.Duration

	// ---- identity (Person 1) -------------------------------------------

	// JWKSURL is the IdP's public key set (PAYMENT_JWKS_URL). The gateway
	// verifies the token first (docs/flow.md §2) and this service verifies it
	// again: the same signature check at a second boundary is the difference
	// between "the perimeter trusted it" and "the callee trusts it".
	JWKSURL string
	// JWKSRefreshInterval is how long a fetched key set is trusted before it is
	// refetched (PAYMENT_JWKS_CACHE_TTL, default 5m).
	JWKSRefreshInterval time.Duration
	// JWKSUnknownKidInterval throttles key-set refetches triggered by a token
	// presenting an unknown key id, so a flood of junk `kid`s cannot turn into
	// a flood of requests to the IdP (PAYMENT_JWKS_UNKNOWN_KID_INTERVAL).
	JWKSUnknownKidInterval time.Duration
	// JWKSRequestTimeout bounds a single key-set fetch.
	JWKSRequestTimeout time.Duration
	// JWKSRequestTLS is the TLS half of fetching the key set, for when the IdP
	// serves https.
	JWKSRequestTLS ClientTLS

	// JWTIssuer is the expected `iss` claim; empty skips the check.
	JWTIssuer string
	// JWTAudience is the expected `aud` claim; empty skips the check.
	JWTAudience string
	// JWTClockSkew is the leeway applied to exp/nbf.
	JWTClockSkew time.Duration

	// ---- authorization (Person 3) --------------------------------------

	// PolicyURL is the OPA data endpoint (PAYMENT_POLICY_URL), exactly the
	// contract endpoint from docs/policymaker.md.
	PolicyURL string
	// PolicyTimeout bounds the synchronous authorization call. It sits in the
	// request path, so it must stay short; the engine answers from memory.
	PolicyTimeout time.Duration
	// PolicyTLS is used when PolicyURL is https.
	PolicyTLS ClientTLS

	// ---- business (Person 4) -------------------------------------------

	// AccountServiceURL is Person 4's Account Service
	// (PAYMENT_ACCOUNT_SERVICE_URL). Its `/api/v1/accounts/deduct` endpoint is
	// the only way this service may move money: it has no access to the
	// `accounts` table (docs/database.md §2).
	AccountServiceURL string
	// AccountServiceTimeout bounds the deduct call.
	AccountServiceTimeout time.Duration
	// AccountServiceTLS is this service's *client* identity for that call.
	AccountServiceTLS ClientTLS
	// AllowInsecureUpstream permits an http:// Account Service URL. Off by
	// default: service-to-service traffic carries a bearer token and must run
	// over the Transport Contract.
	AllowInsecureUpstream bool

	// MaxTransfer is the largest amount this service will even ask about
	// (PAYMENT_MAX_TRANSFER_AMOUNT, default 99999999.99 — the range of the
	// DECIMAL(10,2) column). The *business* threshold (50 000 in Person 3's
	// Rego) deliberately stays in the policy engine: it is a policy decision,
	// not a validation rule, and duplicating it here would move the decision
	// point away from the engine that is contracted to make it.
	MaxTransfer money.Amount
	// EnforceSenderBinding requires a non-admin token's `sub` claim to match
	// the request's sender_id (PAYMENT_ENFORCE_SENDER_BINDING, default true).
	// Without it, any authenticated customer could debit any account by naming
	// it — the exact attack this architecture exists to prevent.
	EnforceSenderBinding bool

	// ---- transport (Person 5's own listener) ---------------------------

	// ServerTLS is the listener's mTLS material: this service's certificate,
	// the shared CA that signed the callers', and whether a client
	// certificate is mandatory.
	ServerTLS ServerTLS
	// AllowInsecureHTTP permits serving without TLS at all. Off by default;
	// the service refuses to start rather than expose an internal financial
	// endpoint in cleartext.
	AllowInsecureHTTP bool
	// AllowedClientIDs is the allowlist of client identities permitted to call
	// the business API (PAYMENT_ALLOWED_CLIENT_IDS, default
	// "gateway,account-service"). A certificate that chains to the shared CA
	// proves a caller is *inside* the trust domain; it does not prove which
	// service it is, and only the API Gateway and Microservice A are supposed
	// to reach Microservice B (docs/division.md).
	AllowedClientIDs []string

	// ---- observability (Person 6) --------------------------------------

	// OTLPEndpoint receives this service's spans as OTLP/JSON
	// (PAYMENT_OTLP_ENDPOINT, default http://telemetry:8088/v1/traces). Empty
	// disables span export; the audit trail on stdout is unaffected.
	OTLPEndpoint string
	// OTLPToken authenticates the export (PAYMENT_OTLP_TOKEN, the
	// TELEMETRY_INGEST_TOKEN value).
	OTLPToken string
	// OTLPTimeout bounds one span export.
	OTLPTimeout time.Duration
	// OTLPRequestTLS is used when OTLPEndpoint is https.
	OTLPRequestTLS ClientTLS
}

// ServerTLS is the listener's TLS material.
type ServerTLS struct {
	CertFile string
	KeyFile  string
	CAFile   string
	// RequireClientCert makes the listener mutual. Default true: Person 5's
	// deliverable is strict mTLS enforcement, so "a valid certificate or no
	// connection" is the norm and turning it off is the deliberate exception.
	RequireClientCert bool
}

// Enabled reports whether TLS material was supplied.
func (s ServerTLS) Enabled() bool {
	return s.CertFile != "" || s.KeyFile != "" || s.CAFile != ""
}

// ClientTLS is one side of an outbound TLS connection.
type ClientTLS struct {
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
}

// Enabled reports whether any TLS setting was supplied.
func (c ClientTLS) Enabled() bool {
	return c.CertFile != "" || c.KeyFile != "" || c.CAFile != "" || c.ServerName != ""
}

// RequiresOTLPAuth reports whether the span export carries a token.
func (c *Config) RequiresOTLPAuth() bool { return c.OTLPToken != "" }

// Load reads the environment and returns a validated Config.
//
// Required:
//   - DATABASE_URL            (unless PAYMENT_STORE=memory)
//   - PAYMENT_TLS_CERT_FILE / PAYMENT_TLS_KEY_FILE / PAYMENT_TLS_CA_FILE
//     (unless PAYMENT_ALLOW_INSECURE_HTTP=true)
func Load() (*Config, error) {
	var err error
	cfg := &Config{
		Addr:               getenvDefault("PAYMENT_ADDR", DefaultAddr),
		ServiceName:        getenvDefault("PAYMENT_SERVICE_NAME", DefaultServiceName),
		Store:              StoreKind(strings.ToLower(getenvDefault("PAYMENT_STORE", string(StorePostgres)))),
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		JWKSURL:            getenvDefault("PAYMENT_JWKS_URL", DefaultJWKSPath),
		JWTIssuer:          os.Getenv("PAYMENT_JWT_ISSUER"),
		JWTAudience:        getenvDefault("PAYMENT_JWT_AUDIENCE", DefaultJWTAudience),
		PolicyURL:          getenvDefault("PAYMENT_POLICY_URL", DefaultPolicyURL),
		AccountServiceURL:  getenvDefault("PAYMENT_ACCOUNT_SERVICE_URL", DefaultAccountURL),
		OTLPEndpoint:       strings.TrimSpace(os.Getenv("PAYMENT_OTLP_ENDPOINT")),
		OTLPToken:          os.Getenv("PAYMENT_OTLP_TOKEN"),
		JWTClockSkew:       30 * time.Second,
		JWKSRequestTimeout: 5 * time.Second,
	}

	if cfg.LogLevel, err = levelEnv("PAYMENT_LOG_LEVEL", slog.LevelInfo); err != nil {
		return nil, err
	}
	if cfg.MaxBodyBytes, err = int64Env("PAYMENT_MAX_BODY_BYTES", DefaultMaxBodyBytes); err != nil {
		return nil, err
	}
	if cfg.DatabaseMaxConns, err = intEnv("PAYMENT_DB_MAX_CONNS", 6); err != nil {
		return nil, err
	}

	switch cfg.Store {
	case StorePostgres, StoreMemory:
	default:
		return nil, fmt.Errorf(
			"config: PAYMENT_STORE=%q is not a known backend (use \"postgres\" or \"memory\")", cfg.Store)
	}
	if cfg.Store == StorePostgres && cfg.DatabaseURL == "" {
		return nil, fmt.Errorf(
			"config: DATABASE_URL is not set — the ledger lives in this service's own transactions table " +
				"(set PAYMENT_STORE=memory for a volatile local demo)")
	}
	if cfg.DatabaseMaxConns <= 0 {
		return nil, fmt.Errorf("config: PAYMENT_DB_MAX_CONNS must be positive")
	}
	if cfg.MaxBodyBytes <= 0 {
		return nil, fmt.Errorf("config: PAYMENT_MAX_BODY_BYTES must be positive")
	}

	if err = durationEnv("PAYMENT_SHUTDOWN_GRACE", 15*time.Second, &cfg.ShutdownGrace); err != nil {
		return nil, err
	}
	if err = durationEnv("PAYMENT_JWKS_CACHE_TTL", 5*time.Minute, &cfg.JWKSRefreshInterval); err != nil {
		return nil, err
	}
	if err = durationEnv("PAYMENT_JWKS_UNKNOWN_KID_INTERVAL", 10*time.Second, &cfg.JWKSUnknownKidInterval); err != nil {
		return nil, err
	}
	if err = durationEnv("PAYMENT_JWKS_TIMEOUT", cfg.JWKSRequestTimeout, &cfg.JWKSRequestTimeout); err != nil {
		return nil, err
	}
	if err = durationEnv("PAYMENT_JWT_CLOCK_SKEW", cfg.JWTClockSkew, &cfg.JWTClockSkew); err != nil {
		return nil, err
	}
	if err = durationEnv("PAYMENT_POLICY_TIMEOUT", 2*time.Second, &cfg.PolicyTimeout); err != nil {
		return nil, err
	}
	if err = durationEnv("PAYMENT_ACCOUNT_TIMEOUT", 5*time.Second, &cfg.AccountServiceTimeout); err != nil {
		return nil, err
	}
	if err = durationEnv("PAYMENT_OTLP_TIMEOUT", 5*time.Second, &cfg.OTLPTimeout); err != nil {
		return nil, err
	}

	if err = urlEnv("PAYMENT_JWKS_URL", cfg.JWKSURL); err != nil {
		return nil, err
	}
	if err = urlEnv("PAYMENT_POLICY_URL", cfg.PolicyURL); err != nil {
		return nil, err
	}
	if cfg.OTLPEndpoint != "" {
		if err = urlEnv("PAYMENT_OTLP_ENDPOINT", cfg.OTLPEndpoint); err != nil {
			return nil, err
		}
	}

	// ---- policy engine: http is the contract, https is supported --------

	cfg.PolicyTLS = clientTLS("PAYMENT_POLICY_TLS_")
	if err = validateClientTLS("PAYMENT_POLICY_TLS_", cfg.PolicyTLS); err != nil {
		return nil, err
	}

	// ---- account service: https and mutual TLS by default ---------------

	if cfg.AllowInsecureUpstream, err = boolEnv("PAYMENT_ALLOW_INSECURE_UPSTREAM", false); err != nil {
		return nil, err
	}
	cfg.AccountServiceTLS = clientTLS("PAYMENT_UPSTREAM_TLS_")
	if err = validateClientTLS("PAYMENT_UPSTREAM_TLS_", cfg.AccountServiceTLS); err != nil {
		return nil, err
	}
	if err = urlEnv("PAYMENT_ACCOUNT_SERVICE_URL", cfg.AccountServiceURL); err != nil {
		return nil, err
	}
	if strings.HasPrefix(cfg.AccountServiceURL, "http://") && !cfg.AllowInsecureUpstream {
		return nil, fmt.Errorf(
			"config: PAYMENT_ACCOUNT_SERVICE_URL=%q is plain http — internal service-to-service traffic "+
				"must satisfy the Transport Contract (TLS 1.3 with mutual certificate verification, "+
				"docs/division.md §2). Point it at https and set PAYMENT_UPSTREAM_TLS_CERT_FILE/_KEY_FILE/_CA_FILE, "+
				"or set PAYMENT_ALLOW_INSECURE_UPSTREAM=true for a local demo",
			cfg.AccountServiceURL)
	}

	cfg.JWKSRequestTLS = clientTLS("PAYMENT_JWKS_TLS_")
	if err = validateClientTLS("PAYMENT_JWKS_TLS_", cfg.JWKSRequestTLS); err != nil {
		return nil, err
	}
	cfg.OTLPRequestTLS = clientTLS("PAYMENT_OTLP_TLS_")
	if err = validateClientTLS("PAYMENT_OTLP_TLS_", cfg.OTLPRequestTLS); err != nil {
		return nil, err
	}

	// ---- business limits -------------------------------------------------

	if cfg.EnforceSenderBinding, err = boolEnv("PAYMENT_ENFORCE_SENDER_BINDING", true); err != nil {
		return nil, err
	}
	maxTransfer, err := money.Parse(getenvDefault("PAYMENT_MAX_TRANSFER_AMOUNT", DefaultMaxTransfer))
	if err != nil {
		return nil, fmt.Errorf("config: PAYMENT_MAX_TRANSFER_AMOUNT is invalid: %w", err)
	}
	if maxTransfer.IsZero() {
		return nil, fmt.Errorf("config: PAYMENT_MAX_TRANSFER_AMOUNT must be greater than zero")
	}
	cfg.MaxTransfer = maxTransfer

	// ---- transport -------------------------------------------------------

	if cfg.AllowInsecureHTTP, err = boolEnv("PAYMENT_ALLOW_INSECURE_HTTP", false); err != nil {
		return nil, err
	}
	cfg.ServerTLS = ServerTLS{
		CertFile: strings.TrimSpace(os.Getenv("PAYMENT_TLS_CERT_FILE")),
		KeyFile:  strings.TrimSpace(os.Getenv("PAYMENT_TLS_KEY_FILE")),
		CAFile:   strings.TrimSpace(os.Getenv("PAYMENT_TLS_CA_FILE")),
	}
	if cfg.ServerTLS.RequireClientCert, err = boolEnv("PAYMENT_TLS_REQUIRE_CLIENT_CERT", true); err != nil {
		return nil, err
	}

	if cfg.ServerTLS.Enabled() {
		if (cfg.ServerTLS.CertFile == "") != (cfg.ServerTLS.KeyFile == "") {
			return nil, fmt.Errorf(
				"config: PAYMENT_TLS_CERT_FILE and PAYMENT_TLS_KEY_FILE must be set together")
		}
		if cfg.ServerTLS.RequireClientCert && cfg.ServerTLS.CAFile == "" {
			return nil, fmt.Errorf(
				"config: PAYMENT_TLS_REQUIRE_CLIENT_CERT is true but PAYMENT_TLS_CA_FILE is not set — " +
					"there would be nothing to verify a client certificate against")
		}
	} else if !cfg.AllowInsecureHTTP {
		return nil, fmt.Errorf(
			"config: no TLS material supplied — this service handles financial transactions and refuses to " +
				"serve them in cleartext. Set PAYMENT_TLS_CERT_FILE, PAYMENT_TLS_KEY_FILE and PAYMENT_TLS_CA_FILE " +
				"(generate a local development CA with `payment-server certs --dir ./certs`), or set " +
				"PAYMENT_ALLOW_INSECURE_HTTP=true for a throwaway local demo")
	}

	cfg.AllowedClientIDs = splitList(getenvDefault("PAYMENT_ALLOWED_CLIENT_IDS", "gateway,account-service"))

	return cfg, nil
}

// WarnInsecure reports the configuration that weakens the Transport Contract,
// so startup can say it out loud rather than leaving it in the code.
func (c *Config) WarnInsecure() []string {
	var warnings []string
	if c.AllowInsecureHTTP {
		warnings = append(warnings,
			"PAYMENT_ALLOW_INSECURE_HTTP=true — the listener is plain HTTP and NO client certificate is verified")
	}
	if !c.ServerTLS.RequireClientCert {
		warnings = append(warnings,
			"PAYMENT_TLS_REQUIRE_CLIENT_CERT=false — a client certificate is optional; mTLS is not enforced")
	}
	if c.AllowInsecureUpstream {
		warnings = append(warnings,
			"PAYMENT_ALLOW_INSECURE_UPSTREAM=true — the Account Service is called over plain HTTP")
	}
	if !c.EnforceSenderBinding {
		warnings = append(warnings,
			"PAYMENT_ENFORCE_SENDER_BINDING=false — any authenticated customer may name any sender account")
	}
	return warnings
}

// LogValue renders the configuration for startup logging with every secret and
// connection string redacted. A database URL is a credential, and a startup
// banner is a log line that Person 6's pipeline copies verbatim into the audit
// store's `raw` column.
func (c *Config) LogValue() slog.Value {
	redact := func(value string) string {
		if value == "" {
			return ""
		}
		return "[set]"
	}
	return slog.GroupValue(
		slog.String("addr", c.Addr),
		slog.String("service_name", c.ServiceName),
		slog.String("store", string(c.Store)),
		slog.String("database_url", redact(c.DatabaseURL)),
		slog.Duration("jwks_cache_ttl", c.JWKSRefreshInterval),
		slog.String("jwks_url", c.JWKSURL),
		slog.String("jwt_audience", c.JWTAudience),
		slog.String("policy_url", c.PolicyURL),
		slog.Duration("policy_timeout", c.PolicyTimeout),
		slog.String("account_service_url", c.AccountServiceURL),
		slog.Duration("account_timeout", c.AccountServiceTimeout),
		slog.String("max_transfer", c.MaxTransfer.String()),
		slog.Bool("enforce_sender_binding", c.EnforceSenderBinding),
		slog.Bool("server_tls", c.ServerTLS.Enabled()),
		slog.Bool("require_client_cert", c.ServerTLS.RequireClientCert),
		slog.Any("allowed_client_ids", c.AllowedClientIDs),
		slog.String("otlp_endpoint", c.OTLPEndpoint),
		slog.String("otlp_token", redact(c.OTLPToken)),
	)
}

func clientTLS(prefix string) ClientTLS {
	return ClientTLS{
		CertFile:   strings.TrimSpace(os.Getenv(prefix + "CERT_FILE")),
		KeyFile:    strings.TrimSpace(os.Getenv(prefix + "KEY_FILE")),
		CAFile:     strings.TrimSpace(os.Getenv(prefix + "CA_FILE")),
		ServerName: strings.TrimSpace(os.Getenv(prefix + "SERVER_NAME")),
	}
}

func validateClientTLS(prefix string, tls ClientTLS) error {
	if (tls.CertFile == "") != (tls.KeyFile == "") {
		return fmt.Errorf("config: %sCERT_FILE and %sKEY_FILE must be set together", prefix, prefix)
	}
	return nil
}

func urlEnv(key, value string) error {
	if !strings.Contains(value, "://") {
		return fmt.Errorf("config: %s=%q needs a scheme, e.g. https://host:port/path", key, value)
	}
	return nil
}

func getenvDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// intEnv/int64Env/boolEnv fail on a malformed value rather than falling back
// to the default. A silently ignored typo in a security switch
// (PAYMENT_TLS_REQUIRE_CLIENT_CERT=flase) would leave the operator believing
// they had changed something they had not.
func intEnv(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid integer: %w", key, raw, err)
	}
	return parsed, nil
}

func int64Env(key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid integer: %w", key, raw, err)
	}
	return parsed, nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("config: %s=%q is not a valid boolean: %w", key, raw, err)
	}
	return parsed, nil
}

func durationEnv(key string, fallback time.Duration, target *time.Duration) error {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		*target = fallback
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("config: %s=%q is not a valid duration (e.g. \"2s\", \"5m\"): %w", key, raw, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("config: %s=%q must be positive", key, raw)
	}
	*target = parsed
	return nil
}

func levelEnv(key string, fallback slog.Level) (slog.Level, error) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch raw {
	case "":
		return fallback, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return fallback, fmt.Errorf("config: %s=%q is not a known level (debug, info, warn, error)", key, raw)
	}
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
