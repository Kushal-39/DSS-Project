// Package config loads and validates the telemetry service's runtime
// configuration from environment variables.
//
// Same rules as the rest of the monorepo (see idp/internal/config): nothing is
// hardcoded, secrets arrive through the git-crypt-encrypted .env file, and a
// missing or malformed required variable aborts startup with a message that
// says how to fix it. A telemetry pipeline that boots with the wrong config is
// worse than one that refuses to boot: it silently records an incomplete
// audit trail, and an incomplete audit trail is a security failure nobody
// notices.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"telemetry/internal/tlsconf"
)

// StoreKind selects the persistence backend.
type StoreKind string

const (
	// StorePostgres is the durable backend and the default.
	StorePostgres StoreKind = "postgres"
	// StoreMemory is an explicit, volatile dev mode for quick demos.
	StoreMemory StoreKind = "memory"
)

// Config is the validated runtime configuration.
type Config struct {
	// Addr is the HTTP listen address (TELEMETRY_ADDR, default ":8088").
	Addr string

	// Store selects the backend (TELEMETRY_STORE, default "postgres").
	Store StoreKind
	// DatabaseURL is the shared PostgreSQL instance (the project's Supabase
	// instance). Under Database-per-Service (docs/database.md §2) telemetry
	// owns the audit_events and spans tables and never reads another service's
	// tables: components feed this pipeline over HTTP, not over SQL.
	DatabaseURL string

	// IngestToken authenticates collectors pushing into the audit pipeline
	// (TELEMETRY_INGEST_TOKEN). Without it anyone who can reach the port can
	// forge, poison or flood the security audit trail.
	IngestToken string
	// InsecureIngest explicitly permits unauthenticated ingestion. Intended
	// only for a throwaway local demo; the service warns loudly when set.
	InsecureIngest bool
	// ReadToken optionally protects the read API and dashboard
	// (TELEMETRY_READ_TOKEN). Empty leaves reads open, which is the small-team
	// default so a reviewer can just open the dashboard in a browser.
	ReadToken string

	// Retention is how far back the store is kept (TELEMETRY_RETENTION,
	// default 720h/30d). Purging runs in the background.
	Retention time.Duration
	// RetentionInterval is how often the purger runs.
	RetentionInterval time.Duration

	// DefaultService labels events whose producer did not name itself.
	DefaultService string

	// ForwardOTLPEndpoint, when set, mirrors received spans to another OTLP
	// collector (e.g. Jaeger's OTLP/HTTP port) so the visual span browser and
	// the audit trace-join view are fed from a single export.
	ForwardOTLPEndpoint string
	// ForwardTimeout bounds a single mirror request.
	ForwardTimeout time.Duration

	// DashboardWindow is the window the dashboard opens with
	// (TELEMETRY_DASHBOARD_WINDOW, default 24h).
	DashboardWindow time.Duration
	// MaxWindow bounds a caller-supplied `window` query parameter so a public
	// read endpoint cannot be used to make the database scan everything.
	MaxWindow time.Duration

	// MaxBodyBytes bounds an ingest payload (TELEMETRY_MAX_BODY_BYTES,
	// default 4 MiB).
	MaxBodyBytes int64

	// ShutdownGrace bounds graceful shutdown (TELEMETRY_SHUTDOWN_GRACE,
	// default 15s).
	ShutdownGrace time.Duration

	// TLS is the Transport Contract half of the audit channel
	// (docs/division.md §2): the collector pushes to this API over TLS 1.3,
	// mutually authenticated against the shared CA. It is empty until the
	// shared CA exists, and the service runs over plain HTTP (bearer token
	// only) until then, like every other component in this repository.
	TLS tlsconf.Settings
}

// Load reads the environment and returns a validated Config.
//
// Required:
//   - DATABASE_URL                 (unless TELEMETRY_STORE=memory)
//   - TELEMETRY_INGEST_TOKEN       (unless TELEMETRY_INSECURE_INGEST=true)
func Load() (*Config, error) {
	cfg := &Config{
		Addr:                getenvDefault("TELEMETRY_ADDR", ":8088"),
		Store:               StoreKind(strings.ToLower(getenvDefault("TELEMETRY_STORE", string(StorePostgres)))),
		DatabaseURL:         os.Getenv("DATABASE_URL"),
		IngestToken:         os.Getenv("TELEMETRY_INGEST_TOKEN"),
		ReadToken:           os.Getenv("TELEMETRY_READ_TOKEN"),
		DefaultService:      getenvDefault("TELEMETRY_DEFAULT_SERVICE", "unknown"),
		ForwardOTLPEndpoint: os.Getenv("TELEMETRY_FORWARD_OTLP_ENDPOINT"),
	}

	switch cfg.Store {
	case StorePostgres, StoreMemory:
	default:
		return nil, fmt.Errorf(
			"config: TELEMETRY_STORE=%q is not a known backend (use \"postgres\" or \"memory\")", cfg.Store)
	}

	if cfg.Store == StorePostgres && cfg.DatabaseURL == "" {
		return nil, fmt.Errorf(
			"config: DATABASE_URL is not set — telemetry needs the shared instance to own its " +
				"audit_events and spans tables (set TELEMETRY_STORE=memory for a throwaway demo)")
	}

	insecure, err := boolEnv("TELEMETRY_INSECURE_INGEST", false)
	if err != nil {
		return nil, err
	}
	cfg.InsecureIngest = insecure

	if cfg.IngestToken == "" && !cfg.InsecureIngest {
		return nil, fmt.Errorf(
			"config: TELEMETRY_INGEST_TOKEN is not set — an unauthenticated ingest endpoint lets " +
				"anyone with network access forge or flood the security audit trail. " +
				"Set it in .env, or set TELEMETRY_INSECURE_INGEST=true for a local demo only")
	}
	if cfg.IngestToken == "" && cfg.InsecureIngest {
		// Left empty on purpose; the server checks InsecureIngest to log a warning.
		cfg.IngestToken = ""
	}

	if cfg.Retention, err = durationEnv("TELEMETRY_RETENTION", 720*time.Hour); err != nil {
		return nil, err
	}
	if cfg.RetentionInterval, err = durationEnv("TELEMETRY_RETENTION_INTERVAL", time.Hour); err != nil {
		return nil, err
	}
	if cfg.ForwardTimeout, err = durationEnv("TELEMETRY_FORWARD_TIMEOUT", 5*time.Second); err != nil {
		return nil, err
	}
	if cfg.DashboardWindow, err = durationEnv("TELEMETRY_DASHBOARD_WINDOW", 24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.MaxWindow, err = durationEnv("TELEMETRY_MAX_WINDOW", 30*24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.ShutdownGrace, err = durationEnv("TELEMETRY_SHUTDOWN_GRACE", 15*time.Second); err != nil {
		return nil, err
	}

	if cfg.MaxBodyBytes, err = intEnv("TELEMETRY_MAX_BODY_BYTES", 4<<20); err != nil {
		return nil, err
	}
	if cfg.MaxBodyBytes <= 0 {
		return nil, fmt.Errorf("config: TELEMETRY_MAX_BODY_BYTES must be positive")
	}

	if cfg.ForwardOTLPEndpoint != "" && !strings.Contains(cfg.ForwardOTLPEndpoint, "://") {
		return nil, fmt.Errorf(
			"config: TELEMETRY_FORWARD_OTLP_ENDPOINT=%q needs a scheme, e.g. http://jaeger:4318",
			cfg.ForwardOTLPEndpoint)
	}

	cfg.TLS = tlsconf.Settings{
		CertFile: strings.TrimSpace(os.Getenv("TELEMETRY_TLS_CERT_FILE")),
		KeyFile:  strings.TrimSpace(os.Getenv("TELEMETRY_TLS_KEY_FILE")),
		CAFile:   strings.TrimSpace(os.Getenv("TELEMETRY_TLS_CA_FILE")),
	}
	if cfg.TLS.RequireClientCert, err = boolEnv("TELEMETRY_TLS_REQUIRE_CLIENT_CERT", false); err != nil {
		return nil, err
	}
	if err := cfg.TLS.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w (set TELEMETRY_TLS_CERT_FILE, TELEMETRY_TLS_KEY_FILE, "+
			"TELEMETRY_TLS_CA_FILE and TELEMETRY_TLS_REQUIRE_CLIENT_CERT together)", err)
	}

	return cfg, nil
}

// RequiresIngestAuth reports whether the ingest endpoints must be authenticated.
func (c *Config) RequiresIngestAuth() bool { return c.IngestToken != "" }

func getenvDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s=%q is not a valid duration (e.g. \"24h\", \"30m\"): %w", key, raw, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("config: %s=%q must be positive", key, raw)
	}
	return parsed, nil
}

func intEnv(key string, fallback int64) (int64, error) {
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
