// Command telemetry is Person 6's service: the central audit logging consumer,
// the OTLP span receiver, and the audit dashboard (docs/division.md).
//
// Subcommands, mirroring the IdP's lifecycle (idp/cmd/server):
//
//	telemetry migrate   apply the audit schema (idempotent)
//	telemetry migrate down --yes   roll the audit schema back (destructive)
//	telemetry migrate status      report the applied schema version
//	telemetry serve     run the ingest + read API and the dashboard
//
// The container entrypoint runs `migrate` then `serve`, as docs/database.md §4
// requires.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"telemetry/internal/api"
	"telemetry/internal/config"
	"telemetry/internal/db"
	"telemetry/internal/otlp"
	"telemetry/internal/store"
	"telemetry/migrations"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(logger)

	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch command {
	case "serve":
		err = runServe(ctx, logger)
	case "migrate":
		err = runMigrate(ctx, logger, os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "telemetry: unknown command %q\n\n", command)
		usage()
		os.Exit(2)
	}

	if err != nil {
		// Same event name as the IdP's fatal path, so a crash in either
		// service is classified identically by the pipeline.
		logger.Error("fatal", "command", command, "error", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `telemetry — Zero-Trust audit pipeline (Person 6)

Usage:
  telemetry migrate    Apply the pending audit schema migrations.
  telemetry serve      Run the ingest API, read API and audit dashboard.
  telemetry help       Show this message.

Environment (see .env.example):
  DATABASE_URL                      PostgreSQL connection string (telemetry's own schema)
  TELEMETRY_ADDR                    HTTP listen address (default :8088)
  TELEMETRY_STORE                   postgres | memory (default postgres)
  TELEMETRY_INGEST_TOKEN            bearer token required from collectors
  TELEMETRY_READ_TOKEN              optional token for the read API and dashboard
  TELEMETRY_RETENTION               how long audit rows are kept (default 720h)
  TELEMETRY_FORWARD_OTLP_ENDPOINT   mirror spans to another collector (e.g. http://jaeger:4318)
`)
}

// runMigrate applies, rolls back or reports the audit schema.
//
// A rollback drops the audit tables, so it needs an explicit --yes: an operator
// who mistypes a subcommand should not discover it from an empty audit trail.
func runMigrate(ctx context.Context, logger *slog.Logger, args []string) error {
	action := "up"
	if len(args) > 0 {
		action = strings.ToLower(strings.TrimSpace(args[0]))
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.Store == config.StoreMemory {
		logger.Info("migrate: skipped", "store", "memory", "detail", "the in-memory store has no schema")
		return nil
	}

	switch action {
	case "up", "":
		return migrateUp(ctx, cfg, logger)
	case "down":
		if !hasFlag(args[1:], "--yes") {
			return fmt.Errorf("migrate down drops the audit_events and spans tables. " +
				"Re-run with --yes if that is what you want")
		}
		return migrateDown(ctx, cfg, logger)
	case "status", "version":
		return migrateStatus(cfg, logger)
	default:
		return fmt.Errorf("migrate: unknown action %q (use up, down --yes, or status)", action)
	}
}

func hasFlag(args []string, flag string) bool {
	for _, arg := range args {
		if strings.EqualFold(arg, flag) {
			return true
		}
	}
	return false
}

func migrateStatus(cfg *config.Config, logger *slog.Logger) error {
	version, dirty, err := db.Version(cfg.DatabaseURL, migrations.FS)
	if err != nil {
		return err
	}
	logger.Info("migrate: status", "version", version, "dirty", dirty)
	if dirty {
		return fmt.Errorf("migrate: the schema is dirty at version %d: a previous migration failed "+
			"and must be resolved (force a version, or roll back) before anything else is applied", version)
	}
	return nil
}

func migrateDown(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	logger.Warn("migrate: rolling back every migration", "table", "telemetry_schema_migrations")
	if err := db.MigrateDown(ctx, cfg.DatabaseURL, migrations.FS); err != nil {
		return err
	}
	logger.Info("migrate: rollback complete")
	return nil
}

func migrateUp(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	logger.Info("migrate: starting")

	// The entrypoint migrates before it serves, so a database that is still
	// accepting connections has to be survivable: Compose does not order a
	// plain `up`, and a shared instance can blip. golang-migrate records each
	// migration as it applies it, so retrying is safe and can only help —
	// unlike starting up with a missing audit table, which would drop every
	// decision the pipeline was supposed to record.
	const attempts = 10
	var migrateErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if migrateErr = db.Migrate(ctx, cfg.DatabaseURL, migrations.FS); migrateErr == nil {
			logger.Info("migrate: complete", "attempt", attempt)
			return nil
		}
		logger.Warn("migrate: attempt failed, retrying", "attempt", attempt, "error", migrateErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("migrate: database unreachable or schema unapplied after %d attempts: %w", attempts, migrateErr)
}

func runServe(ctx context.Context, logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if cfg.InsecureIngest && cfg.IngestToken == "" {
		logger.Warn("ingest_auth_disabled",
			"detail", "TELEMETRY_INSECURE_INGEST=true — anyone who can reach the ingest port "+
				"can forge or flood the audit trail. Never use this outside a local demo.")
	}
	if cfg.ReadToken == "" {
		logger.Warn("read_auth_disabled",
			"detail", "TELEMETRY_READ_TOKEN is unset, so the audit read API and dashboard are open")
	}

	auditStore, closeStore, err := openStore(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer closeStore()

	var forwarder api.SpanForwarder
	if cfg.ForwardOTLPEndpoint != "" {
		forwarder = otlp.NewForwarder(cfg.ForwardOTLPEndpoint, cfg.ForwardTimeout)
		logger.Info("otlp_forwarding", "endpoint", cfg.ForwardOTLPEndpoint)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.New(logger, cfg, auditStore, forwarder, nil).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	// The Transport Contract path (docs/division.md §2). Absent settings mean
	// plain HTTP, which is what the rest of the stack does today; present ones
	// mean the ingest API only answers TLS 1.3 peers, and verifies the
	// collector's certificate when asked to.
	tlsConfig, err := cfg.TLS.Server()
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	server.TLSConfig = tlsConfig

	// Retention: an audit trail that grows forever eventually takes the system
	// down, which is itself an availability failure. Purge on the configured
	// window (0 disables it, for an installation that ships to cold storage).
	if cfg.Retention > 0 {
		go purgeLoop(ctx, cfg, auditStore, logger)
	}

	scheme, clientAuth := "http", "none"
	if tlsConfig != nil {
		scheme = "https"
		clientAuth = tlsClientAuthName(tlsConfig.ClientAuth)
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("serve: listening", "addr", server.Addr, "scheme", scheme, "client_auth", clientAuth, "store", string(cfg.Store))
		// ListenAndServeTLS with the certificates already in TLSConfig: the
		// files are read once, at startup, so a certificate that vanishes
		// mid-run cannot silently downgrade the channel.
		var err error
		if tlsConfig != nil {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("serve: shutting down", "grace", cfg.ShutdownGrace.String())
	}

	// Drain in-flight ingest requests: losing a batch of decisions on shutdown
	// would leave a hole in the audit trail exactly when something interesting
	// (a restart) is happening.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("serve: graceful shutdown failed: %w", err)
	}
	logger.Info("serve: stopped")
	return nil
}

// tlsClientAuthName renders the listener's client-certificate policy for the
// startup log, so "is mTLS actually on?" is answerable without reading config.
func tlsClientAuthName(auth tls.ClientAuthType) string {
	switch auth {
	case tls.RequireAndVerifyClientCert:
		return "required"
	case tls.VerifyClientCertIfGiven:
		return "verified-if-given"
	default:
		return "none"
	}
}

func openStore(ctx context.Context, cfg *config.Config, logger *slog.Logger) (store.Store, func(), error) {
	if cfg.Store == config.StoreMemory {
		logger.Warn("store_in_memory",
			"detail", "TELEMETRY_STORE=memory — the audit trail is volatile and dies with the process")
		return store.NewMemory(), func() {}, nil
	}

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	return store.NewPostgres(pool), pool.Close, nil
}

// purgeLoop enforces the retention window.
func purgeLoop(ctx context.Context, cfg *config.Config, auditStore store.Store, logger *slog.Logger) {
	run := func() {
		cutoff := time.Now().UTC().Add(-cfg.Retention)
		purgeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()

		removed, err := auditStore.Purge(purgeCtx, cutoff)
		if err != nil {
			logger.Warn("purge_failed", "error", err)
			return
		}
		if !removed.Empty() {
			// The two tables are named separately: a sweep that removed one
			// decision and one span is not the same event as one that removed
			// two decisions, and a single total cannot tell you which happened.
			logger.Info("purge_complete",
				"removed_events", removed.Events,
				"removed_spans", removed.Spans,
				"older_than", cutoff)
		}
	}

	run()
	ticker := time.NewTicker(cfg.RetentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func logLevel() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TELEMETRY_LOG_LEVEL"))) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
