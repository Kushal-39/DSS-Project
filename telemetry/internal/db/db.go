// Package db owns the telemetry service's PostgreSQL access: the pgx
// connection pool and the golang-migrate runner for its audit schema.
//
// The migration files are embedded (go:embed) so the container needs no
// external tooling; DATABASE_URL is the single source of truth for
// connectivity and is never hardcoded. Convention matches the IdP
// (idp/internal/db) so the two services boot and fail the same way.
package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"

	// Register the postgres driver with golang-migrate.
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
)

// migrationsTable is telemetry's own version bookkeeping table.
//
// This matters more than it looks. golang-migrate records applied versions in
// a table called `schema_migrations` by default, and that table is per
// *database*, not per service — but every service in this project runs its own
// migrations against the same shared instance (docs/database.md). The first
// service to boot would write version 1 into the shared table, and the next
// service would then be told "migrations already up to date" and silently skip
// creating its own tables. Telemetry therefore namespaces its bookkeeping, and
// `telemetry_schema_migrations` is the only migration state it ever touches.
const migrationsTable = "telemetry_schema_migrations"

// Connect opens a pgx pool and verifies connectivity, retrying briefly so
// container startup ordering does not matter. A misconfigured DATABASE_URL
// fails fast with a clear error.
func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: invalid DATABASE_URL: %w", err)
	}

	// The collector is write-heavy and read-light, but the read API's summary
	// query runs several aggregates at once. A modest pool is plenty and keeps
	// telemetry from starving the other services of Supabase connections.
	if cfg.MaxConns < 4 {
		cfg.MaxConns = 4
	}
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 10 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: failed to create pool: %w", err)
	}

	const attempts = 30
	var pingErr error
	for i := 1; i <= attempts; i++ {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		pingErr = pool.Ping(pingCtx)
		cancel()
		if pingErr == nil {
			slog.Info("db: connected", "attempt", i)
			return pool, nil
		}
		slog.Warn("db: ping failed, retrying", "attempt", i, "error", pingErr)
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, fmt.Errorf("db: context cancelled while waiting for database: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
	pool.Close()
	return nil, fmt.Errorf("db: database unreachable after %d attempts: %w", attempts, pingErr)
}

// Migrate applies pending up migrations from fsys. It is idempotent: a second
// run reports "no change" and is treated as success, which is what makes the
// container entrypoint safe on every boot.
func Migrate(ctx context.Context, databaseURL string, fsys fs.FS) error {
	src, err := iofs.New(fsys, ".")
	if err != nil {
		return fmt.Errorf("db: failed to open embedded migrations: %w", err)
	}

	dsn, err := withMigrationsTable(databaseURL)
	if err != nil {
		return err
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		return fmt.Errorf("db: failed to init migrate: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Info("db: migrations already up to date")
			return nil
		}
		return fmt.Errorf("db: migration failed: %w", err)
	}
	slog.Info("db: migrations applied", "table", migrationsTable)
	return nil
}

// MigrateDown rolls back every migration this service has applied.
//
// docs/database.md §3 requires a DOWN script for rollbacks, and a script that
// nothing can run is not a rollback path. It is destructive by nature — it
// drops the audit tables — so callers are expected to require explicit
// confirmation before reaching here.
func MigrateDown(ctx context.Context, databaseURL string, fsys fs.FS) error {
	src, err := iofs.New(fsys, ".")
	if err != nil {
		return fmt.Errorf("db: failed to open embedded migrations: %w", err)
	}
	dsn, err := withMigrationsTable(databaseURL)
	if err != nil {
		return err
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		return fmt.Errorf("db: failed to init migrate: %w", err)
	}
	defer m.Close()

	if err := m.Down(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Info("db: no migrations to roll back")
			return nil
		}
		return fmt.Errorf("db: rollback failed: %w", err)
	}
	slog.Info("db: migrations rolled back", "table", migrationsTable)
	return nil
}

// Version reports the migration version this service currently has applied, and
// whether the schema is dirty (a failed migration that needs attention before
// anything else is applied).
func Version(databaseURL string, fsys fs.FS) (uint, bool, error) {
	src, err := iofs.New(fsys, ".")
	if err != nil {
		return 0, false, fmt.Errorf("db: failed to open embedded migrations: %w", err)
	}
	dsn, err := withMigrationsTable(databaseURL)
	if err != nil {
		return 0, false, err
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		return 0, false, fmt.Errorf("db: failed to init migrate: %w", err)
	}
	defer m.Close()

	version, dirty, err := m.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("db: cannot read the schema version: %w", err)
	}
	return version, dirty, nil
}

// withMigrationsTable pins golang-migrate's version table to telemetry's own,
// accepting both URL and keyword/value DSN forms (lib/pq supports both).
func withMigrationsTable(databaseURL string) (string, error) {
	if !strings.Contains(databaseURL, "://") {
		// Keyword/value DSN, e.g. "host=db user=telemetry sslmode=require".
		return strings.TrimSpace(databaseURL) + " x-migrations-table=" + migrationsTable, nil
	}

	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return "", fmt.Errorf("db: invalid DATABASE_URL: %w", err)
	}
	query := parsed.Query()
	if query.Get("x-migrations-table") == "" {
		query.Set("x-migrations-table", migrationsTable)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
