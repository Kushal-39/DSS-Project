// Package db owns this service's PostgreSQL access: the pgx connection pool and
// the golang-migrate runner for its ledger schema.
//
// The migration files are embedded (go:embed) so the container needs no
// external tooling, and DATABASE_URL is the single source of truth for
// connectivity — never hardcoded (docs/database.md §5). The conventions match
// idp/internal/db and telemetry/internal/db so every service in this repository
// boots and fails the same way.
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

// migrationsTable is this service's own version bookkeeping table.
//
// This matters more than it looks. golang-migrate records applied versions in a
// table called `schema_migrations` by default, and that table is per
// *database*, not per service — but every service in this project migrates the
// same shared instance (docs/database.md §1). The first service to boot would
// write version 1 into the shared table, and the next service would be told
// "migrations already up to date" and silently skip creating its own tables.
// Telemetry hit this first and documented it (telemetry/README.md §5);
// `payment_schema_migrations` is the only migration state this service touches.
const migrationsTable = "payment_schema_migrations"

// Connect opens a pgx pool and verifies connectivity, retrying briefly so
// container startup ordering does not matter. A misconfigured DATABASE_URL
// fails fast with a clear error.
func Connect(ctx context.Context, databaseURL string, maxConns int) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: invalid DATABASE_URL: %w", err)
	}

	// The shared instance is used by five services. A bounded pool keeps one
	// busy service from consuming every Supabase connection.
	if maxConns > 0 {
		config.MaxConns = int32(maxConns)
	}
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 10 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("db: failed to create pool: %w", err)
	}

	const attempts = 30
	var pingErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		pingErr = pool.Ping(pingCtx)
		cancel()
		if pingErr == nil {
			slog.Info("db: connected", "attempt", attempt)
			return pool, nil
		}
		slog.Warn("db: ping failed, retrying", "attempt", attempt, "error", pingErr)
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, fmt.Errorf("db: context cancelled while waiting for the database: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
	pool.Close()
	return nil, fmt.Errorf("db: database unreachable after %d attempts: %w", attempts, pingErr)
}

// Migrate applies all pending up migrations from fsys. It is idempotent: a
// second run reports "no change" and is treated as success, which is what makes
// the container entrypoint safe on every boot (docs/database.md §4).
func Migrate(ctx context.Context, databaseURL string, fsys fs.FS) error {
	migrator, err := newMigrator(databaseURL, fsys)
	if err != nil {
		return err
	}
	defer migrator.Close()

	if err := migrator.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Info("db: migrations already up to date", "table", migrationsTable)
			return nil
		}
		return fmt.Errorf("db: migration failed: %w", err)
	}
	slog.Info("db: migrations applied", "table", migrationsTable)
	return nil
}

// MigrateDown rolls back every migration this service has applied.
//
// docs/database.md §3 requires a DOWN script for rollbacks, and a script nothing
// can run is not a rollback path. It is destructive by nature — it drops the
// ledger — so the CLI requires an explicit confirmation before reaching it.
func MigrateDown(ctx context.Context, databaseURL string, fsys fs.FS) error {
	migrator, err := newMigrator(databaseURL, fsys)
	if err != nil {
		return err
	}
	defer migrator.Close()

	if err := migrator.Down(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			slog.Info("db: no migrations to roll back")
			return nil
		}
		return fmt.Errorf("db: rollback failed: %w", err)
	}
	slog.Info("db: migrations rolled back", "table", migrationsTable)
	return nil
}

// Version reports the migration version this service has applied and whether
// the schema is dirty (a failed migration that needs attention first).
func Version(databaseURL string, fsys fs.FS) (uint, bool, error) {
	migrator, err := newMigrator(databaseURL, fsys)
	if err != nil {
		return 0, false, err
	}
	defer migrator.Close()

	version, dirty, err := migrator.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("db: cannot read the schema version: %w", err)
	}
	return version, dirty, nil
}

func newMigrator(databaseURL string, fsys fs.FS) (*migrate.Migrate, error) {
	source, err := iofs.New(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("db: failed to open embedded migrations: %w", err)
	}
	dsn, err := withMigrationsTable(databaseURL)
	if err != nil {
		return nil, err
	}
	migrator, err := migrate.NewWithSourceInstance("iofs", source, dsn)
	if err != nil {
		return nil, fmt.Errorf("db: failed to init migrate: %w", err)
	}
	return migrator, nil
}

// withMigrationsTable pins golang-migrate's version table to this service's own,
// accepting both URL and keyword/value DSN forms (lib/pq supports both).
func withMigrationsTable(databaseURL string) (string, error) {
	if !strings.Contains(databaseURL, "://") {
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
