// Package db owns the IdP's PostgreSQL access: a pgx connection pool, the
// golang-migrate runner for schema migrations, and the seed executor for
// bootstrap users.
//
// The migration runner is embedded (go:embed) so the container needs no
// external tooling — see migrations.FS. The DATABASE_URL is the single
// source of truth for connectivity and is never hardcoded.
package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"

	// Register the postgres driver with golang-migrate.
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
)

// Connect opens a pgx connection pool and verifies connectivity, retrying
// briefly so the container tolerates Compose startup ordering. A
// misconfigured DATABASE_URL fails fast with a clear error.
func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: invalid DATABASE_URL: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: failed to create pool: %w", err)
	}

	// Retry the initial ping for up to ~30s. Supabase can be slow to accept
	// a first connection and Compose does not guarantee ordering.
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

// Migrate applies all pending up migrations from fsys against databaseURL.
// It is idempotent: a second run reports "no change" and is treated as
// success, which is what makes the container entrypoint safe on every boot.
func Migrate(ctx context.Context, databaseURL string, fsys fs.FS) error {
	src, err := iofs.New(fsys, ".")
	if err != nil {
		return fmt.Errorf("db: failed to open embedded migrations: %w", err)
	}

	migrationURL, err := url.Parse(databaseURL)
	if err != nil {
		return err
	}
	query := migrationURL.Query()
	query.Set("x-migrations-table", "idp_schema_migrations")
	migrationURL.RawQuery = query.Encode()
	m, err := migrate.NewWithSourceInstance("iofs", src, migrationURL.String())
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
	slog.Info("db: migrations applied")
	return nil
}

// Seed executes the embedded bootstrap script (migrations/seed.sql) as a
// single simple-protocol query. pgx routes a no-argument Exec through the
// simple protocol, which lets PostgreSQL parse comments and multiple
// statements itself — no fragile client-side splitting. The script is
// idempotent (INSERT ... ON CONFLICT DO NOTHING) and safe on every boot.
func Seed(ctx context.Context, pool *pgxpool.Pool, seedSQL string) error {
	if _, err := pool.Exec(ctx, seedSQL); err != nil {
		return fmt.Errorf("db: seed script failed: %w", err)
	}
	slog.Info("db: seed applied")
	return nil
}
