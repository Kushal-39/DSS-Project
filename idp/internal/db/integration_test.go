package db

import (
	"context"
	"os"
	"testing"
	"time"

	"idp/internal/auth"
	"idp/migrations"
)

func TestMigrationIsolationSeedAndRollbackAgainstPostgres(t *testing.T) {
	databaseURL := os.Getenv("IDP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set IDP_TEST_DATABASE_URL to a disposable database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Simulate another service having already migrated this shared database.
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, dirty BOOLEAN NOT NULL); INSERT INTO schema_migrations VALUES (99,false) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	seed, err := migrations.FS.ReadFile("seed.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, databaseURL, migrations.FS); err != nil {
			t.Fatal(err)
		}
		if err := Seed(ctx, pool, string(seed)); err != nil {
			t.Fatal(err)
		}
	}
	var count, version int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM credentials`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("bootstrap count = %d", count)
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM idp_schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("IdP version = %d", version)
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 99 {
		t.Fatal("IdP changed another service's bookkeeping")
	}
	for username, password := range map[string]string{"admin": "admin123", "customer": "customer123"} {
		var hash string
		if err := pool.QueryRow(ctx, `SELECT password_hash FROM credentials WHERE username=$1`, username).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		if !auth.VerifyPassword(password, hash) {
			t.Fatalf("invalid bootstrap hash for %s", username)
		}
	}
	down, err := migrations.FS.ReadFile("001_init.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('credentials') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("credentials survived rollback")
	}
	if _, err := pool.Exec(ctx, `DROP TABLE idp_schema_migrations`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, databaseURL, migrations.FS); err != nil {
		t.Fatal(err)
	}
	if err := Seed(ctx, pool, string(seed)); err != nil {
		t.Fatal(err)
	}
}
