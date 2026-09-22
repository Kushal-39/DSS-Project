package db

import (
	"net/url"
	"strings"
	"testing"
)

// golang-migrate's default `schema_migrations` table is per-database, and five
// services migrate the same shared instance (docs/database.md §1). Without the
// namespace, the first service to boot makes every other service skip its own
// migrations — silently, and with a "migrations already up to date" message
// that looks like success.
func TestMigrationsTableIsNamespaced(t *testing.T) {
	if migrationsTable == "schema_migrations" {
		t.Fatal("the migrations table must be namespaced per service")
	}
	if !strings.HasPrefix(migrationsTable, "payment_") {
		t.Errorf("migrationsTable = %q, want a payment_* name", migrationsTable)
	}
}

func TestWithMigrationsTableHandlesURLDSNs(t *testing.T) {
	dsn, err := withMigrationsTable("postgres://user:pass@host:5432/postgres?sslmode=require")
	if err != nil {
		t.Fatalf("withMigrationsTable: %v", err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("the returned DSN is not a URL: %v", err)
	}
	if got := parsed.Query().Get("x-migrations-table"); got != migrationsTable {
		t.Errorf("x-migrations-table = %q, want %q", got, migrationsTable)
	}
	if parsed.Query().Get("sslmode") != "require" {
		t.Error("the existing query parameters must be preserved")
	}
}

func TestWithMigrationsTablePreservesAnExplicitOverride(t *testing.T) {
	dsn, err := withMigrationsTable("postgres://user:pass@host:5432/postgres?x-migrations-table=custom")
	if err != nil {
		t.Fatalf("withMigrationsTable: %v", err)
	}
	if !strings.Contains(dsn, "x-migrations-table=custom") {
		t.Errorf("an explicit override must be honoured: %s", dsn)
	}
}

func TestWithMigrationsTableHandlesKeywordValueDSNs(t *testing.T) {
	dsn, err := withMigrationsTable("host=localhost user=payment sslmode=require")
	if err != nil {
		t.Fatalf("withMigrationsTable: %v", err)
	}
	if !strings.HasSuffix(dsn, "x-migrations-table="+migrationsTable) {
		t.Errorf("dsn = %q", dsn)
	}
}
