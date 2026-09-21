package db

import (
	"strings"
	"testing"
)

// TestWithMigrationsTableIsolatesTelemetrysBookkeeping is the regression test
// for a collision the first full-stack run exposed.
//
// golang-migrate records applied versions in `schema_migrations`, which is per
// *database*, while every service in this project runs its own migrations
// against the same shared instance. The first service to boot wrote version 1
// into the shared table, and the next one was told "migrations already up to
// date" and skipped creating its own tables — the IdP failed to seed because
// `credentials` never existed. Namespacing the table is what keeps two
// services from silently cancelling each other's schema.
func TestWithMigrationsTableIsolatesTelemetrysBookkeeping(t *testing.T) {
	if migrationsTable != "telemetry_schema_migrations" {
		t.Fatalf("migrations table = %q; it must not be the generic `schema_migrations` "+
			"that every other service also uses", migrationsTable)
	}

	tests := []struct {
		name string
		dsn  string
		want []string
	}{
		{
			name: "URL form",
			dsn:  "postgres://user:pw@host:5432/postgres",
			want: []string{"x-migrations-table=telemetry_schema_migrations"},
		},
		{
			name: "URL form keeps existing parameters",
			dsn:  "postgres://user:pw@host:5432/postgres?sslmode=disable",
			want: []string{"sslmode=disable", "x-migrations-table=telemetry_schema_migrations"},
		},
		{
			name: "URL form respects an explicit override",
			dsn:  "postgres://user:pw@host:5432/postgres?x-migrations-table=custom_table",
			want: []string{"x-migrations-table=custom_table"},
		},
		{
			name: "keyword/value form",
			dsn:  "host=host user=telemetry sslmode=require",
			want: []string{"x-migrations-table=telemetry_schema_migrations"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := withMigrationsTable(test.dsn)
			if err != nil {
				t.Fatalf("withMigrationsTable: %v", err)
			}
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("dsn = %q, want it to contain %q", got, want)
				}
			}
			if strings.Contains(got, "x-migrations-table=telemetry_schema_migrations") &&
				strings.Contains(test.dsn, "x-migrations-table=custom_table") {
				t.Error("the explicit override was overwritten")
			}
		})
	}
}
