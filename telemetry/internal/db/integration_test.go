package db

import (
	"context"
	"os"
	"testing"
	"time"

	"telemetry/migrations"
)

// TestMigrateDownAndVersionAgainstPostgres is the end-to-end test for the
// rollback and status paths.
//
// It is double-gated, deliberately. TELEMETRY_TEST_DATABASE_URL marks a
// throwaway database (the same variable the store test uses), and
// TELEMETRY_TEST_DESTRUCTIVE=1 acknowledges that this one *drops tables*. A
// rollback test that could be pointed at the live audit trail by reaching for
// the variable that is already set would be a footgun, not a test.
//
//	TELEMETRY_TEST_DATABASE_URL=postgres://.../throwaway?sslmode=disable \
//	TELEMETRY_TEST_DESTRUCTIVE=1 go test ./internal/db/...
//
// What it proves, in the order an operator would care:
//
//  1. `telemetry migrate` is idempotent, so the container entrypoint can run it
//     on every boot (docs/database.md §4).
//  2. `telemetry migrate status` reports the applied version, and reports it
//     without a running migration, which is what makes it usable as a
//     pre-flight check.
//  3. The DOWN script is real: 001_init.down.sql exists, runs, and leaves no
//     table behind. docs/database.md §3 requires a rollback script; a script
//     nothing can execute is not a rollback path.
//  4. Rolling back removes telemetry's version bookkeeping rows but not its
//     namespaced table, and re-running `up` afterwards restores the schema — so
//     a mistaken rollout is recoverable in both directions.
//
// The database is left migrated up, so a subsequent run (or a service pointed
// at the same throwaway instance) starts from a working schema.
func TestMigrateDownAndVersionAgainstPostgres(t *testing.T) {
	databaseURL := os.Getenv("TELEMETRY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set TELEMETRY_TEST_DATABASE_URL to a throwaway database to run the migration integration test")
	}
	if os.Getenv("TELEMETRY_TEST_DESTRUCTIVE") != "1" {
		t.Skip("this test drops the audit tables: set TELEMETRY_TEST_DESTRUCTIVE=1 and point " +
			"TELEMETRY_TEST_DATABASE_URL at a throwaway database to run it")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Whatever happens below, leave the schema applied: an aborted run must not
	// turn into a puzzling failure for the next one.
	t.Cleanup(func() {
		restore, restoreCancel := context.WithTimeout(context.Background(), time.Minute)
		defer restoreCancel()
		if err := Migrate(restore, databaseURL, migrations.FS); err != nil {
			t.Errorf("cleanup: could not re-apply the schema: %v", err)
		}
	})

	t.Run("up is idempotent and status reports the version", func(t *testing.T) {
		if err := Migrate(ctx, databaseURL, migrations.FS); err != nil {
			t.Fatalf("first Migrate: %v", err)
		}
		// The entrypoint migrates on every boot: a second run must report
		// "no change" and still succeed.
		if err := Migrate(ctx, databaseURL, migrations.FS); err != nil {
			t.Fatalf("second Migrate (must be a no-op, not an error): %v", err)
		}

		version, dirty, err := Version(databaseURL, migrations.FS)
		if err != nil {
			t.Fatalf("Version: %v", err)
		}
		if version != 1 {
			t.Errorf("version = %d, want 1 (the highest embedded migration)", version)
		}
		if dirty {
			t.Error("a cleanly applied schema is reported dirty")
		}

		if !tableExists(t, databaseURL, "audit_events") {
			t.Error("audit_events is missing after `migrate up`")
		}
		if !tableExists(t, databaseURL, "spans") {
			t.Error("spans is missing after `migrate up`")
		}
		if !tableExists(t, databaseURL, migrationsTable) {
			t.Errorf("%s is missing: without it a re-run cannot tell what is applied", migrationsTable)
		}
	})

	t.Run("down removes the schema and up restores it", func(t *testing.T) {
		if err := MigrateDown(ctx, databaseURL, migrations.FS); err != nil {
			t.Fatalf("MigrateDown: %v", err)
		}

		version, dirty, err := Version(databaseURL, migrations.FS)
		if err != nil {
			t.Fatalf("Version after down: %v", err)
		}
		if version != 0 || dirty {
			t.Errorf("version = %d dirty = %v after a full rollback, want 0 false", version, dirty)
		}

		// The down script only drops what the up script created. Anything left
		// here means the two have drifted apart.
		for _, table := range []string{"audit_events", "spans"} {
			if tableExists(t, databaseURL, table) {
				t.Errorf("%s survived the rollback: the down script does not match the up script", table)
			}
		}
		// telemetry's own bookkeeping stays (golang-migrate owns it), but must
		// not still claim a version.
		if !tableExists(t, databaseURL, migrationsTable) {
			t.Errorf("%s was dropped by the rollback; it belongs to the migration runner", migrationsTable)
		}

		// A second rollback with nothing applied is "no change", not a failure.
		if err := MigrateDown(ctx, databaseURL, migrations.FS); err != nil {
			t.Errorf("a rollback with nothing left to roll back returned an error: %v", err)
		}

		// And it is recoverable: the point of a rollback path.
		if err := Migrate(ctx, databaseURL, migrations.FS); err != nil {
			t.Fatalf("Migrate after rollback: %v", err)
		}
		if !tableExists(t, databaseURL, "audit_events") {
			t.Error("audit_events did not come back after re-migrating")
		}
		version, dirty, err = Version(databaseURL, migrations.FS)
		if err != nil {
			t.Fatalf("Version after re-migrating: %v", err)
		}
		if version != 1 || dirty {
			t.Errorf("version = %d dirty = %v after re-migrating, want 1 false", version, dirty)
		}
	})
}

// tableExists asks PostgreSQL's own catalogue rather than trusting the absence
// of an error from a query against the table.
func tableExists(t *testing.T, databaseURL, table string) bool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
		t.Fatalf("to_regclass(%q): %v", table, err)
	}
	return exists
}
