package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"paymentservice/internal/db"
	"paymentservice/migrations"
)

// These tests exercise the parts of the deliverable a fake cannot: the real
// `transactions` schema, the constraints, and the append-only trigger. They need
// a PostgreSQL database that this service is allowed to migrate, and they are
// skipped without one so `go test ./...` stays runnable everywhere.
//
//	PAYMENT_TEST_DATABASE_URL=postgres://... go test ./internal/store/...
//
// A throwaway database is expected: the test drops the table on the way out
// (which is also how the DOWN migration gets exercised). Do not point this at
// the shared Supabase instance.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := strings.TrimSpace(os.Getenv("PAYMENT_TEST_DATABASE_URL"))
	if url == "" {
		t.Skip("set PAYMENT_TEST_DATABASE_URL to run the ledger integration tests")
	}
	return url
}

func TestPostgresLedgerSchemaAndImmutability(t *testing.T) {
	databaseURL := testDatabaseURL(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := db.Migrate(ctx, databaseURL, migrations.FS); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	// The rollback path is part of the deliverable (docs/database.md §3), and
	// running it here also cleans up the rows the immutability trigger refuses
	// to let us delete.
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := db.MigrateDown(cleanupCtx, databaseURL, migrations.FS); err != nil {
			t.Errorf("migrate down: %v", err)
		}
	})

	version, dirty, err := db.Version(databaseURL, migrations.FS)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if version == 0 || dirty {
		t.Fatalf("version = %d dirty = %v, want a clean applied schema", version, dirty)
	}

	pool, err := db.Connect(ctx, databaseURL, 2)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	ledger := NewPostgres(pool)

	entry := Transaction{
		TxnID:      "11111111-2222-4333-8444-555555555555",
		SenderID:   "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		ReceiverID: "8f9619ff-8b86-d011-b42d-00c04fc964fa",
		Amount:     amount(t, "50.00"),
	}

	recorded, err := ledger.RecordTransaction(ctx, entry)
	if err != nil {
		t.Fatalf("RecordTransaction: %v", err)
	}
	// The timestamp comes back from the database, not from this process.
	if recorded.CreatedAt.IsZero() {
		t.Error("the ledger must return the timestamp it recorded")
	}

	// The primary key is real.
	if _, err := ledger.RecordTransaction(ctx, entry); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate insert error = %v, want ErrDuplicate", err)
	}

	// The amount is stored exactly, as NUMERIC.
	var stored string
	if err := pool.QueryRow(ctx, `SELECT amount::text FROM transactions WHERE txn_id = $1::uuid`,
		entry.TxnID).Scan(&stored); err != nil {
		t.Fatalf("read the amount back: %v", err)
	}
	if stored != "50.00" {
		t.Errorf("stored amount = %q, want 50.00", stored)
	}

	// ---- immutability ---------------------------------------------------
	//
	// docs/contacts.md calls this an immutable ledger. Documentation is not an
	// enforcement mechanism, so the table refuses to change.
	if _, err := pool.Exec(ctx, `UPDATE transactions SET amount = 999.99 WHERE txn_id = $1::uuid`,
		entry.TxnID); err == nil {
		t.Error("UPDATE must be refused: an editable ledger is not evidence")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("the refusal must explain itself, got: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM transactions WHERE txn_id = $1::uuid`, entry.TxnID); err == nil {
		t.Error("DELETE must be refused")
	}
	if _, err := pool.Exec(ctx, `TRUNCATE transactions`); err == nil {
		t.Error("TRUNCATE must be refused")
	}

	// ---- the constraints the API also enforces --------------------------

	for name, statement := range map[string]string{
		"zero amount": `INSERT INTO transactions (txn_id, sender_id, receiver_id, amount)
		                VALUES (gen_random_uuid(), '6f9619ff-8b86-d011-b42d-00c04fc964ff',
			                '8f9619ff-8b86-d011-b42d-00c04fc964fa', 0)`,
		"negative amount": `INSERT INTO transactions (txn_id, sender_id, receiver_id, amount)
		                    VALUES (gen_random_uuid(), '6f9619ff-8b86-d011-b42d-00c04fc964ff',
		                            '8f9619ff-8b86-d011-b42d-00c04fc964fa', -1)`,
		"self transfer": `INSERT INTO transactions (txn_id, sender_id, receiver_id, amount)
		                  VALUES (gen_random_uuid(), '6f9619ff-8b86-d011-b42d-00c04fc964ff',
		                          '6f9619ff-8b86-d011-b42d-00c04fc964ff', 1)`,
	} {
		if _, err := pool.Exec(ctx, statement); err == nil {
			t.Errorf("%s must violate a constraint", name)
		}
	}

	// The row is still there, unchanged, after every refusal above.
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM transactions WHERE txn_id = $1::uuid`,
		entry.TxnID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("rows = %d, want the original row to survive", count)
	}
}
