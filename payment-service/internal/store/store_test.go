package store

import (
	"context"
	"errors"
	"testing"

	"paymentservice/internal/money"
)

func amount(t *testing.T, value string) money.Amount {
	t.Helper()
	parsed, err := money.Parse(value)
	if err != nil {
		t.Fatalf("Parse(%q): %v", value, err)
	}
	return parsed
}

func TestMemoryRecordsAndStampsTheTransaction(t *testing.T) {
	ledger := NewMemory()
	recorded, err := ledger.RecordTransaction(context.Background(), Transaction{
		TxnID:      "11111111-2222-4333-8444-555555555555",
		SenderID:   "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		ReceiverID: "8f9619ff-8b86-d011-b42d-00c04fc964fa",
		Amount:     amount(t, "50.00"),
	})
	if err != nil {
		t.Fatalf("RecordTransaction: %v", err)
	}
	if recorded.CreatedAt.IsZero() {
		t.Error("a recorded entry must carry the timestamp it was recorded at")
	}
	if entries := ledger.Entries(); len(entries) != 1 || entries[0].TxnID != recorded.TxnID {
		t.Fatalf("entries = %+v", entries)
	}
	if ledger.Kind() != "memory" {
		t.Errorf("Kind = %q", ledger.Kind())
	}
	if err := ledger.Ping(context.Background()); err != nil {
		t.Errorf("Ping: %v", err)
	}
	ledger.Close()
}

// A ledger that accepts the same transaction twice is not a ledger.
func TestMemoryRefusesADuplicatePrimaryKey(t *testing.T) {
	ledger := NewMemory()
	entry := Transaction{
		TxnID:      "11111111-2222-4333-8444-555555555555",
		SenderID:   "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		ReceiverID: "8f9619ff-8b86-d011-b42d-00c04fc964fa",
		Amount:     amount(t, "50.00"),
	}
	if _, err := ledger.RecordTransaction(context.Background(), entry); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := ledger.RecordTransaction(context.Background(), entry); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second insert error = %v, want ErrDuplicate", err)
	}
	if entries := ledger.Entries(); len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
}

func TestValidateRefusesAnEntryThatCannotBeEvidence(t *testing.T) {
	valid := Transaction{
		TxnID:      "11111111-2222-4333-8444-555555555555",
		SenderID:   "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		ReceiverID: "8f9619ff-8b86-d011-b42d-00c04fc964fa",
		Amount:     amount(t, "50.00"),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a complete transaction must validate: %v", err)
	}

	cases := map[string]func(Transaction) Transaction{
		"no id":       func(txn Transaction) Transaction { txn.TxnID = ""; return txn },
		"no sender":   func(txn Transaction) Transaction { txn.SenderID = ""; return txn },
		"no receiver": func(txn Transaction) Transaction { txn.ReceiverID = ""; return txn },
		"zero amount": func(txn Transaction) Transaction { txn.Amount = money.Zero; return txn },
	}
	for name, mutate := range cases {
		if err := mutate(valid).Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}

	// The memory backend refuses a malformed entry too, so the rule holds even
	// when the database's constraints are not in play.
	ledger := NewMemory()
	if _, err := ledger.RecordTransaction(context.Background(), mutateZero(valid)); err == nil {
		t.Error("the memory ledger must refuse an entry with no amount")
	}
}

func mutateZero(txn Transaction) Transaction {
	txn.Amount = money.Zero
	return txn
}
