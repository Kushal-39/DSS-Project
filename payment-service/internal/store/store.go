// Package store is this service's access to its own ledger: the `transactions`
// table from docs/contacts.md.
//
// Database-per-Service (docs/database.md §2) is the rule that shapes this
// package's whole surface. This service:
//
//   - owns `transactions` and reads nothing else in the shared instance;
//   - never reads `accounts` (Person 4's) or `credentials` (Person 1's);
//   - answers "does this user exist / have funds" by calling the Account
//     Service, never by a join.
//
// That is why the interface below has exactly one write method and a Ping:
// there is nothing else this service is entitled to do with a database.
package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"paymentservice/internal/money"
)

// ErrDuplicate is returned when a ledger row with the same primary key already
// exists. The transaction id is generated per request, so this indicates a
// retry of an already-recorded transfer rather than a routine conflict.
var ErrDuplicate = errors.New("transaction already recorded")

// Transaction is one immutable ledger entry.
type Transaction struct {
	// TxnID is the ledger's primary key (UUID).
	TxnID string
	// SenderID is the account being debited.
	SenderID string
	// ReceiverID is the account being credited.
	ReceiverID string
	// Amount is the exact transferred sum.
	Amount money.Amount
	// CreatedAt is the timestamp the *database* assigned. It is returned from
	// the insert rather than generated in the application, so the ledger's
	// ordering is the database's and survives clock drift between replicas.
	CreatedAt time.Time
}

// Store is the ledger.
type Store interface {
	// RecordTransaction appends one entry. It must never update or delete:
	// the table is append-only at the database level as well (see
	// migrations/001_init.up.sql).
	RecordTransaction(ctx context.Context, txn Transaction) (Transaction, error)
	// Ping reports whether the ledger is reachable, for the readiness probe.
	Ping(ctx context.Context) error
	// Kind names the backend, for startup logging.
	Kind() string
	// Close releases resources.
	Close()
}

// Memory is an in-process Store used when PAYMENT_STORE=memory.
//
// It exists so the end-to-end path (mTLS → JWT → policy → deduct → ledger) can
// be exercised on a machine with no database credentials, the same way
// telemetry's memory store does. It is explicitly not durable, and the service
// says so on every boot.
type Memory struct {
	mu      sync.RWMutex
	entries map[string]Transaction
}

// NewMemory builds an empty in-memory ledger.
func NewMemory() *Memory {
	return &Memory{entries: map[string]Transaction{}}
}

// Kind implements Store.
func (m *Memory) Kind() string { return "memory" }

// Ping implements Store.
func (m *Memory) Ping(context.Context) error { return nil }

// Close implements Store.
func (m *Memory) Close() {}

// RecordTransaction implements Store.
//
// The same validation runs here as in the durable backend: a demo mode that
// accepts an entry the real ledger would refuse is a demo that hides a bug.
func (m *Memory) RecordTransaction(_ context.Context, txn Transaction) (Transaction, error) {
	if err := txn.Validate(); err != nil {
		return Transaction{}, err
	}
	if txn.CreatedAt.IsZero() {
		txn.CreatedAt = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[txn.TxnID]; exists {
		return Transaction{}, fmt.Errorf("%w: %s", ErrDuplicate, txn.TxnID)
	}
	m.entries[txn.TxnID] = txn
	return txn, nil
}

// Entries returns the ledger in insertion order (by CreatedAt, then id). It is
// used by tests and by the CLI's verification helper; the API never reads it.
func (m *Memory) Entries() []Transaction {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Transaction, 0, len(m.entries))
	for _, txn := range m.entries {
		out = append(out, txn)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].TxnID < out[j].TxnID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// Validate checks a transaction before it reaches a backend, so a malformed
// record is refused by the service rather than by a database constraint whose
// error message names a column instead of a cause.
func (t Transaction) Validate() error {
	if strings.TrimSpace(t.TxnID) == "" {
		return errors.New("store: a transaction id is required")
	}
	if strings.TrimSpace(t.SenderID) == "" || strings.TrimSpace(t.ReceiverID) == "" {
		return errors.New("store: sender and receiver are required")
	}
	if t.Amount.IsZero() {
		return errors.New("store: a transaction amount must be greater than zero")
	}
	return nil
}
