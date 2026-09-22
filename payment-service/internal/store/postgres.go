package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"paymentservice/internal/config"
	"paymentservice/internal/db"
)

// Postgres is the durable ledger.
type Postgres struct {
	pool *pgxpool.Pool
}

// Open builds the configured Store.
//
// With PAYMENT_STORE=memory the DatabaseURL is not required and no pool is
// opened; with the default (postgres) a failure to reach the database is fatal,
// because a payment service that cannot write its ledger must not accept
// transfers.
func Open(ctx context.Context, cfg *config.Config) (Store, error) {
	switch cfg.Store {
	case config.StoreMemory:
		return NewMemory(), nil
	case config.StorePostgres:
		pool, err := db.Connect(ctx, cfg.DatabaseURL, cfg.DatabaseMaxConns)
		if err != nil {
			return nil, err
		}
		return NewPostgres(pool), nil
	default:
		return nil, fmt.Errorf("store: unknown backend %q", cfg.Store)
	}
}

// NewPostgres wraps an existing pool (used by tests).
func NewPostgres(pool *pgxpool.Pool) *Postgres { return &Postgres{pool: pool} }

// Kind implements Store.
func (p *Postgres) Kind() string { return "postgres" }

// Close implements Store.
func (p *Postgres) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

// Ping implements Store.
func (p *Postgres) Ping(ctx context.Context) error {
	if p.pool == nil {
		return errors.New("store: no database pool")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return p.pool.Ping(pingCtx)
}

// uniqueViolation is PostgreSQL's SQLSTATE for a duplicate primary key.
const uniqueViolation = "23505"

// RecordTransaction implements Store.
//
// The insert is a single statement, and the row's `created_at` comes back from
// the database (`RETURNING`): the ledger's timestamp is the one the ledger
// itself recorded, not one this process hoped matched it. The amount is bound
// as an exact decimal string and cast explicitly, so PostgreSQL's NUMERIC does
// the storage — no float ever touches the value on the way in.
func (p *Postgres) RecordTransaction(ctx context.Context, txn Transaction) (Transaction, error) {
	if err := txn.Validate(); err != nil {
		return Transaction{}, err
	}
	if p.pool == nil {
		return Transaction{}, errors.New("store: no database pool")
	}

	const insert = `
		INSERT INTO transactions (txn_id, sender_id, receiver_id, amount)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::numeric)
		RETURNING created_at`

	recorded := txn
	if err := p.pool.QueryRow(ctx, insert,
		txn.TxnID, txn.SenderID, txn.ReceiverID, txn.Amount.String(),
	).Scan(&recorded.CreatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return Transaction{}, fmt.Errorf("%w: %s", ErrDuplicate, txn.TxnID)
		}
		return Transaction{}, fmt.Errorf("store: failed to record the transaction: %w", err)
	}
	return recorded, nil
}
