-- 001_init.up.sql
-- Payment & Transaction Service schema bootstrap (Person 5).
--
-- Database-per-Service (docs/database.md §2): this service owns the
-- `transactions` table exclusively.
--
--   * It never reads `accounts` (Person 4's) or `credentials` (Person 1's).
--   * Balances are verified and debited by calling the Account Service over
--     mTLS (docs/contacts.md); there is no cross-service SQL and no join.
--
-- The column definitions below are the contract from docs/contacts.md verbatim.
-- Everything added around them is a constraint, an index or an immutability
-- guarantee — no column, type or default was changed, because the other
-- services and the project's documentation are written against this exact
-- shape.

CREATE TABLE IF NOT EXISTS transactions (
    txn_id UUID PRIMARY KEY,
    sender_id UUID NOT NULL,
    receiver_id UUID NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE transactions IS
    'Immutable ledger of transfers, owned exclusively by the payment service. Append-only: see the reject_ledger_mutation trigger.';
COMMENT ON COLUMN transactions.txn_id IS
    'Primary key, a UUID v4 minted by the payment service per transfer.';
COMMENT ON COLUMN transactions.created_at IS
    'Assigned by the database (CURRENT_TIMESTAMP). TIMESTAMP without time zone because the contract specifies it; the shared instance runs UTC and this service reads and writes UTC.';

-- Money-safety constraints.
--
-- These are the rules the API also enforces, restated where they cannot be
-- bypassed: a bug in a handler, a future migration, or a hand-run INSERT must
-- not be able to write a zero-value, negative or self-referential transfer into
-- the ledger. A ledger that can hold a nonsensical row cannot be used to
-- reconstruct what actually happened.
ALTER TABLE transactions
    DROP CONSTRAINT IF EXISTS transactions_amount_positive_check;
ALTER TABLE transactions
    ADD CONSTRAINT transactions_amount_positive_check CHECK (amount > 0);

ALTER TABLE transactions
    DROP CONSTRAINT IF EXISTS transactions_distinct_parties_check;
ALTER TABLE transactions
    ADD CONSTRAINT transactions_distinct_parties_check CHECK (sender_id <> receiver_id);

-- Query indexes. The ledger's two questions are "everything that touched
-- account X" and "what happened in this window", and both filter on
-- created_at after an equality on a participant.
CREATE INDEX IF NOT EXISTS transactions_sender_idx    ON transactions (sender_id, created_at DESC);
CREATE INDEX IF NOT EXISTS transactions_receiver_idx  ON transactions (receiver_id, created_at DESC);
CREATE INDEX IF NOT EXISTS transactions_created_at_idx ON transactions (created_at DESC);

-- ---------------------------------------------------------------------------
-- Immutability.
--
-- docs/contacts.md calls this table "an immutable ledger of transactions", and
-- documentation is not an enforcement mechanism. A ledger whose rows can be
-- edited is not evidence of anything: whoever can UPDATE a transfer can erase
-- one. Row-level security would not help, because the service's own role is
-- the one that needs the guarantee.
--
-- So the table refuses mutation outright. Corrections are new rows (a reversal
-- or a compensation entry), which is how an append-only ledger is supposed to
-- express them anyway. TRUNCATE is covered too: it bypasses row triggers but
-- can be caught by a statement-level trigger.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION reject_ledger_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'transactions is an append-only ledger: % is not permitted (row %). Record a compensating entry instead.',
        TG_OP, COALESCE(OLD.txn_id::text, '');
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS transactions_reject_update ON transactions;
CREATE TRIGGER transactions_reject_update
    BEFORE UPDATE ON transactions
    FOR EACH ROW EXECUTE FUNCTION reject_ledger_mutation();

DROP TRIGGER IF EXISTS transactions_reject_delete ON transactions;
CREATE TRIGGER transactions_reject_delete
    BEFORE DELETE ON transactions
    FOR EACH ROW EXECUTE FUNCTION reject_ledger_mutation();

DROP TRIGGER IF EXISTS transactions_reject_truncate ON transactions;
CREATE TRIGGER transactions_reject_truncate
    BEFORE TRUNCATE ON transactions
    FOR EACH STATEMENT EXECUTE FUNCTION reject_ledger_mutation();
