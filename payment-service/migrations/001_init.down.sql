-- 001_init.down.sql
-- Rollback for 001_init.up.sql (docs/database.md §3 requires a DOWN script).
--
-- Destructive by nature: it drops the ledger and its immutability guard. The
-- CLI requires an explicit confirmation before running it.

DROP TRIGGER IF EXISTS transactions_reject_update ON transactions;
DROP TRIGGER IF EXISTS transactions_reject_delete ON transactions;
DROP TRIGGER IF EXISTS transactions_reject_truncate ON transactions;
DROP FUNCTION IF EXISTS reject_ledger_mutation();

DROP TABLE IF EXISTS transactions;
