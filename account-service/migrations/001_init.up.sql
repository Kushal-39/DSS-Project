-- 001_init.up.sql
-- Account Service schema bootstrap (Person 4 — Microservice A).
--
-- Database-per-Service (docs/database.md §2):
-- This table is owned exclusively by the Account Service.
-- No other service (Payment, IdP, Gateway) may read or write it directly.
-- Inter-service operations must occur via the API (e.g. POST /api/v1/accounts/deduct) over mTLS.

CREATE TABLE IF NOT EXISTS accounts (
    user_id UUID PRIMARY KEY,
    balance DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    status VARCHAR(20) DEFAULT 'ACTIVE'
);

COMMENT ON TABLE accounts IS 'User accounts and balances owned exclusively by Account Service.';
