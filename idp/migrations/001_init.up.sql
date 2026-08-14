-- 001_init.up.sql
-- IdP schema bootstrap (Person 1 — Identity & Token Authority).
--
-- Database-per-Service: this table is owned exclusively by the IdP.
-- No other service may read or write it; inter-service verification
-- happens over the API, never via shared tables.

CREATE TABLE IF NOT EXISTS credentials (
    user_id       UUID        PRIMARY KEY,
    username      VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(128) NOT NULL,
    role          VARCHAR(32) NOT NULL CHECK (role IN ('admin', 'customer'))
);

COMMENT ON TABLE credentials IS 'Credentials owned by the IdP service. Password field stores bcrypt hashes only.';
