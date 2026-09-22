-- seed.sql
-- Bootstrap accounts for local development and integration testing.
--
-- Matches the bootstrap users seeded in idp/migrations/seed.sql:
--   admin:    11111111-1111-4111-8111-111111111111 (balance 5000.00, ACTIVE)
--   customer: 22222222-2222-4222-8222-222222222222 (balance 1000.00, ACTIVE)
--
-- Idempotent thanks to ON CONFLICT (user_id) DO NOTHING.

INSERT INTO accounts (user_id, balance, status) VALUES
    ('11111111-1111-4111-8111-111111111111', 5000.00, 'ACTIVE'),
    ('22222222-2222-4222-8222-222222222222', 1000.00, 'ACTIVE')
ON CONFLICT (user_id) DO NOTHING;
