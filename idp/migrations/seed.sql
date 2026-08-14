-- seed.sql
-- Bootstrap the IdP with two dummy users (one admin, one customer).
--
-- DEV-ONLY credentials. These are intentionally known, documented values so
-- every team member can exercise the full Zero-Trust flow locally:
--     admin    / admin123
--     customer / customer123
-- They are NOT secrets; real credentials live in the git-crypt-encrypted
-- .env file and are provisioned out of band.
--
-- password_hash values below are bcrypt (cost 10) hashes of the passwords
-- above. Executed by the entrypoint after migrations; idempotent thanks to
-- ON CONFLICT (username) DO NOTHING, so it is safe to run on every boot.

INSERT INTO credentials (user_id, username, password_hash, role) VALUES
    ('11111111-1111-4111-8111-111111111111', 'admin',    '$2a$10$Sfr7rOEC27E1s6XNaz.boezZusBW.ZGOAWAMCWamwuE2fgUzW2swq', 'admin'),
    ('22222222-2222-4222-8222-222222222222', 'customer', '$2a$10$FSzv1oxSaXVJ1Eq60jO.j.rIdyfZRIfWbUImURXSibZ6Ztqum4PHm', 'customer')
ON CONFLICT (username) DO NOTHING;
