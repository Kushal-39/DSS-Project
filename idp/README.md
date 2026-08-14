# IdP — Identity Provider

Person 1's microservice in the Zero-Trust architecture. Owns the
`credentials` table (Database-per-Service — see `docs/database.md`),
authenticates users, and issues RS256-signed JWTs that the API Gateway
(Person 2) verifies against our JWKS.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/login` | Authenticate (`{"username","password","device_id"?}`) → `{token, token_type, expires_in, user}` |
| `GET` | `/.well-known/jwks.json` | Public RSA key (JWKS) for signature verification |
| `GET` | `/.well-known/openid-configuration` | Minimal discovery document |
| `GET` | `/healthz`, `/readyz` | Liveness / readiness (DB ping) |

## Running

```bash
# 1. Environment (see .env.example — copy into the git-crypt-encrypted .env)
#    DATABASE_URL=postgres://...  (Supabase)
#    IDP_RSA_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n...  (or _PATH)

# 2. Build & run
docker compose up --build          # via the root compose file
# or locally:
go run ./cmd/server migrate && go run ./cmd/server seed && go run ./cmd/server serve

# 3. Smoke test
curl -s http://localhost:8080/.well-known/jwks.json
curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
```

The container entrypoint runs `migrate → seed → serve` automatically
(`docs/database.md` §4). Migrations and the seed script are compiled into
the binary via `go:embed`.

## Bootstrap users (DEV-ONLY)

| username | password | role |
| --- | --- | --- |
| `admin` | `admin123` | `admin` |
| `customer` | `customer123` | `customer` |

These are intentionally known, documented values so every team member can
exercise the flow. They are **not** secrets; real credentials are provisioned
out of band.

## Developer utilities

```bash
go run ./cmd/server genkey          # print a fresh RSA private key for .env
go run ./cmd/server hash <password> # print a bcrypt hash for seed data
```

## Token claims

`sub` (user UUID), `roles` (`["admin"]`/`["customer"]` — the array shape the
Policy Engine contract expects), `device_id`, plus `iss`/`aud`/`exp`/`iat`/`jti`.
See `decisions.md` for the full design rationale.

## Tests

```bash
go test ./...        # unit tests (keys, auth, HTTP handlers)
go vet ./...         # static analysis
```
