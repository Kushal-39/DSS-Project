# IdP Service — Design Decisions

**Author:** Person 1 (Identity & Token Authority)
**Scope:** `idp/` — the Identity Provider microservice
**Context:** Six-person university proof-of-concept (POC) building a Zero-Trust
architecture on a shared Supabase PostgreSQL instance, Docker Compose, and
git-crypt-encrypted `.env`. The `main` branch is locked; work happens on
`feat/idp-service` and lands via PR.

---

## 0. Mandate from the repository documentation

Before any code, the governing docs were read and analyzed:

| Document | Binding requirements for the IdP |
| --- | --- |
| `docs/database.md` | IdP **owns** the `credentials` tables (Database-per-Service). No service touches another's tables. Migrations live in `migrations/` as `NNN_name.up.sql` / `NNN_name.down.sql`, run automatically at container start **before** the web server boots. Go services use `golang-migrate`. Read `DATABASE_URL` from env; never hardcode credentials. |
| `docs/flow.md` | `POST /login` returns a signed RS256 JWT containing `sub`, `roles`, and `device_id`. Every component emits structured JSON logs. |
| `docs/division.md` | Person 1 delivers a lightweight auth service exposing `/.well-known/openid-configuration`, `/token` (we map to `/login` per `flow.md`), and `/jwks.json`. Tokens feed the Policy Engine contract where `roles` is an **array** (`"roles": ["customer"]`). |
| `docs/contacts.md` | No IdP-specific API contract, but establishes the strict contract-first culture: exact field names matter, no guessing. |
| `CONTRIBUTING.md` | Stay in `/idp`. Feature branch + PR. Never commit `.env`. `.env.example` holds dummy values. `docker compose up --build` must succeed. Clean, readable, formatted code. |

**Contract decisions derived from docs:**

1. JWT claims follow `flow.md` + the Policy Engine contract in `division.md`:
   `sub` = user UUID, `roles` = `[role]` (array, because Person 3's Rego rules
   read `input.subject.roles[_]`), `device_id` = provided by the client at
   login (generated as a UUID v4 when omitted so the claim is always present).
2. The login endpoint is `POST /login` (exactly as `flow.md` step 1 specifies),
   not `/token`. `/token` is reserved for a future OAuth2/OIDC grant flow.
3. All logs are structured JSON (stdlib `log/slog`), with the `traceparent`
   header captured and echoed into log lines so Person 6's pipeline can
   correlate spans (no OpenTelemetry SDK in this phase — see §8).

---

## 1. Language & HTTP stack

**Requirement:** Build a lightweight auth service in Go or Python, avoiding
bloated enterprise frameworks.

### Approaches considered

1. **Go + standard library `net/http`** (`http.ServeMux` with method+path
   patterns, `log/slog`, `embed`). Zero web framework. Static binary.
2. **Go + Gin/Echo/Chi.** Small routers with middleware helpers; adds a
   dependency and framework idioms for what is ~3 endpoints.
3. **Python + FastAPI.** Fast to write, auto OpenAPI docs; but adds a runtime
   (Python interpreter in the image), a framework, Pydantic, and a WSGI/ASGI
   layer for three handlers.

### Evaluation (6-person POC)

- We need **four** routes (`/login`, `/.well-known/jwks.json`,
  `/.well-known/openid-configuration`, `/healthz`). A framework buys nothing.
- Go 1.22+ `ServeMux` natively supports `"POST /login"` patterns and method
  matching, and `log/slog` gives structured JSON logging from the standard
  library.
- A single static Go binary in the Docker image is simpler for the whole team
  to run via Compose than a Python venv + uvicorn.
- `docs/database.md` already assumes Go tooling for this repo's services.

### Decision

**Go (1.23+ language level) with the standard library only for HTTP.** No web
framework. Rationale: smallest attack surface, no framework lock-in, one static
binary, and the stdlib covers routing, logging, and embedding. Python/FastAPI
was rejected because the feature set does not justify the runtime and framework
overhead in a security-sensitive service.

---

## 2. JWT signing library

**Requirement:** Signed RS256 JWTs. Never invent custom signing logic.

### Approaches considered

1. **`github.com/golang-jwt/jwt/v5`** — the de-facto community standard,
   actively maintained, supports RS256 and `jwt.RegisteredClaims`, used by
   most of the Go ecosystem.
2. **`github.com/lestrrat-go/jwx/v2`** — powerful, more feature-complete
   (JWKS, JWE), but a much larger API surface and dependency tree.
3. **`gopkg.in/dgrijalva/jwt-go.v3`** — the original library; effectively
   unmaintained (the author moved to `golang-jwt`).
4. Hand-rolled RS256 (raw `crypto/rsa` + base64url) — explicitly forbidden by
   the task.

### Decision

**`golang-jwt/jwt/v5`.** It is the maintained continuation of the original
`jwt-go`, has a stable v5 API with typed `RegisteredClaims`, and covers exactly
what we need (RS256 signing, standard claim validation). `jwx` was rejected as
overkill for a POC; `jwt-go` v3 was rejected as unmaintained.

---

## 3. Password hashing

**Requirement:** Verify `password_hash` against submitted credentials; store
never-plaintext hashes.

### Approaches considered

1. **bcrypt** (`golang.org/x/crypto/bcrypt`) — 20+ years of production use,
   built-in salt, cost factor tunable; `CompareHashAndPassword` is
   constant-time.
2. **Argon2id** — the current recommended KDF (memory-hard, resistant to GPU
   cracking); requires manual parameter management, salt generation, and
   encoded-format bookkeeping in Go.
3. **scrypt** — memory-hard but older design, fewer audited high-level
   wrappers.
4. Plaintext / SHA-256 — rejected outright; unacceptable for any auth service,
   even a POC.

### Decision

**bcrypt with default cost (10).** Rationale: zero configuration, battle-tested
API, and the strongest choice that a six-person team can implement correctly
on the first pass. Argon2id is strictly stronger and is noted as a follow-up
upgrade path (the `password_hash` column is `VARCHAR` so an Argon2id PHC string
fits without a migration). A **dummy bcrypt hash** is also compared whenever a
username is not found, so successful and failed lookups take similar time and
the endpoint does not leak which usernames exist (user-enumeration resistance).
Both cases return the identical `invalid_credentials` error.

---

## 4. Cryptographic key management (RSA)

**Requirement:** Load the RSA private key from environment variables injected
via the encrypted `.env`; never hardcode secrets; fail fast on missing vars.

### Approaches considered

1. **Private key as a PEM string in `IDP_RSA_PRIVATE_KEY` env var.**
   Injected via the git-crypt-encrypted `.env`; parsed in-process at startup.
2. **Private key in a file mounted at `IDP_RSA_PRIVATE_KEY_PATH`**
   (e.g., a Docker secret or volume). Common in production; requires the team
   to manage a key file per machine.
3. **Generate a fresh keypair at startup when missing.** Zero setup, but the
   key rotates on every restart → every cached JWKS entry in the API Gateway
   becomes invalid and tokens issued before restart fail verification.
   Also normalizes the anti-pattern of "it works on my machine".
4. **Cloud KMS / secret manager** (GCP KMS, AWS Secrets Manager, Vault).
   Operationally correct but absurd for a university POC on a free Supabase
   tier; adds accounts, SDKs, and IAM.

### Decision

**Approach 1 with Approach 2 as a fallback.** The private key lives in the
encrypted `.env` as `IDP_RSA_PRIVATE_KEY` (a PEM block, with `\n` escapes as
written in dotenv files). If that variable is absent, we fall back to
`IDP_RSA_PRIVATE_KEY_PATH` (file mount). If **neither** is present, the process
exits immediately with a clear error (fail fast). The public key is derived
from the private key in memory — no second secret to keep in sync.

- `kid` (key ID) is computed as the **RFC 7638 JWK thumbprint** (SHA-256 over
  the canonical `{"e","kty","n"}` JSON), so the `kid` is self-describing,
  stable across restarts, and never has to be configured.
- A `genkey` subcommand prints a fresh 2048-bit RSA private key in PEM so a
  teammate can generate one and paste it into `.env`.
- The committed `idp/.env.example` ships a **clearly labeled DEV-ONLY** key so
  `docker compose up` works out of the box; production `.env` values are never
  committed (`CONTRIBUTING.md` §3).

---

## 5. Database driver & connection pooling

**Requirement:** Talk to the shared Supabase PostgreSQL instance.

### Approaches considered

1. **`jackc/pgx/v5` (`pgxpool`)** for application queries — the modern,
   maintained, pure-Go driver with a battle-tested connection pool.
2. **`lib/pq`** — the original database/sql driver; stable but in maintenance
   mode, and pooling must be hand-managed via `database/sql`.
3. **`database/sql` + `pgx/stdlib`** — `database/sql` abstraction with the pgx
   driver underneath; fine, but adds an indirection layer for one query.

### Decision

**`pgx/v5` with `pgxpool` for application queries; `golang-migrate`'s
`database/postgres` (lib/pq) driver for migrations only.** `pgxpool` gives us
connection reuse, retries, and context-aware cancellation with minimal code.
`golang-migrate`'s postgres driver is used purely inside the migrate library
(it is the driver `golang-migrate` documents first for Postgres). This keeps
each dependency on its best-trodden path without forcing `database/sql`
everywhere. Supabase requires TLS — `sslmode=require` is expected in the
`DATABASE_URL` provided by the team, and the Docker image ships CA
certificates for this.

---

## 6. Migration execution strategy

**Requirement:** Migrations must run automatically at container start against
`DATABASE_URL`, before the web server boots. Files must be `001_init.up.sql`
and `001_init.down.sql`.

### Approaches considered

1. **`golang-migrate` as an embedded library** (`source/iofs` + `go:embed`).
   The binary runs `migrate` (a subcommand), then `seed`, then `serve` from a
   shell entrypoint. No external downloads, works offline, versioned via
   `schema_migrations`, and supports down migrations.
2. **`golang-migrate` CLI installed in the Dockerfile** (per `docs/database.md`
   literally). Works, but the build step downloads a binary from GitHub at
   image build time — a flaky, supply-chain-visible step that also duplicates
   the version pinning.
3. **Hand-rolled SQL runner** — a loop that executes migration files in
   filename order. Zero dependencies but no `schema_migrations` bookkeeping,
   no down-migration support, and easy to get wrong on partial failures.
4. **Alembic** (Python) — only relevant if we had chosen Python (§1).

### Decision

**Approach 1: `golang-migrate` embedded in the Go binary, driven by an
entrypoint script.** This honors the spirit and the letter of
`docs/database.md` ("use `golang-migrate`") while removing the Dockerfile
download step and its failure modes. The container lifecycle is explicit and
observable:

```
entrypoint.sh:  idp-server migrate  →  idp-server seed  →  exec idp-server serve
```

`migrate` and `seed` both retry the DB connection briefly (Compose startup
ordering) and fail fast with a clear message if `DATABASE_URL` is missing or
unreachable. `001_init.down.sql` provides a real rollback path, satisfying the
"standard SQL migration scripts" requirement.

### Seeding

The seed is a plain SQL script (`migrations/seed.sql`) with idempotent
`INSERT ... ON CONFLICT (username) DO NOTHING` statements for two dummy users
(`admin` / `admin123`, `customer` / `customer123`), storing **pre-generated
bcrypt hashes**. Rationale for SQL over app-level seeding:

1. It is a literal "script to seed the database" (the deliverable) and is
   reviewable in the PR.
2. It is idempotent and environment-independent.
3. The dummy credentials are explicitly **not secrets** (they are documented
   dev-only values, like `.env.example`); real secrets never appear in SQL.

The `golang-migrate` matcher only parses `NNN_name.up|down.sql` files, so
`seed.sql` is ignored by the migration engine and executed separately.

---

## 7. Containerization

**Requirement:** Dockerfile that runs migrations before the web server starts.

### Approaches considered

1. **Multi-stage: `golang:1.24-alpine` build → `alpine` runtime, non-root user.**
   Small (~20 MB), debuggable, ships `ca-certificates` for Supabase TLS.
2. **Multi-stage: `golang` build → `gcr.io/distroless/static`.**
   Smallest surface, but no shell → the migration/seed entrypoint must be
   reworked as a pure-Go subcommand chain, and debugging (e.g.,
   `docker exec`) is painful.
3. **Single-stage `golang` image.** Fast to iterate but ships the toolchain,
   ~800 MB, and bloats the runtime with a compiler.

### Decision

**Approach 1: `golang:1.24-alpine` builder → `alpine:3.20` runtime with a
non-root `idp` user.** `CGO_ENABLED=0` produces a static binary that runs
unmodified on Alpine. The entrypoint script (`entrypoint.sh`) performs
`migrate → seed → serve` and `exec`s the server as PID 1 (correct signal
handling for graceful shutdown). Non-root runtime user + read-only workdir +
`ca-certificates` satisfy the Zero-Trust posture without sacrificing team
debuggability.

---

## 8. Observability

**Requirement (from `docs/flow.md` §6):** structured JSON logs; the IdP is a
source of auth/audit events for Person 6.

### Approaches considered

1. **stdlib `log/slog` with a JSON handler.** Zero dependencies, structured
   output, leveled logging.
2. **`zap`/`logrus`.** More features (sampling, custom encoders) we do not
   need.
3. **OpenTelemetry SDK + exporter.** The "right" long-term answer; heavy
   dependency tree and config for a POC that does not yet run a collector.

### Decision

**`log/slog` JSON.** Every request is logged as one JSON line with
`method`, `path`, `status`, `duration_ms`, `remote_addr`, and the inbound
`traceparent` header (so Person 6 can correlate without a tracing SDK). Login
attempts emit explicit audit events:

```json
{"ts":"...","level":"info","msg":"login_attempt","outcome":"success","user_id":"...","role":"admin","traceparent":"00-..."}
```

Passwords and password hashes are **never** logged. OpenTelemetry is deferred
to a later phase and noted as the upgrade path.

---

## 9. API surface & response contract

### Endpoints

| Method & path | Purpose |
| --- | --- |
| `POST /login` | Authenticate; returns `{token, token_type, expires_in, user}`. |
| `GET /.well-known/jwks.json` | Public RSA key as a JWKS set (`kid` = RFC 7638 thumbprint). |
| `GET /.well-known/openid-configuration` | Minimal discovery doc pointing at the JWKS URI (per `division.md`). |
| `GET /healthz`, `GET /readyz` | Liveness; readiness (pings the DB). |

### Login contract

```json
// request
{"username": "admin", "password": "admin123", "device_id": "optional-uuid"}
// 200 response
{"token": "<jwt>", "token_type": "Bearer", "expires_in": 900,
 "user": {"id": "<uuid>", "username": "admin", "role": "admin"}}
```

Errors use a consistent envelope: `{"error": {"code": "...", "message": "..."}}`
with `400` (malformed), `401` (bad credentials — identical message whether the
username or password is wrong), `415` (non-JSON), `500` (internal, details
only in logs).

### Claims in the issued JWT

```json
{"iss":"http://idp:8080","sub":"<uuid>","aud":["zerotrust-api-gateway"],
 "exp":..., "iat":..., "jti":"...", "roles":["admin"], "device_id":"..."}
```

All issuer/audience/TTL values are configurable (`IDP_JWT_ISSUER`,
`IDP_JWT_AUDIENCE`, `IDP_JWT_TTL`, default 15m).

---

## 10. Rejected / deferred items (explicitly out of scope for this phase)

| Idea | Why deferred |
| --- | --- |
| OAuth2/OIDC authorization-code flow, `/token` with grant types | `flow.md` defines password login at `/login`; OIDC is a future phase. |
| Account lockout / per-IP login rate limiting | Global rate limiting is Person 2's gateway job; revisit if brute force becomes an issue. |
| Key rotation endpoints / multiple active keys | POC uses one long-lived dev key; `kid` + JWKS design already supports rotation later. |
| Argon2id password hashing | bcrypt chosen for first pass (§3); upgrade path documented. |
| OpenTelemetry SDK | Deferred to the telemetry phase (§8). |
| Centralized config service | Overkill; env vars via git-crypt are the team's agreed mechanism. |

---

## 11. Summary of chosen stack

| Concern | Choice |
| --- | --- |
| Language / HTTP | Go 1.23+, stdlib `net/http` (`ServeMux` method routing) |
| JWT | `github.com/golang-jwt/jwt/v5` (RS256) |
| Password hashing | `golang.org/x/crypto/bcrypt` (+ timing-equalizing dummy hash) |
| DB driver | `jackc/pgx/v5` (`pgxpool`) |
| Migrations | `golang-migrate/v4` embedded via `go:embed` (`source/iofs`) |
| Keys | `IDP_RSA_PRIVATE_KEY` env PEM (fallback: file path); `kid` = RFC 7638 thumbprint |
| Logging | stdlib `log/slog` JSON |
| Container | Multi-stage `golang:1.24-alpine` → `alpine:3.20`, non-root, entrypoint `migrate → seed → serve` |
| Secrets | All secrets via git-crypt-encrypted `.env`; fail fast on missing required vars |
