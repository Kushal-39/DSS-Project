# Payment & Transaction Service (Person 5)

## Overview

The Payment Service (Microservice B) is the downstream financial transaction service. It validates client certificates on every incoming connection (TLS 1.3, shared CA, identity allowlist), verifies the bearer token, re-checks the decision with the Policy Engine, asks the Account Service to debit, and records the result in its own immutable `transactions` ledger.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Running the Service](#running-the-service)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Docker Development](#docker-development)

## Quick Start

### Prerequisites

- Go 1.24+
- Docker and Docker Compose (for full integration test)
- Git-crypt encrypted `.env` file with the following required variables:

```env
DATABASE_URL=postgres://payment:changeme@db.example.com:5432/postgres
PAYMENT_TLS_CERT_FILE=/certs/payment-service.crt
PAYMENT_TLS_KEY_FILE=/certs/payment-service.key
PAYMENT_TLS_CA_FILE=/certs/ca.crt
PAYMENT_TLS_REQUIRE_CLIENT_CERT=true
PAYMENT_ALLOWED_CLIENT_IDS=gateway,account-service
PAYMENT_JWKS_URL=http://idp:8080/.well-known/jwks.json
PAYMENT_JWT_AUDIENCE=zerotrust-api-gateway
PAYMENT_POLICY_URL=http://policy-engine:8181/v1/data/authz/allow
PAYMENT_ACCOUNT_SERVICE_URL=https://account-service:8082
PAYMENT_UPSTREAM_TLS_CERT_FILE=/certs/payment-service-client.crt
PAYMENT_UPSTREAM_TLS_KEY_FILE=/certs/payment-service-client.key
PAYMENT_UPSTREAM_TLS_CA_FILE=/certs/ca.crt
PAYMENT_ALLOW_INSECURE_UPSTREAM=false
PAYMENT_STORE=postgres
PAYMENT_LOG_LEVEL=info
```

### Running Locally (Go)

```bash
# 1. Generate certificates (one-time)
docker compose run --rm --user 0:0 payment-service-certs
# or locally:
cd payment-service && go run ./cmd/server certs --dir ./certs

# 2. Start the full stack
cd .. && docker compose up --build

# 3. Test the service
# The service listens on :8081 with mTLS
# POST /api/v1/payments/transfer with Bearer token
```

### Running Locally (Without Docker)

```bash
# Generate certificates
go run ./cmd/server certs --dir ./certs

# Set environment variables from .env.example
cp .env.example ../.env  # then edit the root .env

# Build and run
go build -o payment-server ./cmd/server
PAYMENT_TLS_CERT_FILE=/certs/payment-service.crt \
PAYMENT_TLS_KEY_FILE=/certs/payment-service.key \
PAYMENT_TLS_CA_FILE=/certs/ca.crt \
PAYMENT_TLS_REQUIRE_CLIENT_CERT=true \
PAYMENT_ALLOWED_CLIENT_IDS=gateway,account-service \
PAYMENT_JWKS_URL=http://idp:8080/.well-known/jwks.json \
PAYMENT_POLICY_URL=http://policy-engine:8181/v1/data/authz/allow \
PAYMENT_ACCOUNT_SERVICE_URL=https://account-service:8082 \
./payment-server serve
```

## Configuration

### Environment Variables

All configuration is via environment variables (see `.env.example`). Key categories:

| Category | Variables | Description |
|----------|-----------|-------------|
| **Transport (mTLS)** | `PAYMENT_TLS_CERT_FILE`, `PAYMENT_TLS_KEY_FILE`, `PAYMENT_TLS_CA_FILE`, `PAYMENT_TLS_REQUIRE_CLIENT_CERT` | Listener mTLS: certificate, key, shared CA, and whether client cert is mandatory |
| **Identity (Person 1)** | `PAYMENT_JWKS_URL`, `PAYMENT_JWT_AUDIENCE` | JWT verification: IdP key set and expected audience |
| **Authorization (Person 3)** | `PAYMENT_POLICY_URL`, `PAYMENT_POLICY_TIMEOUT` | Policy engine: OPA authorization endpoint and timeout |
| **Business (Person 4)** | `PAYMENT_ACCOUNT_SERVICE_URL`, `PAYMENT_UPSTREAM_TLS_*` | Account service: HTTPS URL and client mTLS identity for deduct calls |
| **Observability (Person 6)** | `PAYMENT_OTLP_ENDPOINT`, `PAYMENT_OTLP_TOKEN` | Telemetry: OTLP span export endpoint and token |

### StrictDefaults

Per `docs/division.md` §2, the service has these stricter defaults:

- `PAYMENT_TLS_REQUIRE_CLIENT_CERT=true` (mandatory; set `false` only for rollout)
- `PAYMENT_ALLOW_INSECURE_UPSTREAM=false` (account service must be HTTPS with mTLS)
- Service refuses to start without TLS material (`PAYMENT_ALLOW_INSECURE_HTTP=false`)

## API Endpoints

### POST /api/v1/payments/transfer

**Request Body:**
```json
{
  "sender_id": "uuid-string",
  "receiver_id": "uuid-string",
  "amount": "50.00"
}
```

**Response (200 OK):**
```json
{
  "txn_id": "uuid-string",
  "sender_id": "uuid-string",
  "receiver_id": "uuid-string",
  "amount": "50.00",
  "created_at": "2024-01-15T10:30:00Z"
```

**Security Flow:**

1. **mTLS handshake**: Client certificate must chain to shared CA (`guardPeer`)
2. **Identity allowlist**: Certificate identity must be in `PAYMENT_ALLOWED_CLIENT_IDS` (`guardBusiness`)
3. **JWT verification**: `Authorization: Bearer <jwt>` header verified against JWKS (`bearerToken`)
4. **Syntax validation**: UUID format, positive amount, no self-transfer (`validate`)
5. **Sender binding**: `sender_id` must match authenticated user or token must be admin (`checkSenderBinding`)
6. **Policy check**: Synchronous OPA authorization with nested `input` payload (`policy.Authorize`)
7. **Account deduct**: Call Person 4's `/api/v1/accounts/deduct` over mTLS (`s.accounts.Deduct`)
8. **Ledger record**: Write transaction to immutable `transactions` table (`store.RecordTransaction`)

**Error Paths:**

| Scenario | Status | Code | Description |
|----------|--------|------|-------------|
| Policy engine unavailable | 403 | `policy_unavailable` | Fail-closed if engine is down |
| Policy engine denies | 403 | `policy_denied` | Rego evaluation returned false |
| Account service refuses (403) | 400 | `deduction_failed` | Insufficient balance or policy refusal |
| Account service 5xx unavailable | 400 | `deduction_unavailable` | Account service unreachable |
| Ledger write failure | 500 | `ledger_write_failed` | Requires manual reconciliation |

## Testing

### Unit Tests

All packages have comprehensive unit tests. Run:

```bash
go test -count=1 ./...
```

**Key test suites:**

- `payment-service/internal/payments` - 14 tests covering the full transfer orchestration
- `payment-service/internal/mtls` - mTLS listener and connection tests
- `payment-service/internal/httpapi` - HTTP API handler tests
- `payment-service/internal/config` - Configuration validation tests

### Integration Tests

**PostgreSQL schema immutability test** (requires `PAYMENT_TEST_DATABASE_URL`):

```bash
PAYMENT_TEST_DATABASE_URL=postgres://user:pass@db:5432/payment_db go test -count=1 ./internal/store/
```

This test verifies:
- Table constraints (amount > 0, sender_id != receiver_id)
- Append-only triggers (rejects UPDATE, DELETE, TRUNCATE)
- Schema migration up/down paths

**Person 5 test suite** (run from payment-service):

```bash
go test -count=1 -v ./internal/payments/
```

### Manual Verification Steps

Refer to `payment-service/README.md` for curl-based verification steps that can be run from the host. The docker-compose.yml notes that these steps need the certificates mounted from the `payment-service-certs` service.

## Docker Development

### Services

Two relevant services in `docker-compose.yml`:

1. **`payment-service-certs`** (one-shot):
   - Builds the payment-service image
   - Entry point: `payment-server certs --dir /certs`
   - Mints local CA and certificates into `./payment-service/certs` on the host
   - Exits after completing; the `payment-service` depends on it

2. **`payment-service`**:
   - Builds the payment-service image
   - Runs the mTLS API on `:8081`
   - Dependencies: `payment-service-certs` (certs mounted read-only), `policy-engine`, `account-service`
   - Health check presents valid client certificate via the payment-server binary
   - Read-only filesystem, no-new-privileges, cap-drop ALL

### Certificate Generation

The `payment-service-certs` service generates these files in `./payment-service/certs`:

- `ca.crt` - Shared CA certificate
- `payment-service.crt` / `payment-service.key` - Service's own certificate/key (listener auth)
- `payment-service-client.crt` / `payment-service-client.key` - Client identity for upstream calls
- `probe.crt` / `probe.key` - Health check certificate (deliberately NOT in `PAYMENT_ALLOWED_CLIENT_IDS`)

### Health Check

The service declares a health check in docker-compose.yml that uses the payment-server binary to probe `/healthz` over mTLS. This is necessary because the listener refuses a peer without a certificate, so `wget` cannot probe it directly.

## Architecture Integration

Person 5 interfaces with all other persons:

| Person | Interaction | Contract |
|--------|-------------|----------|
| **Person 1** (IdP) | JWT verification via JWKS | `Authorization: Bearer <token>` |
| **Person 3** (Policy Engine) | OPA authorization with nested `input` payload | `POST http://policy-engine:8181/v1/data/authz/allow` |
| **Person 4** (Account Service) | `/api/v1/accounts/deduct` over mTLS | HTTPS + mutual certs |
| **Person 6** (Observability) | Audit records + OTLP spans | Structured JSON logs, OpenTelemetry |

**Three Global Interfaces adhered to:**

1. **Auth Contract**: `Authorization: Bearer <JWT>` HTTP header
2. **Transport Contract**: TLS 1.3 mTLS with shared CA across all services
3. **Policy Request Contract**: Nested `input` object in policy engine request (strict format, no exceptions)

## Appendix: Important Notes

- **No manual schema changes**: All database changes must be tracked in `migrations/` (see `docs/database.md`)
- **Database-per-service**: Payment service owns `transactions` only; it never reads `accounts` directly
- **Immutable ledger**: `transactions` table has triggers that reject UPDATE, DELETE, and TRUNCATE
- **Fail-closed design**: Policy engine down = 403 Forbidden; account service error = 400 Bad Request
- **Sender binding**: By default, `sender_id` must match the JWT `sub` claim; configurable via `PAYMENT_ENFORCE_SENDER_BINDING`