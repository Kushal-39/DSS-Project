# Zero-Trust Distributed System

The gateway on `http://localhost:8080` authenticates JWTs against IdP JWKS,
applies a global traffic limit, and forwards business requests over mutual
TLS 1.3. Account and payment independently verify JWTs and query OPA before
business operations. Payment calls account's atomic deduction endpoint and
then appends an immutable transaction. Services own their tables and use
separate migration bookkeeping in the shared PostgreSQL database.

## Run

Unlock the encrypted environment, then start the configured database deployment:

```bash
git-crypt unlock /path/to/DSS.key
export TELEMETRY_DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
docker compose up --build -d --wait
```

`DATABASE_URL`, `IDP_RSA_PRIVATE_KEY`, and `TELEMETRY_INGEST_TOKEN` must be
set; `.env.example` describes their format. The deployment needs an IPv6
route if the configured database resolves only to IPv6. Override
`DSS_IPV6_ENABLED=false` for an IPv4-only database.

For a self-contained stack with disposable PostgreSQL, use:

```bash
export TELEMETRY_DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
docker compose -p dss-e2e -f docker-compose.yml -f compose.test.yml up --build -d --wait
```

The test override uses local PostgreSQL instead of `DATABASE_URL`; it still
uses the unlocked signing key and telemetry token. The test gateway uses port
18080, audit dashboard 18088, collector 18089, Jaeger 26686, Loki 13100, and
Grafana 13300, so tests can run while the normal deployment remains up.
Compose 2.24.4 or newer is required for the test port overrides.

## API

| Method | Gateway path | Behavior |
| --- | --- | --- |
| POST | `/login`, `/token` | JSON credentials → `token` and `access_token` aliases |
| GET | `/jwks.json`, `/.well-known/jwks.json` | Public RS256 signing key |
| GET | `/.well-known/openid-configuration` | Minimal discovery document |
| GET | `/api/v1/accounts` | Authenticated user's account, authorized by OPA |
| GET | `/api/v1/accounts/{user_id}` | Owner or administrator; authorized by OPA |
| POST | `/api/v1/accounts/deduct` | Positive amount with at most two decimal places |
| POST | `/api/v1/payments/transfer`, `/api/v1/payment` | Sender-bound transfer; deduction followed by ledger append |
| GET | `/healthz`, `/readyz` | Liveness and dependency readiness |

Login with the documented development customer (`customer` / `customer123`)
or administrator (`admin` / `admin123`). Transfer JSON follows
[`docs/contacts.md`](docs/contacts.md): `sender_id`, `receiver_id`, `amount`.
Transfer amounts are JSON numbers, as the canonical contract requires. Account
deduction also accepts decimal strings. Fractional cents, non-finite values,
and amounts outside `DECIMAL(10,2)` are refused.

Only the gateway publishes business ports. Backend sockets reject clients
without CA-verified certificates and clients limited to TLS 1.2. Probe
certificates can query health but cannot call business endpoints. Each service
mounts its own certificate volume; the CA signing key stays exclusively in
the provisioning volume. Certificates are generated idempotently before startup.

The policy endpoint keeps the HTTP address explicitly required by
[`docs/policymaker.md`](docs/policymaker.md). JWKS and telemetry use their
documented internal HTTP endpoints; telemetry ingest requires its token.
The mandatory mTLS boundaries are gateway → account/payment and payment → account.

## Observability

| URL | View |
| --- | --- |
| `http://localhost:8088/dashboard` | Audit decisions and trace joins |
| `http://localhost:8089/metrics` | Collector delivery and readiness |
| `http://localhost:16686` | Jaeger distributed spans |
| `http://localhost:3300/d/zt-logs` | Provisioned Grafana/Loki log dashboard |

Gateway, IdP, account, and payment emit OTLP/JSON spans and structured decision
logs. OPA console decision logs are enabled; their policy-context trace headers
are promoted by telemetry so policy decisions join the caller's trace. The
collector and Promtail scope discovery to their Compose project automatically.

## Presentation and reproduction

Use [the step-by-step PoC runbook](docs/poc-demo.md) for explicit positive and
negative demonstrations, expected HTTP/policy results, database evidence,
outage recovery, and presentation order. Its helper uses only the disposable
stack. Set `DSS_TEST_DATABASE_PORT` if the default test port 55432 is occupied.

## Verification

```bash
./scripts/test-all.sh
```

This builds and starts the disposable stack, runs every Go suite with the race
detector and `go vet`, checks/tests Rego, runs Python security and gateway
regressions, and runs the live end-to-end suite. PostgreSQL integration tests
use separate `payment_checks` and `telemetry_checks` databases, including
migration rollbacks, immutable ledger constraints, filtering, trace joins,
and retention. Live tests cover monetary precision, sender ownership, forged
and expired tokens, mTLS and TLS version rejection, simultaneous transfers,
dependency outages/recovery, restart persistence, global rate limiting,
trace joins, and log delivery. Reports are written to ignored `test-results/`.

The live suite changes balances only in the disposable `dss-e2e` database.
Leave the stack running to inspect the dashboards, or remove its containers with
`docker compose -p dss-e2e -f docker-compose.yml -f compose.test.yml down`.
Named volumes retain certificates and observability data. PostgreSQL test data
lives in the container and is disposable.

## Financial contract limits

The supplied contract debits the sender and records the receiver in the ledger;
it does not define a receiver-credit API. It also defines deduction and ledger
append as two separate service operations. A crash or ledger outage after a
successful debit requires reconciliation, as the payment implementation records
in its error audit. Automatic retry/idempotency, receiver credit, and a durable
saga are separate financial protocol changes; this implementation follows the
existing debit-then-ledger contract.

Earlier component decision documents describe their original milestones.
This README and the root Compose files describe the integrated deployment.
