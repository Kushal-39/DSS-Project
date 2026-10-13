# Proof of Concept: reproducible demonstration and test runbook

Run the numbered sections in order, in **one Bash terminal**, from the repository root. Every `dc` and `demo` command below targets the disposable **`dss-e2e`** project. The normal deployment on port `8080` can stay running.

A negative test **passes** when the system produces the documented refusal and leaves balances/ledger rows unchanged. The helper exits with an error if an HTTP result differs from `--expect`.

## 1. Explain what the PoC demonstrates

```mermaid
sequenceDiagram
    participant C as Client
    participant G as Gateway
    participant I as IdP
    participant P as Payment
    participant O as OPA
    participant A as Account
    participant T as Telemetry
    C->>G: POST /login, JSON credentials
    G->>I: Forward login
    I-->>C: RS256 JWT through gateway
    C->>G: Transfer + Bearer JWT
    G->>I: Fetch/cache JWKS
    G->>P: Forward JWT + trace context over mTLS 1.3
    P->>P: Revalidate JWT and bind sender
    P->>O: Authorize TRANSFER
    O-->>P: result.allow
    P->>A: Synchronous deduction over mTLS 1.3
    A->>A: Revalidate JWT, ownership, balance/status
    A->>O: Independently authorize deduction
    O-->>A: result.allow
    A->>A: Atomic conditional balance update
    A-->>P: Deduction result
    P->>P: Append immutable ledger row
    P-->>C: Transaction through gateway
    G-->>T: Structured logs + spans
    I-->>T: Structured logs + spans
    P-->>T: Structured logs + spans
    A-->>T: Structured logs + spans
    O-->>T: Console decision logs via collector
```

**Presentation claims supported by the demos:** identity is verified at multiple boundaries; an authenticated user can still be denied; trusted transport and authorization are separate checks; concurrent deductions cannot overdraw; policy failures stop money movement; decisions and spans can be correlated.

**Scope to state explicitly:** this PoC debits a sender and records a receiver in an immutable transaction. The supplied contract has no receiver-credit API. Debit and ledger append are separate commits; a crash after debit requires reconciliation. The public demo ingress is HTTP. mTLS protects gateway → account/payment and payment → account. IdP/JWKS, OPA, and the default telemetry channel use their documented internal HTTP endpoints; telemetry ingest additionally requires its token. OIDC discovery is minimal, and `/token` is a JSON-login alias rather than a complete OAuth2 grant implementation.

## 2. Prerequisites and terminal setup

On another machine, adjust the repository and key paths in the setup block.

Required: Bash, Docker with Compose supporting `!override`, `git-crypt`, Python with `venv`, Go, and `curl`. **`jq` is not required.**

```bash
cd /home/manroy/Desktop/DSS-Project

docker --version
docker compose version
go version
python3 --version

# Run once if the environment is still encrypted.
git-crypt unlock /home/manroy/DSS.key

python3 -m venv .venv-test
.venv-test/bin/pip install -r account-service/requirements.txt -r tests/requirements.txt

export TELEMETRY_DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
# 55433 avoids the other project's PostgreSQL currently using 55432.
export DSS_TEST_DATABASE_PORT=55433
# Use the default open read dashboard for the initial presentation.
export TELEMETRY_READ_TOKEN=""

export BASE=http://127.0.0.1:18080
export AUDIT=http://127.0.0.1:18088
export CUSTOMER=22222222-2222-4222-8222-222222222222
export ADMIN=11111111-1111-4111-8111-111111111111

dc() {
  docker compose -p dss-e2e -f docker-compose.yml -f compose.test.yml "$@"
}
demo() {
  .venv-test/bin/python scripts/poc-demo.py "$@"
}
sql() {
  dc exec -T postgres psql -U postgres -d dss_test -v ON_ERROR_STOP=1 -c "$1"
}
wait_http() {
  local path=$1 expected=$2 code
  for attempt in $(seq 1 45); do
    code=$(curl --max-time 3 -s -o /dev/null -w '%{http_code}' "$BASE$path") || code=000
    if [ "$code" = "$expected" ]; then
      printf '%s -> HTTP %s\n' "$path" "$code"
      return 0
    fi
    sleep 1
  done
  printf 'Timed out waiting for %s -> %s\n' "$path" "$expected"
  return 1
}
login_tokens() {
  TOKEN=$(curl -fsS "$BASE/login" -H 'Content-Type: application/json' \
    -d '{"username":"customer","password":"customer123","device_id":"presentation-laptop"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
  ADMIN_TOKEN=$(curl -fsS "$BASE/login" -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"admin123","device_id":"presentation-laptop"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
  export TOKEN ADMIN_TOKEN
}
```

Keep terminal tracing (`set -x`) off and keep `.env` and private keys off screen. The usernames/passwords above are the documented development seed credentials. Tokens are stored in shell variables; the demo helper omits issued tokens from its printed login response.

If a different machine uses port `55433`, select another unused port with `DSS_TEST_DATABASE_PORT` **before startup**. The helpers, test runner, and test database connections all honor this variable. All other demo ports are listed below.

## 3. Build and establish the baseline

```bash
dc up --build -d --wait --wait-timeout 180
dc ps -a

demo http GET /healthz --expect 200
demo http GET /readyz --expect 200

demo reset --balance 1000.00
demo state
```

**Expected:** request-path services and telemetry/collector are healthy; certificate provisioning has exited `0`; customer balance is `1000.00`, status `ACTIVE`. The administrator starts with `5000.00` on a new database. Existing ledger rows remain: reset changes only the customer's test balance/status, so compare ledger **deltas**, not an assumed zero count.

| Demo component | URL/port |
| --- | --- |
| Gateway | `http://127.0.0.1:18080` |
| Audit dashboard | `http://127.0.0.1:18088/dashboard` |
| Collector readiness/metrics | `http://127.0.0.1:18089/readyz`, `/metrics` |
| Jaeger | `http://127.0.0.1:26686` |
| Loki API | `http://127.0.0.1:13100` |
| Grafana log dashboard | `http://127.0.0.1:13300/d/zt-logs` |
| Disposable PostgreSQL | `127.0.0.1:$DSS_TEST_DATABASE_PORT`, database `dss_test` |

The shell `sql` helper is **test setup/evidence**. In application traffic, payment calls account's API; it never queries `accounts` directly.

## 4. Identity: login, discovery, and failed credentials

### 4.1 Login succeeds

```bash
demo http POST /login --expect 200 \
  --data '{"username":"customer","password":"customer123","device_id":"presentation-laptop"}'
login_tokens
```

**Expected:** HTTP `200`, `token_type: Bearer`, `expires_in`, user UUID and role. The helper replaces token values with `[token omitted]` in its displayed response.

Decode the stored token's claims for the presentation:

```bash
.venv-test/bin/python - <<'PY'
import os,json,jwt
claims=jwt.decode(os.environ['TOKEN'],options={'verify_signature':False})
print(json.dumps(claims,indent=2))
PY
```

**Expected:** `sub` is the customer UUID, `roles` is `["customer"]`, device ID is present, and `iss`, `aud`, `exp`, `iat`, `jti` exist. This command displays claims; the actual signature checks are exercised by the API success/rejection demos below. Tokens normally expire after 15 minutes; rerun `login_tokens` during a long presentation.

### 4.2 Public discovery and endpoint aliases work

```bash
demo http GET /.well-known/openid-configuration --expect 200
demo http GET /.well-known/jwks.json --expect 200
demo http GET /jwks.json --expect 200
demo http POST /token --expect 200 \
  --data '{"username":"customer","password":"customer123"}'
```

**Expected:** JWKS contains an RSA signing key with `alg: RS256` and a `kid`; discovery identifies the issuer/JWKS/token endpoint. `/token` returns the same login response shape.

### 4.3 Wrong password and nonexistent user are denied

```bash
demo http POST /login --expect 401 \
  --data '{"username":"customer","password":"wrong"}'
demo http POST /login --expect 401 \
  --data '{"username":"ghost","password":"wrong"}'
```

**Expected:** both return `invalid_credentials` with the same public message. User existence is not exposed in that message.

Malformed credentials are a different failure:

```bash
demo http POST /login --expect 400 --data '{"username":"customer"}'
curl -sS -i "$BASE/login" -H 'Content-Type: text/plain' -d 'not-json'
```

**Expected:** missing password → `400`; unsupported content type → `415`.

## 5. Central policy: explicit allow and deny matrix

These commands call the **real OPA engine from inside Docker**, using the documented nested `input` shape. The helper prints the submitted input, HTTP status, returned decision, and expected decision, and asserts they match.

**Critical distinction:** a syntactically valid OPA query normally returns HTTP `200` even for a refusal: `{"result":{"allow":false}}`. Business services interpret that decision and return `403`.

Execute every command:

| Command | Expected `result.allow` | What to explain |
| --- | --- | --- |
| `demo policy allow` | `true` | Customer, 50, verified mTLS |
| `demo policy boundary` | `true` | Customer threshold includes exactly 50000 |
| `demo policy over-limit` | `false` | 50000.01 exceeds customer threshold |
| `demo policy zero` | `false` | Zero does not move a positive amount |
| `demo policy negative` | `false` | Negative amount refused |
| `demo policy string-amount` | `false` | Policy amount must be numeric |
| `demo policy no-mtls` | `false` | Connection context is not verified |
| `demo policy guest` | `false` | Guest lacks the customer/admin role |
| `demo policy unknown-action` | `false` | Customer action has no allow rule |
| `demo policy empty` | `false` | Default deny on empty input |
| `demo policy flat` | `false` | Incorrect nesting/flat roles |
| `demo policy unwrapped` | `false` | Missing OPA `input` envelope |
| `demo policy admin` | `true` | Documented admin override permits 60000 |
| `demo policy admin-no-mtls` | `false` | Admin still needs verified transport context |
| `demo policy read-own` | `true` | Customer reading their own resource |
| `demo policy read-other` | `false` | Customer reading another user's resource |

Copy/paste batch version:

```bash
for case in allow boundary over-limit zero negative string-amount no-mtls guest \
  unknown-action empty flat unwrapped admin admin-no-mtls read-own read-other; do
  demo policy "$case" || break
done
```

Show malformed JSON separately:

```bash
dc exec -T account-service python - <<'PY'
import httpx
r=httpx.post('http://policy-engine:8181/v1/data/authz/allow',
             content='{broken',headers={'Content-Type':'application/json'})
print('HTTP',r.status_code,r.text)
assert r.status_code==400
PY
```

**Expected:** malformed JSON → HTTP `400`, rather than a valid policy decision. Direct policy calls do not change accounts or the ledger. The admin rule is a privileged override; describe the 50000 limit specifically as the **customer** transfer policy.

## 6. Account reads: ownership and admin permissions

```bash
login_tokens
demo http GET /api/v1/accounts --token-env TOKEN --expect 200
demo http GET "/api/v1/accounts/$CUSTOMER" --token-env TOKEN --expect 200
demo http GET "/api/v1/accounts/$ADMIN" --token-env TOKEN --expect 403
demo http GET "/api/v1/accounts/$CUSTOMER" --token-env ADMIN_TOKEN --expect 200
demo http GET /api/v1/accounts --expect 401
demo http GET /api/v1/accounts/33333333-3333-4333-8333-333333333333 \
  --token-env ADMIN_TOKEN --expect 404
```

**Expected:** owner read `200`; customer reading the admin `403`; admin reading customer `200`; missing JWT `401`; authorized read of nonexistent account `404`. Account reads also query OPA before returning data. No balance/ledger mutation occurs.

## 7. Successful money flow and exact monetary values

### 7.1 Transfer succeeds and records exactly one row

```bash
demo reset --balance 1000.00
demo state

demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 200 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":50.00}"

demo state
sql 'SELECT txn_id,sender_id,receiver_id,amount,created_at FROM transactions ORDER BY created_at DESC LIMIT 3;'
```

**Expected:** response has `txn_id`, sender/receiver IDs, numeric amount, timestamp. Customer balance becomes `950.00`; ledger count increases by **one**. The administrator's balance is unchanged because receiver credit is outside the supplied contract.

**Presentation evidence:** show before/after state and the newest immutable transaction. Explain the two independent OPA checks: payment authorizes the request, then account authorizes its own deduction.

### 7.2 One cent is preserved exactly

```bash
demo reset --balance 1000.00
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 200 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":0.01}"
demo state
```

**Expected:** `999.99` balance and one new `0.01` transaction; fractional cents are rejected later.

### 7.3 Documented gateway alias works

```bash
demo reset --balance 1000.00
demo http POST /api/v1/payment --token-env TOKEN --expect 200 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":50.00}"
demo state
```

**Expected:** same transfer behavior and `950.00` balance.

### 7.4 Direct account deduction works

```bash
demo reset --balance 1000.00
demo state
demo http POST /api/v1/accounts/deduct --token-env TOKEN --expect 200 \
  --data "{\"user_id\":\"$CUSTOMER\",\"amount\":50.00}"
demo state
```

**Expected:** successful deduction, remaining balance `950.00`. **Ledger count stays unchanged:** this is the account deduction API, not payment orchestration.

## 8. Business and policy failures leave data unchanged

Use `demo state` immediately before and after each refusal. Compare both balance and ledger count.

### 8.1 Customer policy denies despite sufficient funds

```bash
demo reset --balance 100000.00
demo state
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 403 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":50000.01}"
demo state
```

**Expected:** `policy_denied`, balance still `100000.00`, no new transaction. This separates authorization from balance availability.

Verify the positive boundary through the complete flow:

```bash
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 200 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":50000.00}"
demo state
```

**Expected:** balance `50000.00` and exactly one new transaction.

### 8.2 Insufficient balance

```bash
demo reset --balance 10.00
demo state
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 400 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":50.00}"
demo http POST /api/v1/accounts/deduct --token-env TOKEN --expect 403 \
  --data "{\"user_id\":\"$CUSTOMER\",\"amount\":50.00}"
demo state
```

**Expected:** payment maps account refusal to `400`; direct account deduction returns `403`. Balance stays `10.00`; ledger count stays unchanged.

### 8.3 Inactive account

```bash
demo reset --balance 1000.00
sql "UPDATE accounts SET status='SUSPENDED' WHERE user_id='$CUSTOMER';"
demo state
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 400 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1.00}"
demo state
demo reset --balance 1000.00
```

**Expected:** no deduction/ledger row while suspended. The final reset restores `ACTIVE`.

### 8.4 Sender ownership and missing sender account

```bash
demo state
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 403 \
  --data "{\"sender_id\":\"$ADMIN\",\"receiver_id\":\"$CUSTOMER\",\"amount\":1.00}"
demo http POST /api/v1/accounts/deduct --token-env TOKEN --expect 403 \
  --data "{\"user_id\":\"$ADMIN\",\"amount\":1.00}"
demo http POST /api/v1/payments/transfer --token-env ADMIN_TOKEN --expect 400 \
  --data "{\"sender_id\":\"33333333-3333-4333-8333-333333333333\",\"receiver_id\":\"$CUSTOMER\",\"amount\":1.00}"
demo state
```

**Expected:** customer cannot debit admin. Admin's missing-sender request reaches account validation but is refused; no row is recorded. All balances remain unchanged.

## 9. Input validation: invalid requests are denied

```bash
demo reset --balance 1000.00
demo state
for amount in 0 -1 0.001 100000000.00 '"50.00"' NaN Infinity; do
  demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 400 \
    --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":$amount}"
done

demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 400 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$CUSTOMER\",\"amount\":1}"
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 400 \
  --data "{\"sender_id\":\"not-a-uuid\",\"receiver_id\":\"$ADMIN\",\"amount\":1}"
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 400 --data '{broken'
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 400 --data '{}'
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 400 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1,\"unexpected\":true}"
demo http POST /api/v1/accounts/deduct --token-env TOKEN --expect 422 \
  --data "{\"user_id\":\"$CUSTOMER\",\"amount\":0.001}"
demo state
```

**Expected:** payment invalid syntax/amount/UUID/self-transfer/unknown field → `400`; FastAPI account schema rejection → `422`; no data mutation. `NaN` and `Infinity` above deliberately produce non-standard JSON numeric tokens and must be refused. Transfer amounts are unquoted JSON numbers; account deduction additionally accepts decimal strings.

## 10. JWT rejection and independent backend verification

### 10.1 Missing token

```bash
demo http POST /api/v1/payments/transfer --expect 401 --data '{}'
```

### 10.2 Tampered, wrong algorithm, expired, wrong issuer/audience, missing expiry

```bash
login_tokens
demo state
for case in tampered hs256 expired wrong-issuer wrong-audience no-exp; do
  BAD_TOKEN=$(demo token "$case")
  export BAD_TOKEN
  printf '\nJWT case: %s\n' "$case"
  demo http POST /api/v1/payments/transfer --token-env BAD_TOKEN --expect 401 \
    --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1}"
done
demo state
```

**Expected:** every case returns `401`, with no debit/ledger row. `tampered` changes the roles claim while retaining the original signature. `hs256` tests algorithm rejection. The expiry/issuer/audience cases use the development signing key **in memory** to isolate claim validation from signature validation; this controlled test capability is not an attacker capability.

### 10.3 Backends revalidate JWTs even on a valid mTLS connection

```bash
export BAD_TOKEN=forged-token
demo mtls account-service --path "/api/v1/accounts/$CUSTOMER" \
  --token-env BAD_TOKEN --expect 401
demo mtls payment-service --method POST --path /api/v1/payments/transfer \
  --token-env BAD_TOKEN --expect 401
```

**Expected:** transport succeeds with the trusted account-service client certificate, but both handlers return `401` for the bearer token. This proves validation is not delegated entirely to the gateway.

## 11. mTLS: successful transport, rejected peers, and restricted probe identity

The helper runs its client inside the account container. It reads mounted certificates without printing/exporting private keys. `status: 0` means **no HTTP response was obtained**, because the TLS exchange failed; it is not an HTTP status code.

### 11.1 Trusted certificate succeeds

```bash
demo mtls account-service --expect 200
demo mtls payment-service --expect 200
```

**Expected:** `/healthz` returns `200` over TLS 1.3 with a CA-issued client certificate.

### 11.2 No client certificate is refused, even with a JWT or spoofed headers

```bash
for service in account-service payment-service; do
  demo mtls "$service" --identity none --expect 0
  demo mtls "$service" --identity none --spoof --token-env TOKEN --expect 0
done
```

**Expected:** TLS refusal in every case. `X-Forwarded-Client-Cert` and `X-Client-Cert-Present` cannot manufacture a verified peer identity.

### 11.3 Certificate from an unrelated issuer is refused

```bash
demo mtls account-service --identity untrusted --expect 0
demo mtls payment-service --identity untrusted --expect 0
```

**Expected:** a generated unrelated/self-signed client credential is refused. The helper's temporary credential is removed when the client exits.

### 11.4 TLS 1.2 is refused

```bash
demo mtls account-service --tls12 --expect 0
demo mtls payment-service --tls12 --expect 0
```

**Expected:** refusal despite a trusted client certificate, because the server requires TLS 1.3.

### 11.5 Probe certificates can inspect health but cannot perform business operations

```bash
demo mtls account-service --identity probe --expect 200
demo mtls payment-service --identity probe --expect 200
demo mtls account-service --identity probe --path "/api/v1/accounts/$CUSTOMER" \
  --token-env TOKEN --expect 403
demo mtls payment-service --identity probe --method POST --path /api/v1/payments/transfer \
  --token-env TOKEN --expect 403
```

**Expected:** `200` for health, `403` for business routes. These refusals occur after a successful TLS handshake: valid CA membership alone does not grant business authority.

### 11.6 Backend bypass ports and private-key isolation

```bash
dc ps
for service in idp account-service payment-service; do
  docker inspect --format '{{json .NetworkSettings.Ports}}' "$(dc ps -q "$service")"
done

dc exec -T gateway python -c 'import os; print(sorted(os.listdir("/certs")))'
dc exec -T account-service python -c 'import os; print(sorted(os.listdir("/certs")))'
dc exec -T payment-service sh -c \
  'test ! -e /certs/ca.key && test ! -e /certs/gateway.key && test ! -e /certs/account-server.key && echo "Unrelated private keys absent"'
```

**Expected:** backend exposed ports have no host binding (`null`); gateway certificate directory contains only `ca.crt`, `gateway.crt`, `gateway.key`; no runtime mounts `ca.key`. Display filenames, not contents.

## 12. Concurrent deductions: exact result, not just successful requests

```bash
login_tokens
demo reset --balance 100.00
.venv-test/bin/python - <<'PY'
import asyncio,os,json
from collections import Counter
import asyncpg,httpx
CUSTOMER='22222222-2222-4222-8222-222222222222'
ADMIN='11111111-1111-4111-8111-111111111111'
async def main():
    port=int(os.getenv('DSS_TEST_DATABASE_PORT','55432'))
    db=await asyncpg.connect(f'postgres://postgres:dss-test@127.0.0.1:{port}/dss_test?sslmode=disable')
    try:
        before=await db.fetchval('SELECT count(*) FROM transactions')
        async with httpx.AsyncClient(timeout=20) as client:
            semaphore=asyncio.Semaphore(12)
            async def transfer():
                async with semaphore:
                    r=await client.post('http://127.0.0.1:18080/api/v1/payments/transfer',
                        headers={'Authorization':'Bearer '+os.environ['TOKEN']},
                        json={'sender_id':CUSTOMER,'receiver_id':ADMIN,'amount':10})
                    return r.status_code
            results=await asyncio.gather(*(transfer() for _ in range(20)))
        balance=await db.fetchval('SELECT balance FROM accounts WHERE user_id=$1::uuid',CUSTOMER)
        after=await db.fetchval('SELECT count(*) FROM transactions')
        counts=Counter(results)
        print(json.dumps({'HTTP_counts':dict(counts),'balance':str(balance),'new_ledger_rows':after-before},indent=2))
        assert counts=={200:10,400:10} and balance==0 and after-before==10
    finally:
        await db.close()
asyncio.run(main())
PY
demo state
demo reset --balance 1000.00
```

**Expected:** ten `200`s, ten `400`s, balance `0.00`, exactly ten new transactions. The account's conditional SQL update makes the deduction atomic despite simultaneous authorization/balance reads. Run without other clients changing demo balances concurrently.

## 13. Dependency outages: fail closed and recover

Refresh tokens and establish a controlled balance first:

```bash
login_tokens
demo reset --balance 1000.00
```

### 13.1 OPA unavailable

```bash
demo state
dc stop policy-engine
demo http GET /healthz --expect 200
demo http GET /readyz --expect 503
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 403 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1}"
demo state

dc up -d --wait policy-engine
wait_http /readyz 200
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 200 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1}"
```

**Expected during outage:** process liveness `200`, readiness `503`, payment `403` with `policy_unavailable`; no money moves. **After recovery:** successful request, one-unit debit and one new transaction. Policy dependency failure is logged with an error verdict as well as its public HTTP response.

### 13.2 Account unavailable

```bash
demo state
dc stop account-service
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 400 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1}"
demo state

dc up -d --wait account-service
wait_http /readyz 200
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 200 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1}"
```

**Expected:** `400` with `deduction_unavailable`, no ledger row, unchanged stored balance. The test database remains available to `demo state` while account's API is down. Recovery restores successful transfers.

### 13.3 IdP/JWKS unavailable with a cold verification cache

```bash
demo state
dc stop idp
# Clear the gateway's cached JWKS by restarting it.
dc restart gateway
wait_http /healthz 200

demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 503 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1}"
demo state

dc up -d --wait idp
wait_http /readyz 200
login_tokens
demo http GET /api/v1/accounts --token-env TOKEN --expect 200
```

**Expected:** `503 verification_unavailable`, with no debit/ledger row. A fresh cached public key may continue validating tokens during a short IdP outage; restarting gateway deliberately exercises the unavailable-key path. This is distinct from bad credentials (`401`).

### 13.4 Telemetry unavailable: business path remains available

```bash
demo reset --balance 1000.00
dc stop telemetry
demo http POST /api/v1/payments/transfer --token-env TOKEN --expect 200 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1}"
demo state

dc up -d --wait telemetry telemetry-collector
curl -sS http://127.0.0.1:18089/metrics
```

**Expected:** successful one-unit transfer while telemetry is down. Spans are best-effort asynchronous exports and can be lost during an outage; audit decisions remain in producer stdout. Observe collector retry/delivery counters during recovery. Failure counters are cumulative, so a past outage does not make them return to zero.

### 13.5 Ledger-write failure and reconciliation evidence

Run the specific orchestration regression:

```bash
(cd payment-service && go test -race -v ./internal/payments \
  -run '^TestTransferReportsALedgerFailureWithEvidenceForReconciliation$')
```

**Expected:** `PASS`; the test asserts HTTP-layer failure semantics and evidence for reconciliation after a successful deduction followed by a failed ledger write. This uses controlled collaborators, not a live database outage. State the limitation from section 1 instead of claiming distributed atomicity or automatic compensation.

## 14. Ledger immutability, migrations, and restart persistence

### 14.1 Ledger rows cannot be edited, deleted, or truncated

Ensure section 7 has created at least one transaction, then run:

```bash
sql 'SELECT count(*) AS before_count FROM transactions;'
sql 'UPDATE transactions SET amount=999.99;'
sql 'DELETE FROM transactions;'
sql 'TRUNCATE transactions;'
sql 'SELECT count(*) AS after_count FROM transactions;'
```

**Expected:** each mutating SQL command fails with an append-only error; before/after counts match. These are expected non-zero command exits—run each command separately if your shell has `set -e` enabled. Original amounts remain unchanged. An `UPDATE`/`DELETE` on an empty table would touch no rows; use a populated ledger for this proof.

### 14.2 Each service has its own migration bookkeeping

```bash
sql "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;"
sql 'SELECT version,dirty FROM idp_schema_migrations;'
sql 'SELECT version,dirty FROM payment_schema_migrations;'
sql 'SELECT version,dirty FROM telemetry_schema_migrations;'
sql 'SELECT version FROM _account_schema_migrations;'
```

**Expected:** `credentials`, `accounts`, `transactions`, `audit_events`, `spans`; independent migration tables. Go migrations report version `1`, `dirty=false`; account records `001_init.up.sql`. Startup applies migrations and seeds idempotently.

### 14.3 Restart does not reset balances or ledger rows

```bash
BEFORE_RESTART=$(demo state)
dc restart idp account-service payment-service
wait_http /readyz 200
AFTER_RESTART=$(demo state)
[ "$BEFORE_RESTART" = "$AFTER_RESTART" ] && echo 'PASS: balances/status/ledger count preserved'
demo http GET /api/v1/accounts --token-env TOKEN --expect 200
```

**Expected:** stored state and pre-restart token continue to work. The RSA key is stable; seed scripts do not overwrite balances on conflict.

## 15. Global rate limiting and recovery

Run this **after** ordinary HTTP demos, so intentional throttling does not interfere with them.

```bash
dc restart gateway
wait_http /healthz 200
.venv-test/bin/python - <<'PY'
from collections import Counter
import httpx
with httpx.Client(timeout=10) as client:
    responses=[client.get('http://127.0.0.1:18080/unregistered') for _ in range(125)]
counts=Counter(r.status_code for r in responses)
print('HTTP counts:',dict(counts))
throttled=[r for r in responses if r.status_code==429]
assert throttled and int(throttled[0].headers['retry-after'])>0
print('Retry-After:',throttled[0].headers['retry-after'])
PY

dc restart gateway
wait_http /readyz 200
demo http GET /unregistered --expect 404
```

**Expected:** with default limit 120/window 60 seconds and no concurrent public requests, normally 120 `404`s then five `429`s; `Retry-After` is positive. Platform health probes are exempt. Resetting gateway clears the window; alternatively wait for the window to expire. If `GATEWAY_RATE_LIMIT`/`GATEWAY_RATE_WINDOW` were customized, use their configured values rather than asserting the default count.

## 16. Show a real joined trace across the system

Create a new trace and use it for login plus a successful transfer:

```bash
demo reset --balance 1000.00
TRACE_ID=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
TRACEPARENT="00-$TRACE_ID-$(python3 -c 'import secrets; print(secrets.token_hex(8))')-01"
export TRACE_ID TRACEPARENT
TOKEN=$(curl -fsS "$BASE/login" -H 'Content-Type: application/json' -H "traceparent: $TRACEPARENT" \
  -d '{"username":"customer","password":"customer123","device_id":"presentation-laptop"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
export TOKEN

demo http POST /api/v1/payments/transfer --token-env TOKEN --trace "$TRACEPARENT" --expect 200 \
  --data "{\"sender_id\":\"$CUSTOMER\",\"receiver_id\":\"$ADMIN\",\"amount\":1}"
```

Wait for asynchronous delivery and assert the join:

```bash
.venv-test/bin/python - <<'PY'
import os,time,json,httpx
url='http://127.0.0.1:18088/v1/audit/traces/'+os.environ['TRACE_ID']
end=time.monotonic()+35
while time.monotonic()<end:
    response=httpx.get(url,timeout=5)
    if response.status_code==200:
        flow=response.json()['trace']
        spans={s['service'] for s in flow['spans']}
        events={e['service'] for e in flow['events']}
        if {'gateway','idp','payment-service','account-service'}<=spans and {'gateway','idp','payment-service','account-service','policy-engine'}<=events:
            print(json.dumps({'trace_id':flow['trace_id'],'span_services':sorted(spans),
                'event_services':sorted(events),'span_count':len(flow['spans']),
                'event_count':len(flow['events'])},indent=2))
            break
    time.sleep(.5)
else:
    raise AssertionError('Trace join did not arrive within 35 seconds')
PY
curl -sS "$AUDIT/v1/audit/traces/$TRACE_ID" | python3 -m json.tool
```

**Expected:** same trace ID throughout; server spans for gateway, IdP, payment, account; payment dependency spans for policy/account calls; decisions from all five request-path components, including OPA. OPA decisions join through the trace context in policy input; OPA does not emit its own server span in this deployment.

### What to display in the browser

1. Open `http://127.0.0.1:18088/dashboard`. Scroll to **Trace explorer — one flow across all components**, paste `$TRACE_ID` into the W3C trace-ID input, and click **Inspect**. Show decisions, denials, source services, and the timeline.
2. Open `http://127.0.0.1:26686`. Select `payment-service` or `gateway`, find recent traces, and show parent/child spans.
3. Open `http://127.0.0.1:13300/d/zt-logs`. Show log volume and blocked-request panels; use Grafana Explore with `{service="payment-service"}` or `{service="gateway"}`. A trace-bearing log can pivot into Jaeger.
4. Show the collector's readiness and delivery metrics:

```bash
curl -sS http://127.0.0.1:18089/readyz
curl -sS http://127.0.0.1:18089/metrics
curl -sS "$AUDIT/v1/audit/summary?window=15m" | python3 -m json.tool
curl -sS "$AUDIT/v1/audit/events?decision=DENY&limit=10" | python3 -m json.tool
curl -sS "$AUDIT/v1/audit/events?category=AUTHZ&limit=10" | python3 -m json.tool
curl -sS http://127.0.0.1:13100/loki/api/v1/label/service/values | python3 -m json.tool
```

**Expected:** collector ready and following this project's containers; records delivered; summary contains permits/denials/errors and service/category counts; denial samples include earlier tests. Counts are **audit events**, not unique requests—a single request may emit multiple decisions. Loki retains operational/plain logs too; the audit trail keeps security signals. Rejections before TLS completion have no HTTP trace header but should appear as transport-denial events.

## 17. Telemetry API: authentication, receipts, deduplication, OTLP

Obtain the ingest token into a variable without printing it:

```bash
INGEST_TOKEN=$(dc exec -T telemetry sh -c 'printf %s "$TELEMETRY_INGEST_TOKEN"')
export INGEST_TOKEN
python3 - <<'PY'
import json,os
from datetime import datetime,timezone
record={'time':datetime.now(timezone.utc).isoformat(),'service':'poc-demo',
        'msg':'access_decision','decision':'deny','reason':'presentation_test',
        'action':'TRANSFER','resource':'account_demo',
        'user_id':os.environ['CUSTOMER'],'traceparent':os.environ['TRACEPARENT']}
with open('/tmp/dss-poc-event.json','w') as f: json.dump(record,f)
PY
```

### 17.1 Missing/wrong ingest credentials fail

```bash
curl -sS -i "$AUDIT/v1/audit/events" -H 'Content-Type: application/json' --data-binary @/tmp/dss-poc-event.json
curl -sS -i "$AUDIT/v1/audit/events" -H 'Content-Type: application/json' \
  -H 'X-Telemetry-Token: deliberately-wrong' --data-binary @/tmp/dss-poc-event.json
```

**Expected:** `401` for both.

### 17.2 Correct credentials succeed; identical retry is deduplicated

```bash
curl -sS "$AUDIT/v1/audit/events" -H 'Content-Type: application/json' \
  -H "X-Telemetry-Token: $INGEST_TOKEN" --data-binary @/tmp/dss-poc-event.json
curl -sS "$AUDIT/v1/audit/events" -H 'Content-Type: application/json' \
  -H "X-Telemetry-Token: $INGEST_TOKEN" --data-binary @/tmp/dss-poc-event.json
curl -sS "$AUDIT/v1/audit/events?service=poc-demo&limit=5" | python3 -m json.tool
```

**Expected:** first receipt `accepted:1`; second `accepted:0, duplicates:1`. Keep the original timestamp/payload unchanged between submissions. Receipt counts may also include `skipped:0`.

### 17.3 Structured stdout/NDJSON ingestion and noise filtering

```bash
printf '%s\n' '{"msg":"startup_banner_without_a_verdict"}' > /tmp/dss-poc-noise.ndjson
curl -sS "$AUDIT/v1/audit/logs" -H 'Content-Type: application/x-ndjson' \
  -H "X-Telemetry-Token: $INGEST_TOKEN" --data-binary @/tmp/dss-poc-noise.ndjson
```

**Expected:** `accepted:0, skipped:1`. A startup line without security signal does not inflate audit counters.

### 17.4 Valid OTLP/JSON succeeds; malformed or protobuf exports fail

```bash
curl -sS -i "$AUDIT/v1/traces" -H 'Content-Type: application/json' \
  -H "X-Telemetry-Token: $INGEST_TOKEN" -d '{"resourceSpans":[]}'
curl -sS -i "$AUDIT/v1/logs" -H 'Content-Type: application/json' \
  -H "X-Telemetry-Token: $INGEST_TOKEN" -d '{"resourceLogs":[]}'
curl -sS -i "$AUDIT/v1/traces" -H 'Content-Type: application/json' \
  -H "X-Telemetry-Token: $INGEST_TOKEN" -d '{broken'
curl -sS -i "$AUDIT/v1/logs" -H 'Content-Type: application/x-protobuf' \
  -H "X-Telemetry-Token: $INGEST_TOKEN" -d 'not-a-json-export'
```

**Expected:** empty valid exports `200` with zero accepted; malformed JSON `400`; protobuf `415` with guidance to select `http/json`. Section 16 already demonstrated ingestion/storage/mirroring of actual nonempty spans.

### 17.5 Optional read protection and dashboard sign-in

```bash
export TELEMETRY_READ_TOKEN=poc-read-token
dc up -d --wait telemetry telemetry-collector

curl -sS -i "$AUDIT/v1/audit/summary?window=15m"
curl -sS -i "$AUDIT/v1/audit/summary?window=15m" -H 'Authorization: Bearer wrong'
curl -sS -i "$AUDIT/v1/audit/summary?window=15m" -H 'Authorization: Bearer poc-read-token'
curl -sS -i "$AUDIT/dashboard?token=poc-read-token" -c /tmp/dss-poc-cookies.txt
curl -sS -o /dev/null -w 'Dashboard with cookie: %{http_code}\n' "$AUDIT/dashboard" -b /tmp/dss-poc-cookies.txt
curl -sS -o /dev/null -w 'Readiness: %{http_code}\n' "$AUDIT/readyz"

# Restore the initial demo configuration before further tests.
export TELEMETRY_READ_TOKEN=""
dc up -d --wait telemetry telemetry-collector
```

**Expected:** absent/wrong read token `401`; correct bearer `200`; dashboard token exchange `302` to `/dashboard` plus `HttpOnly; SameSite=Strict` cookie; cookie request `200`. Health/readiness endpoints remain `200` without read credentials. The public demo token is a presentation setting, not the actual ingest secret.

## 18. Automated proof for remaining operational behavior

These targeted tests use generated credentials/controlled clocks or the disposable SQL databases rather than requiring manual certificate edits and long retention waits.

```bash
# Payment stays responsive with a stalled TLS peer; foreign CA is refused.
(cd payment-service && go test -race -v ./internal/mtls \
  -run 'TestStalledHandshakeCannotBlockAValidClient|TestListenerRefusesACertificateFromAnotherCA')

# A dead exporter cannot block transfers; exporter shutdown is race-safe.
(cd payment-service && go test -race -v ./internal/tracing \
  -run 'TestRecordNeverBlocksOnADeadExporter|TestConcurrentRecordAndShutdown')

# Optional telemetry mTLS, credential log hygiene, future timestamps,
# OTLP log/trace joining, and protected dashboard/cookie handling.
(cd telemetry && go test -race -v ./internal/api)

# Collector discovery, filtering, bounded queues, retries and shutdown flush.
(cd telemetry && go test -race -v ./internal/collector)

# Gateway body bound/context-header sanitization and account stale-JWKS rejection.
PYTHONPATH="$PWD:$PWD/account-service" ENVIRONMENT=test \
  .venv-test/bin/python -m pytest tests/test_gateway.py tests/test_security.py -v
```

**Expected:** every test `PASS`; no race reports. Optional telemetry mTLS is tested with real generated handshakes but is not enabled in the baseline HTTP dashboard deployment.

Run **everything**, including real PostgreSQL immutability/constraints, isolated migration bookkeeping, up/down/reapply, filters/aggregates, trace joins, and retention:

```bash
./scripts/test-all.sh
```

**Expected for this revision:** 26 IdP Go tests/subtests, 139 payment, 218 telemetry; 22 policy tests; 31 Python regression tests; 33 end-to-end tests, all passing, no skips. Go modules also pass `go vet`. The runner creates separate `idp_checks`, `payment_checks`, and `telemetry_checks` databases in this project's PostgreSQL container for SQL tests; it does not roll back the active `dss_test` schema or the configured Supabase database.

Reports:

```bash
ls -lh test-results/
# python.xml and e2e.xml are JUnit; module .jsonl files are Go test events.
python3 - <<'PY'
import json
from pathlib import Path
import xml.etree.ElementTree as E
for path in Path('test-results').glob('*.jsonl'):
    counts={}
    for line in path.read_text().splitlines():
        try: event=json.loads(line)
        except ValueError: continue
        if 'Test' in event and event.get('Action') in {'pass','fail','skip'}:
            action=event['Action']; counts[action]=counts.get(action,0)+1
    print(path.name,counts)
for path in Path('test-results').glob('*.xml'):
    suite=E.parse(path).getroot().find('testsuite')
    print(path.name,{k:suite.attrib[k] for k in ['tests','failures','errors','skipped']})
PY
```

Counts can grow when new tests are added; zero failures/errors/skips is the criterion. The full runner changes demo balances, adds test ledger rows, and restarts demo dependencies. Finish manual screenshots before running it, then use `demo reset` and `login_tokens` to prepare another presentation.

## 19. Recommended 15-minute presentation order

| Time | Demonstration | Evidence to capture |
| --- | --- | --- |
| 0–2 min | Architecture, trust boundaries, healthy stack | Diagram and `dc ps` |
| 2–4 min | Login; wrong password; private account denial | `200`, `401`, `403` and role claims |
| 4–6 min | Policy allow, over-limit, no-mTLS, admin/no-mTLS | Input/decision pairs |
| 6–8 min | Successful transfer then sufficient-funds policy refusal | Before/after balance and ledger |
| 8–10 min | No certificate, TLS 1.2, probe business restriction | TLS refusal versus HTTP `403` |
| 10–12 min | Concurrent deductions and OPA outage | Exact 10/10 result; fail-closed/no mutation |
| 12–14 min | Trace/audit/Grafana views | One trace ID and all component decisions |
| 14–15 min | Automated reports and PoC limitations | Passing totals; debit/ledger reconciliation scope |

Keep the longer reproduction sections available for questions: malformed tokens, account suspension, JWKS cache behavior, rate limiting, immutable ledger, restart persistence, ingest deduplication, and protected dashboard sign-in.

## 20. Reset, cleanup, and troubleshooting

Prepare another presentation without discarding history:

```bash
demo reset --balance 1000.00
export TELEMETRY_READ_TOKEN=""
dc up -d --wait
login_tokens
```

Stop the demo stack and leave the normal deployment running:

```bash
dc stop
unset TOKEN ADMIN_TOKEN BAD_TOKEN INGEST_TOKEN
rm -f /tmp/dss-poc-event.json /tmp/dss-poc-noise.ndjson /tmp/dss-poc-cookies.txt
```

For a **fresh disposable database**, remove demo containers, then recreate them. This discards test PostgreSQL container data; named certificate/log/dashboard volumes remain:

```bash
dc down
dc up --build -d --wait --wait-timeout 180
demo reset --balance 1000.00
login_tokens
```

| Symptom | Reproduction fix |
| --- | --- |
| Port already in use | Inspect `docker ps` and `ss -ltnp`; use an unused `DSS_TEST_DATABASE_PORT` for PostgreSQL. Do not stop another project's process. |
| Token rejected midway | Rerun `login_tokens`; tokens expire. |
| Unexpected `429` in another demo | Finish rate-limit demo last; restart demo gateway and wait for readiness. |
| OPA direct refusal has HTTP `200` | Inspect `result.allow`; this is expected decision-API behavior. |
| Business HTTP `400` for low balance | Payment maps account `403` to the documented upstream-failure `400`. |
| Audit/Jaeger evidence appears late | Allow up to 35 seconds for collection/export/mirroring; verify collector `/readyz` and telemetry `/readyz`. |
| Collector cannot read socket | Set `TELEMETRY_DOCKER_GID` from `stat`; inspect `dc logs telemetry-collector`. |
| Dashboard unexpectedly `401` | Restore empty `TELEMETRY_READ_TOKEN` and recreate demo telemetry, or use the read-token sign-in step. |
| Concurrency count differs | Stop other demo clients; restore 100.00 balance, refresh token and rerun. |
| Immutability UPDATE/DELETE appears to succeed | Ensure at least one ledger row exists; an empty-table row trigger has no row to reject. |
| Startup/readiness failure | Run `dc logs --tail 60 idp account-service payment-service telemetry` and verify the unlocked environment and test PostgreSQL health. |
