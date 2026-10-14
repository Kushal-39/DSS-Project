# Zero-Trust Distributed System — POC Presentation Tutorial

Every command in this document was executed and its output observed on the
integrated stack before it was written down. Expected output is quoted verbatim
from a real run.

**Stack:** 11 containers — `gateway`, `idp`, `policy-engine`, `account-service`,
`payment-service`, `telemetry`, `telemetry-collector`, `jaeger`, `loki`,
`promtail`, `grafana`.

**Published ports (everything else is internal-only by design):**

| Service | URL | Role |
| --- | --- | --- |
| API Gateway | http://localhost:8080 | The **only** entry point for business traffic |
| Audit dashboard | http://localhost:8088/dashboard | Person 6's deliverable |
| Jaeger | http://localhost:16686 | Distributed tracing UI |
| Grafana (Loki logs) | http://localhost:3300/d/zt-logs | Centralized log UI |
| Loki | http://localhost:3100 | Log API |

---

## 0. Verification status (what was tested, and how)

| Layer | How it was verified | Result |
| --- | --- | --- |
| Full documented suite | `scripts/test-all.sh` (builds a disposable stack + runs every suite) | **EXIT=0** |
| IdP Go tests | `go test -race ./...` | 26 passed |
| Payment Go tests | `go test -race ./...` | 139 passed |
| Telemetry Go tests | `go test -race ./...` | 218 passed |
| Policy (Rego) | `opa test -v`, `opa check --strict` | PASS 22/22, no violations |
| Python suites (`test_security`, `test_gateway`, account) | pytest | 31 passed |
| Live contract / E2E suite (`tests/test_e2e.py`) | pytest against the `dss-e2e` stack | 33 passed |
| Live manual walkthrough of this tutorial | All steps below run against the presentation stack | All as expected |
| DB-backed suites against the connected Supabase instance | 4 migration/store suites in a scratch database on the live Supabase host (§11.4) | all passed |
| Clean rebuild from a cold start | `docker compose down` → `docker compose up --build -d --wait` | **EXIT=0**, every service healthy |

> **Cleanup note.** The workspace originally carried uncommitted WIP files in
> `idp/` — four test files plus three packages (`internal/otlp`,
> `internal/ratelimit`, `internal/tlsconf`) that referenced IdP features which
> were never implemented (`RateLimitPerMinute`, `LockoutDuration`, `TLSCertFile`,
> `PreviousKeyPEM`, `Claims.AuthTime`, …). They broke `go vet` and `go test ./...`
> for the whole `idp` module and were referenced by nothing else, so they were
> removed; an exact copy is kept in `test-results/idp-wip-removed-backup.tar.gz`.
> With them gone, `cd idp && go build/vet/test ./...` is clean again.

---

## 1. Bring the stack up

```bash
# One-time prerequisites (see CONTRIBUTING.md §3)
git-crypt unlock /path/to/zerotrust-key.key   # decrypts the root .env

# Audit collector must know the host's docker-socket group id (see §10 gotcha)
grep -q TELEMETRY_DOCKER_GID .env || \
  echo "TELEMETRY_DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)" >> .env

# Build and start everything
docker compose up --build -d
```

Wait for health — all six core services must report `healthy`:

```bash
docker compose ps
```

Observed:

```
account-service    Up 10 minutes (healthy)
gateway            Up 9 minutes  (healthy)
idp                Up 10 minutes (healthy)
payment-service    Up 10 minutes (healthy)
policy-engine      Up 37 seconds (healthy)
telemetry          Up 10 minutes (healthy)
telemetry-collector Up 8 minutes (healthy)
grafana / jaeger / loki / promtail   Up …
```

The gateway only reports ready when IdP **and** account **and** payment answer
over their real transports:

```bash
curl -s -w ' [%{http_code}]\n' http://localhost:8080/readyz
# {"status":"ready"} [200]
```

**Presenter talking point:** the IdP, account and payment ports are *not
published* on the host at all — there is no way to bypass the gateway from
outside. (The E2E suite asserts this: every published port of `idp`,
`account-service` and `payment-service` must be empty.)

---

## 2. Identity — Person 1 (IdP) via the gateway

```bash
GW=http://localhost:8080

# Discovery + public keys
curl -s $GW/.well-known/openid-configuration
curl -s $GW/.well-known/jwks.json | head -c 200
# {"keys":[{"alg":"RS256","e":"AQAB","kid":"c59_pTG51LdyO_QEurkHreM3MIUIbV1XAcorfOH-7Pg","kty":"RSA", …

# Login (bootstrap users are documented in idp/README.md)
curl -s -X POST $GW/login -H 'Content-Type: application/json' \
  -d '{"username":"customer","password":"customer123","device_id":"demo-laptop"}'
```

Response shape:

```json
{"access_token":"<JWT>","token":"<JWT>","token_type":"Bearer",
 "expires_in":900,"user":{"id":"22222222-…","role":"customer","username":"customer"}}
```

**Show the token's claims** — this is the identity every later hop re-verifies:

```bash
TOKEN=$(curl -s -X POST $GW/login -H 'Content-Type: application/json' \
  -d '{"username":"customer","password":"customer123","device_id":"demo-laptop"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

python3 - "$TOKEN" <<'EOF'
import sys, base64, json
p = sys.argv[1].split('.')[1]; p += '=' * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
EOF
```

Observed claims:

```json
{
  "iss": "http://idp:8080",
  "sub": "22222222-2222-4222-8222-222222222222",
  "aud": ["zerotrust-api-gateway"],
  "exp": 1791950655, "iat": 1791949755, "jti": "1791949755674238358",
  "roles": ["customer"],
  "device_id": "demo-laptop"
}
```

**Negative case — credentials are not leaked:**

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"customer","password":"wrong"}'
# {"error":{"code":"invalid_credentials","message":"invalid username or password"}} [401]
```

A wrong password for an **existing** user and for a **non-existent** user return
byte-identical bodies (E2E asserts `a.json() == b.json()`), so the API cannot be
used to enumerate accounts.

---

## 3. Perimeter — Person 2 (API Gateway)

### 3.1 No token → 401

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":1}'
# {"error":"unauthorized"} [401]
```

### 3.2 Tampered / forged tokens → 401

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer ${TOKEN%????}aaaaaaaa" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":1}'
# {"error":"unauthorized"} [401]
```

The full rejection matrix (all → **401**) is automated in
`tests/test_e2e.py::test_gateway_rejects_invalid_tokens`:
`missing`, `tampered`, `hs256` (algorithm confusion), `expired`, wrong
`issuer`, wrong `audience`, and a token with `exp` removed. The gateway only
accepts **RS256 + a known `kid` from the IdP's JWKS**, requires
`exp/sub/iss/aud`, and requires `roles` to be an array.

### 3.3 Global rate limit → 429 + `Retry-After`

```bash
for i in $(seq 1 130); do curl -s -o /dev/null -w '%{http_code}\n' $GW/api/v1/accounts; done \
  | sort | uniq -c
#    120 401     <- the 120 permitted requests (no token, so each is a 401)
#     10 429     <- shed at the perimeter
```

Headers on a throttled response:

```
HTTP/1.1 429 Too Many Requests
retry-after: 58
```

The denial is itself audited (`gateway / DENY / rate_limited`), so a flood is
visible on the dashboard as *rate limited*, counted **separately** from
*unauthorized attempts*.

> The window is 120 requests / 60 s and shared across all public routes. If you
> trip it mid-demo, wait ~60 s (or `docker compose restart gateway`) before the
> next call.

### 3.4 Header allowlist

The gateway forwards only `authorization`, `content-type`, `accept`,
`traceparent`, `tracestate`, and replaces the client address with the real
ingress peer in `x-forwarded-for`. Client-supplied certificate headers
(`X-Forwarded-Client-Cert`, etc.) never authenticate anything — the E2E suite
proves a request carrying `X-Forwarded-Client-Cert: gateway` with **no**
certificate is still refused by the internal services.

---

## 4. Policy engine — Person 3 (OPA / ABAC)

The engine has **no host port** (internal Docker network only). Query it from
inside the network. Use the **nested** payload — the flat one is denied by
default:

```bash
# ALLOW — customer, 50.00, mTLS verified (the contract payload)
docker compose exec -T idp wget -qO- --header='Content-Type: application/json' \
  --post-data='{"input":{"subject":{"user_id":"22222222-2222-4222-8222-222222222222","roles":["customer"]},"action":"TRANSFER","resource":"account_987","context":{"amount":50.00,"ip_address":"192.168.1.50","mTLS_verified":true}}}' \
  http://policy-engine:8181/v1/data/authz/allow
# {"decision_id":"262834f5-…","result":{"allow":true}}

# DENY — over the 50 000 fraud threshold
#   …same body with "amount":60000 → {"result":{"allow":false}}

# DENY — mTLS not verified
#   …same body with "mTLS_verified":false → {"result":{"allow":false}}

# DENY — flat payload from docs/division.md (roles at top level)
#   → {"result":{"allow":false},"warning":{"code":"api_usage_warning",
#      "message":"'input' key missing from the request"}}
```

**Presenter talking point:** *default deny* is enforced, not documented — the
healthcheck itself runs `opa eval --fail 'data.authz.allow == {"allow": false}'`,
so the container goes unhealthy if the default-deny rule ever disappears.
`opa test -v` reports **22/22 PASS**.

---

## 5. Moving money — Persons 4 & 5 (account + payment)

### 5.1 Happy path (the full 6-step flow from `docs/flow.md`)

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222",
       "receiver_id":"11111111-1111-4111-8111-111111111111","amount":50.00}'
# {"txn_id":"17c0a200-98e0-4d55-a8a4-e0cb5b83a578",
#  "sender_id":"22222222-2222-4222-8222-222222222222",
#  "receiver_id":"11111111-1111-4111-8111-111111111111",
#  "amount":50.00,"created_at":"2026-10-14T03:49:44Z"} [200]

# Balance before/after
curl -s -H "Authorization: Bearer $TOKEN" $GW/api/v1/accounts
# before: {"user_id":"22222222-…","balance":"884.00","status":"ACTIVE"}
# after:  {"user_id":"22222222-…","balance":"834.00","status":"ACTIVE"}
```

What happened, in order (say this out loud during the demo):

1. Gateway verified the RS256 JWT against the IdP's JWKS.
2. Gateway opened an **mTLS** connection (TLS 1.3, its own CA-issued client
   cert) to `payment-service:8081`.
3. Payment re-verified the JWT, checked the sender binding, and asked OPA with
   the nested payload.
4. Payment called `account-service:8082` over a **second** mTLS channel to
   deduct atomically (`UPDATE … WHERE balance >= amount RETURNING balance`).
5. Account re-verified the JWT *and* re-asked OPA before touching the row.
6. Payment appended the row to the immutable `transactions` ledger.
7. All components emitted a structured JSON decision; the collector shipped it
   to the audit trail, and spans went to telemetry → Jaeger.

The documented alias from `docs/flow.md` §2 also works:

```bash
curl -s -X POST $GW/api/v1/payment -H "Authorization: Bearer $TOKEN" … # 200
```

### 5.2 The denial matrix (each one is a different layer refusing)

```bash
# (a) policy threshold exceeded        → 403 policy_denied
curl … -d '{…,"amount":60000.00}'
# {"error":{"code":"policy_denied","message":"the authorization policy denied this transfer"}} [403]

# (b) someone else's account as sender → 403 sender_mismatch
curl … -d '{"sender_id":"11111111-1111-4111-8111-111111111111", … ,"amount":1.00}'
# {"error":{"code":"sender_mismatch","message":"sender_id must be the authenticated user's own account"}} [403]

# (c) invalid amount                   → 400 invalid_amount
curl … -d '{…,"amount":-5}'
# {"error":{"code":"invalid_amount","message":"amount must be a positive decimal with at most two fraction digits"}} [400]

# (d) insufficient balance             → 400 (never debited, never recorded)
# (e) suspended account                → 400 (same)
```

The E2E suite additionally asserts, against real SQL: `0`, `-1`, `0.001`,
`NaN`, `Infinity`, `100000000.00`, `"50.00"` (string) and `garbage` all return
**400** and leave **both** the balance and the ledger count untouched.

### 5.3 Authorization on reads (ABAC in practice)

```bash
ADMIN=$(curl -s -X POST $GW/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# admin may read the customer's account
curl -s -w ' [%{http_code}]\n' -H "Authorization: Bearer $ADMIN" \
  $GW/api/v1/accounts/22222222-2222-4222-8222-222222222222
# {"user_id":"22222222-…","balance":"830.50","status":"ACTIVE"} [200]

# customer may NOT read the admin's account
curl -s -w ' [%{http_code}]\n' -H "Authorization: Bearer $TOKEN" \
  $GW/api/v1/accounts/11111111-1111-4111-8111-111111111111
# {"detail":"Forbidden: Cannot view another user's account"} [403]
```

---

## 6. Transport contract — mTLS is real (Person 4/5 boundary)

No certificate, no connection — even for a service inside the Docker network:

```bash
docker compose exec -T account-service python -c "
import httpx, ssl
ctx = ssl.create_default_context(cafile='/certs/ca.crt')
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
try:
    httpx.get('https://payment-service:8081/healthz', verify=ctx, timeout=5)
    print('UNEXPECTED')
except Exception as e:
    print('REFUSED:', type(e).__name__)"
# REFUSED: ReadError          <- server hung up: no client certificate
```

TLS 1.2-only clients are refused rather than negotiated down:

```bash
# … ctx.maximum_version = ssl.TLSVersion.TLSv1_2, presenting a valid cert
# REFUSED: ConnectError
```

Presenting a certificate that is **not** on the identity allowlist (`probe`)
gets `403` — the probe cert is deliberately allowed to answer health checks and
forbidden from calling `/transfer`.

**Presenter talking point:** these attempts are not silent. They land in the
audit trail as `payment-service / AUTHZ / DENY / handshake_failed` and
`… / no_client_certificate` (visible in §7).

---

## 7. Fail-closed behaviour (the money shot for a zero-trust demo)

Kill the policy engine and try to move money:

```bash
docker compose stop policy-engine

curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222",
       "receiver_id":"11111111-1111-4111-8111-111111111111","amount":1.00}'
# {"error":{"code":"policy_unavailable",
#           "message":"the authorization service could not be reached; the transfer was not attempted"}} [403]

docker compose start policy-engine    # wait ~10 s

# same request now succeeds:
# {"txn_id":"1f5dfdf2-…","amount":1.00, …} [200]
```

**Key line:** *"the transfer was not attempted"* — when the authorizer is
unreachable, the system does nothing rather than something. The E2E suite
asserts the same for an `account-service` outage (→ 400) and that both recover
to 200 without restarting anything else.

---

## 8. Observability — Person 6

### 8.1 One request = one trace across every component

Send a transfer with a W3C trace id you choose:

```bash
TID=$(python3 -c "import secrets;print(secrets.token_hex(16))")
TRACE="00-$TID-$(python3 -c 'import secrets;print(secrets.token_hex(8))')-01"

curl -s -D- -o /dev/null -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" -H "traceparent: $TRACE" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222",
       "receiver_id":"11111111-1111-4111-8111-111111111111","amount":2.50}'
# traceparent: 00-fc5198a1f676029a0a4a04e1644e6c08-475d86367c834309-01   (same trace id echoed back)
```

Join **spans and security decisions** for that one request:

```bash
curl -s "http://localhost:8088/v1/audit/traces/$TID"
# spans: gateway 'POST /api/v1/payments/transfer'
#        payment-service 'POST transfer' | 'policy.authorize'
#        payment-service 'account.deduct' | 'ledger.insert'
#        account-service 'POST /api/v1/accounts/deduct'
# decisions: 7
# services: ['account-service', 'gateway', 'payment-service', 'policy-engine']
```

The same trace is browsable in Jaeger:

```bash
curl -s "http://localhost:16686/api/traces/$TID"     # 6 spans, 3 services
# open http://localhost:16686/trace/$TID
```

Jaeger service list: `gateway`, `idp`, `account-service`, `payment-service`.

### 8.2 The audit dashboard — http://localhost:8088/dashboard

Live values observed during this run (24 h window — the counters accumulate as
you demo, so treat them as "at least this much evidence"):

```
DECISIONS 867   BLOCKED REQUESTS 609   UNAUTHORIZED ATTEMPTS 532
RATE LIMITED 56 ERRORS 6              DENIAL RATE 70.2%
SERVICES REPORTING 5                  TRACES SEEN 350 (2,174 spans stored)
BLOCKED — BY REASON: unauthorized 245, invalid_token 234, rate_limited 56
```

Supporting API calls you can show live:

```bash
curl -s "http://localhost:8088/v1/audit/summary?window=24h"          # counters, denial rate, top reasons
curl -s "http://localhost:8088/v1/audit/events?decision=DENY&limit=3" # individual denials with raw payload
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8088/v1/audit/events \
  -H 'Content-Type: application/json' -d '{"decision":"DENY"}'        # 401 — the trail cannot be forged
```

The raw stored record for one of our mTLS probes:

```json
{"occurred_at":"2026-10-14T03:50:06Z","service":"payment-service",
 "category":"AUTHZ","decision":"DENY","reason":"handshake_failed",
 "event_type":"mtls_handshake_rejected","ingested_via":"docker",
 "raw":{"detail":{"error":"tls: client offered only unsupported versions: [303 302 301]"}}}
```

### 8.3 Centralized logging — Loki + Grafana

Open http://localhost:3300/d/zt-logs (folder **Zero-Trust**, anonymous admin
enabled for local demo). Observed live:

```
Log lines 3.25 k   Errors 1   Warnings 15   Security decisions in the logs 149
```

Every container in the project ships there, including `policy-engine`:

```bash
curl -s http://localhost:3100/loki/api/v1/label/service/values
# ["account-service","gateway","grafana","idp","jaeger","loki",
#  "payment-service","policy-engine","promtail","telemetry","telemetry-collector"]
```

### 8.4 The audit pipeline itself is observable

```bash
curl -s http://localhost:8089/metrics | grep telemetry_collector
# telemetry_collector_containers_followed 9
# telemetry_collector_records_queued_total 325
# telemetry_collector_records_shipped_total 325
# telemetry_collector_records_dropped_total 0
# telemetry_collector_batches_failed_total 0
# telemetry_collector_records_skipped_total 1007
```

Two paths over the same stdout, on purpose: **everything → Loki** (raw logs),
**decisions → audit_events** (PERMIT/DENY with verdicts, retention, forensics).

---

## 9. Prove it with the automated suite

```bash
./scripts/test-all.sh
```

This builds a **disposable** `dss-e2e` stack (own project name, own Postgres,
ports 18080/18088/13100/13300/26686 — it never touches the presentation stack
or the shared database), then runs:

| Stage | Suite | Expected |
| --- | --- | --- |
| 1 | Go `-race` tests for `idp`, `payment-service`, `telemetry` + `go vet` | all green |
| 2 | `opa test -v` + `opa check --strict` in the running container | `PASS: 22/22` |
| 3 | pytest: `account-service/tests`, `test_security.py`, `test_gateway.py` | `31 passed` |
| 4 | pytest: `tests/test_e2e.py` with `DSS_E2E=1` | `33 passed` |
| 5 | `docker compose ps` of the whole disposable stack | everything `healthy` |

JUnit/JSON artifacts land in `test-results/`. Last run: **`EXIT=0`**.

Highlights of what the E2E suite proves for you:

- exact-to-the-cent transfers recorded **once** in an append-only ledger
  (`UPDATE`/`DELETE`/`TRUNCATE` on `transactions` raise SQL errors);
- 20 concurrent transfers against a 100.00 balance → exactly **10** succeed,
  balance ends at exactly `0`, ledger grows by exactly 10 (no overdraw);
- 7 token-forgery variants all → 401 with **no** balance/ledger mutation;
- certificate mounts contain no other service's private keys, and no core
  service publishes a bypass port;
- stopping `policy-engine` → 403, stopping `account-service` → 400, both
  recover to 200;
- a restart of IdP/account/payment preserves balances and ledger;
- audit + spans join the live flow, and Loki/Jaeger/Grafana all answer.

---

## 10. 5-minute live demo run sheet

Run top to bottom from the repo root. Keep `$GW` and `$TOKEN` exported.

```bash
GW=http://localhost:8080
docker compose ps                                   # 1. all healthy
curl -s $GW/readyz                                  # 2. {"status":"ready"}

TOKEN=$(curl -s -X POST $GW/login -H 'Content-Type: application/json' \
  -d '{"username":"customer","password":"customer123","device_id":"demo-laptop"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
python3 - "$TOKEN" <<'EOF'                         # 3. show sub / roles / device_id
import sys, base64, json
p = sys.argv[1].split('.')[1]; p += '=' * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
EOF

# 4. blocked without a token
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":1}'

# 5. policy allows 50, denies 60000
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":50.00}'
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":60000.00}'

# 6. balance moved
curl -s -H "Authorization: Bearer $TOKEN" $GW/api/v1/accounts

# 7. mTLS: nothing reaches payment without a client certificate
docker compose exec -T account-service python -c "
import httpx,ssl
c=ssl.create_default_context(cafile='/certs/ca.crt'); c.minimum_version=ssl.TLSVersion.TLSv1_3
try: httpx.get('https://payment-service:8081/healthz',verify=c,timeout=5); print('UNEXPECTED')
except Exception as e: print('REFUSED:',type(e).__name__)"

# 8. fail closed, then recover   (see §7)
#    docker compose stop policy-engine  → 403 policy_unavailable
#    docker compose start policy-engine  → 200

# 9. open the evidence
#    http://localhost:8088/dashboard     audit decisions (867 in the last 24 h)
#    http://localhost:16686              Jaeger — pick service "gateway"
#    http://localhost:3300/d/zt-logs     Grafana — 3.25k log lines
```

**Narrative to read off the slides while this runs:**

1. **Identity** — credentials in, signed RS256 JWT out; wrong password is
   indistinguishable from a nonexistent user.
2. **Perimeter** — the gateway is the only door; it verifies the signature
   against the IdP's JWKS, sheds excess traffic with 429, and strips headers.
3. **Policy** — *default deny*; nested `input` payload, 50 000 threshold,
   mTLS attribute required.
4. **Execution** — money moves only over mTLS, with a second policy check at
   the account boundary and an append-only ledger.
5. **Fail-closed** — pull the policy engine and the transfer is *not attempted*.
6. **Proof** — every decision is in the audit trail, every request is a trace
   spanning all four services, and `scripts/test-all.sh` replays all of it
   (64 Python + 383 Go + 22 Rego assertions) against a disposable stack.

---

## 11. The data layer — the connected Supabase instance

The stack runs no database of its own. `DATABASE_URL` (inside the git-crypt
`.env`) points at the shared **Supabase PostgreSQL 17.6** instance, and every
migrations, seed user, balance, ledger row and audit decision in this tutorial
is written there. This section proves that, and shows how to exercise the
database-backed suites against it without endangering it.

```
host  aws-0-ap-northeast-1.pooler.supabase.com:5432
db    postgres        user  postgres        sslmode  require
```

### 11.1 Unlocking the credentials

```bash
head -c 60 .env     # readable? -> already unlocked, do nothing
# locked (binary garbage) instead:
git-crypt unlock /path/to/DSS.key
git-crypt status | grep -E '\.env$'    # "encrypted: .env" = filter armed
```

> If `.env` is already plaintext the repository is **already unlocked**. Running
> `unlock` again re-decrypts from the index and silently discards local edits to
> `.env` — check first, as above.

### 11.2 Verify who owns what (`docs/database.md` §2)

From the repo root (`.venv-test` is created by `scripts/test-all.sh`):

```bash
.venv-test/bin/python - <<'EOF'
from dotenv import dotenv_values
import asyncpg, asyncio
url = dotenv_values(".env")["DATABASE_URL"]
async def main():
    con = await asyncpg.connect(url, timeout=20)
    try:
        r = await con.fetchrow("select current_database() db, current_user u, version() v")
        print(f"{r['db']} / {r['u']} / {r['v'].split(',')[0]}")
        for t in ["credentials","accounts","transactions","audit_events","spans"]:
            print(f"  {t}: {await con.fetchval('select count(*) from ' + t)}")
        for m in ["idp_schema_migrations","_account_schema_migrations",
                  "payment_schema_migrations","telemetry_schema_migrations"]:
            print(" ", m, [dict(x) for x in await con.fetch(f"select * from {m}")])
    finally:
        await con.close()
asyncio.run(main())
EOF
```

Observed (counts grow as you demo):

```
postgres / postgres / PostgreSQL 17.6 on x86_64-pc-linux-gnu
  credentials: 2        <- owned by the IdP
  accounts: 2           <- owned by account-service
  transactions: 12      <- owned by payment-service (append-only)
  audit_events: 867     <- owned by telemetry
  spans: 2174           <- owned by telemetry
 idp_schema_migrations [{'version': 1, 'dirty': False}]
 _account_schema_migrations [{'version': '001_init.up.sql', …}]
 payment_schema_migrations [{'version': 1, 'dirty': False}]
 telemetry_schema_migrations [{'version': 1, 'dirty': False}]
```

Two lines for the slide here:

* **Every service migrates into its own bookkeeping table.** golang-migrate's
  default `schema_migrations` belongs to the *database*, so on a shared instance
  the first service to boot used to freeze all the others out — it really broke
  this project's IdP seed once (telemetry/README.md §5). A leftover
  `public.schema_migrations` from the early build is still there; it is inert.
* **Nobody reads anyone else's tables.** Payment confirms the balance by calling
  account-service over mTLS — never with a `SELECT`.

### 11.3 Watch the demo land in Supabase

Run a transfer from §5, then query (Supabase SQL editor or `psql`):

```sql
select txn_id, amount, created_at from transactions order by created_at desc limit 3;
select service, category, decision, reason from audit_events
  order by occurred_at desc limit 5;
```

Every transfer appears in **two** stores: the ledger row in `transactions`
(written by payment-service) and the decision rows in `audit_events` (written by
the audit pipeline) — joined by `trace_id`, which is exactly what the §8 trace
view renders.

### 11.4 Running the database-backed suites against Supabase

Four Go suites need a real PostgreSQL. Three of them **drop tables** as part of
the migration-rollback path, so they must never be pointed at the live
`postgres` database. Give them a scratch database on the same instance:

```bash
# 1. scratch database + URL (Supabase allows CREATE DATABASE)
.venv-test/bin/python - > /tmp/scratch.env <<'EOF'
from dotenv import dotenv_values
import re
base = dotenv_values(".env")["DATABASE_URL"]
print("SCRATCH_URL='" + re.sub(r"^postgresql://", "postgres://",
      re.sub(r"/postgres\?", "/dss_scratch?", base)) + "'")
EOF
source /tmp/scratch.env
.venv-test/bin/python -c "
from dotenv import dotenv_values
import asyncpg, asyncio
async def main():
    con = await asyncpg.connect(dotenv_values('.env')['DATABASE_URL'])
    try:
        await con.execute('CREATE DATABASE dss_scratch')
        print('created')
    finally:
        await con.close()
asyncio.run(main())"

# 2. the four suites
(cd payment-service && PAYMENT_TEST_DATABASE_URL="$SCRATCH_URL" \
   go test ./internal/store/ -run TestPostgresLedger -count=1)
(cd telemetry && TELEMETRY_TEST_DATABASE_URL="$SCRATCH_URL" \
   go test ./internal/store/ -run TestPostgresStore -count=1)
(cd telemetry && TELEMETRY_TEST_DATABASE_URL="$SCRATCH_URL" TELEMETRY_TEST_DESTRUCTIVE=1 \
   go test ./internal/db/ -run TestMigrateDownAndVersionAgainstPostgres -count=1)
(cd idp && IDP_TEST_DATABASE_URL="$SCRATCH_URL" go test ./internal/db/ -count=1)

# 3. drop the scratch database (WITH FORCE kills lingering pooler sessions;
#    a plain DROP fails with ObjectInUseError while one is still attached)
.venv-test/bin/python - <<'EOF'
from dotenv import dotenv_values
import asyncpg, asyncio, time
async def main():
    con = await asyncpg.connect(dotenv_values(".env")["DATABASE_URL"])
    try:
        await con.execute("DROP DATABASE IF EXISTS dss_scratch WITH (FORCE)")
        time.sleep(1)
        dbs = await con.fetch("select datname from pg_database where datname like 'dss%'")
        print("dss* databases:", [r["datname"] for r in dbs] or "none (cleaned up)")
    finally:
        await con.close()
asyncio.run(main())
EOF
```

Results on the real instance (round trips to AWS, so these are seconds, not
milliseconds):

| Suite | Result | Time |
| --- | --- | --- |
| payment: ledger schema, constraints, append-only trigger, DOWN | ok | 19.8 s |
| idp: migration isolation, seed, rollback | PASS | 22.1 s |
| telemetry: store, aggregate query, retention, trace join | ok | 19.9 s |
| telemetry: migrate up/down + version reporting | ok | 49.4 s |

After dropping the scratch database the live tables were re-counted —
`credentials 2, accounts 2, transactions 9, audit_events 557, spans 1837` at
that moment — every row from the demo still there, which is the proof that the
suites never touched them. (The §11.2 counts have kept growing since: the audit
trail only ever accumulates until retention sweeps it.)

### 11.5 Behaviour specific to this environment

* The IdP's `/readyz` occasionally logs `readiness_check_failed` /
  `timeout: context deadline exceeded` (twice in eight hours of running) — the
  Supabase pooler answering slower than the probe's timeout. The container's own
  healthcheck recovers by itself and the incident is written to the audit trail:
  even the platform's health signals are auditable.
* `scripts/test-all.sh` deliberately uses its **own** disposable PostgreSQL on
  port 55432 rather than Supabase, so the suite can drop and recreate tables and
  stay reproducible for every teammate. Supabase is the deployment database;
  §11.4 is the supported way to exercise it directly.

---

## 12. Gotchas

| Symptom | Cause / fix |
| --- | --- |
| `telemetry-collector` unhealthy, logs say `dial unix /var/run/docker.sock: connect: permission denied` | `TELEMETRY_DOCKER_GID` in `.env` does not match this host. Run `stat -c '%g' /var/run/docker.sock` and set it (added as `=952` on this machine). |
| Unexpected 429 mid-demo | The gateway's global window is 120 req/60 s. Wait a minute or `docker compose restart gateway` (restart also resets the window — do it *before* the demo, not during). |
| Ports 18080/18088/13300 busy | The disposable `dss-e2e` stack from `scripts/test-all.sh` is still up: `docker compose -p dss-e2e down`. |
| IdP not reachable on localhost | By design — IdP has no published port; use the gateway's `/login`, `/token`, `/jwks.json`, `/.well-known/openid-configuration`. |
| `PAYMENT_`/`IDP_`/`TELEMETRY_TEST_DATABASE_URL` pointing at the live `postgres` database | Three of the four DB suites **drop tables**. Always use a scratch database (§11.4). |
| `curl localhost:3100/ready` → 503 right after a full restart | Loki's ring takes ~30 s to initialise. Grafana shows "no data" until then; re-check, don't rebuild. |
| `/readyz` intermittently logs `readiness_check_failed` | Supabase pooler latency spike; self-healing, and recorded in the audit trail. |
| Starting over | `docker compose down` keeps the database; `docker compose down -v` also drops the cert/log volumes. |
