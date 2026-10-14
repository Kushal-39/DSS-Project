# Zero-Trust Presentation Script — Run Sheet with Talking Points

**Companion to:** [docs/poc-presentation.md](docs/poc-presentation.md) and
[Presentation Script.pptx](Presentation%20Script.pptx) — that deck has the same
speaker notes baked into every slide.

**What this is:** a slide-by-slide walkthrough of what to *say*, what to *show*,
and exactly which **commands to run** during the demo, with the verbatim output you
should expect when the stack is healthy. Every command in this document was executed
against the running stack and its output was observed before it was written down.

**Stack (11 containers):** `gateway`, `idp`, `policy-engine`, `account-service`,
`payment-service`, `telemetry`, `telemetry-collector`, `jaeger`, `loki`,
`promtail`, `grafana`.

**Published entry points you will use during the demo:**

| Service | URL | Role |
| --- | --- | --- |
| API Gateway | http://localhost:8080 | the only public door |
| Audit dashboard | http://localhost:8088/dashboard | Person 6's deliverable |
| Jaeger | http://localhost:16686 | trace UI |
| Grafana (Loki logs) | http://localhost:3300/d/zt-logs | log UI |
| IdP / account / payment | *not published* | reachable only through the gateway or the internal Docker network |

---

## Before you start speaking

Set these two variables in your terminal once. They are used by every demo step
below.

```bash
GW=http://localhost:8080
```

**One-time prep (do this before the audience arrives, not during the talk):**

```bash
# 1. Make sure the stack is actually up and healthy.
docker compose ps
# account-service    running (healthy)
# gateway            running (healthy)
# idp                running (healthy)
# payment-service    running (healthy)
# policy-engine      running (healthy)
# telemetry          running (healthy)
# … grafana / jaeger / loki / promtail also running

# 2. Confirm the gateway is ready to serve — it only says ready when IdP AND
#    account AND payment all answer over their real transports.
curl -s -w ' [%{http_code}]\n' $GW/readyz
# {"status":"ready"} [200]
```

**Talking point (say this while the readiness check runs):**
*"The gateway only returns ready when three internal services — IdP, account and
payment — all answer over their real transports. If any one of them is down, the
entry point itself refuses to advertise ready."*

> **Pro tip:** the IdP, account and payment ports are **not published** on the host
> at all. There is no way to reach them from outside the Docker network — the E2E
> suite asserts exactly this (every published port of those three services must be
> empty). If anyone asks "can I just curl the payment service directly?", the answer
> is no, by design.

---

## Slide 2 — Introduction

**Reference:** `Zero-Trust Architecture - Project Presentation.pptx`, slide 2.

### What to say

*"Zero trust means no request is trusted just because of where it comes from.
Every call is authenticated, authorised and logged — even calls that stay entirely
inside our own network."*

*"Distributed microservices widen the attack surface. If one service is compromised,
a perimeter-only design lets an attacker move laterally across the whole fleet with
no further checks."*

*"We built a runnable zero-trust reference system: six components, eleven containers,
started by a single `docker compose` command. The components are an Identity Provider,
an API Gateway, an OPA policy engine, an Account service, a Payment service, and a
Telemetry pipeline."*

*"This matters because breaches are costly and regulated — PCI-DSS for payments,
India's DPDP Act for personal data. Zero trust turns security from a perimeter
checkbox into policy-as-code that can be tested, audited and proved."*

### What to show

Nothing technical yet — just the slide. Optionally open
[docs/poc-presentation.md](docs/poc-presentation.md) §0 verification table in a
browser tab so you can point at it later when you reach the results slide.

---

## Slide 3 — Literature Review

**Reference:** slide 3.

### What to say

*"NIST Special Publication 800-207, Zero Trust Architecture, is the standards-body
anchor for this whole idea — Rose, Borchert, Mitchell and Connelly, 2020."*

*"BeyondCorp — Ward and Beyer, 2014, in ;login: — is the industry example that
showed Google replacing its trusted LAN and VPN with device- and user-context-based
access."*

*"SPIFFE is the emerging standard for cryptographic workload identities — the way a
service proves who it is, not just who the user is."*

*"JWT and OIDC standardise token-based identity. OPA and Rego centralise
authorisation as policy-as-code — a decision engine you can version, test and review,
not a hard-coded if-statement."*

*"Service meshes like Istio and Linkerd add mutual TLS sidecars — powerful, but
heavyweight for a lightweight system."*

*"The gap we target: prior work secures transport or identity in isolation. Few combine
per-request ABAC at **every** hop with a queryable audit trail that joins decisions to
distributed traces."*

### What to show

Just the slide. If asked for specifics, refer to the IEEE-format references on slide 10.

---

## Slide 4 — Motivation

**Reference:** slide 4.

### What to say

*"Zero trust is widely adopted as a slogan, but most implementations stop at 'TLS
everywhere' plus a VPN. That is not zero trust — it is just encrypted perimeter."*

*"Perimeter-only designs fail the moment one service is compromised. There is nothing
left to stop lateral movement."*

*"Authorisation decisions without an audit trail cannot be investigated, attributed or
shown to an auditor after the fact."*

*"Our novelty: policy enforced at every hop — gateway and each service — default deny,
fail closed, and every PERMIT and DENY stored with its trace id so you can reconstruct
exactly why a request was allowed."*

*"Lightweight by design: no mesh sidecars, no Kubernetes. The entire zero-trust stack
runs on a laptop."*

### What to show

Just the slide.

---

## Slide 5 — Problem Statement

**Reference:** slide 5.

### What to say

*"Here is the precise problem we solved: secure a lightweight distributed system with
no fixed perimeter against credential theft, lateral movement and insider misuse — while
staying simple enough to run and verify end to end."*

*"We expressed that as six verifiable requirements:*

1. *Short-lived token identity for every request — an RS256 JWT, verified against the
   issuer's JWKS.*
2. *Attribute-based authorisation enforced at every hop, default deny.*
3. *TLS 1.3 mutual TLS between all services, using a private certificate authority.*
4. *Fail-closed behaviour whenever a dependency is unavailable.*
5. *A tamper-evident audit trail of every decision, correlated across services by trace
   id.*
6. *No bypass paths — internal services are never published on the host network.*"

*"Each requirement maps to a component, and each one maps to a test that proves it.
Requirement 6 is why the IdP, account and payment ports are not published."*

### What to show

Just the slide. If someone wants to see requirement 6 proven, jump ahead to the
mTLS probe in the demo section.

---

## Slide 6 — Architecture

**Reference:** slide 6.

### What to say

*"Here is one request walking through the system, hop by hop."*

1. *"Client to gateway: the gateway verifies the RS256 JWT against the IdP's JWKS, applies
   a global rate limit, and enforces a header allowlist."*
2. *"Gateway to payment: the request is forwarded over mTLS 1.3 with a CA-issued client
   identity, and the sender_id must match the token subject."*
3. *"Payment to policy engine: a nested payload — subject, action, resource, context — goes
   to OPA and comes back as a simple allow or deny. Default deny, 50,000 cap, mTLS attribute
   required."*
4. *"Payment to account: a second mTLS hop re-verifies the JWT and re-asks policy before an
   atomic deduction."*
5. *"Ledger: the transactions table is append-only — UPDATE, DELETE and TRUNCATE are rejected
   by a database trigger."*
6. *"Telemetry: every component emits structured JSON decisions; a collector ships them to the
   audit database, spans to Jaeger, logs to Loki and Grafana."*
7. *"Data: database-per-service on one PostgreSQL instance — each service migrates into its own
   bookkeeping table."*

*"The key idea: every hop verifies, and every hop is logged."*

### What to show

Just the slide for now. The rest of this script is the **live proof** of this architecture.
When you reach the demo section, come back to this slide in your head — every command you run
is one of these hops.

---

## Slide 7 — Experimental Results

**Reference:** slide 7.

### What to say

*"Setup: eleven Docker containers on PostgreSQL 17 via Supabase, plus a disposable database
for the runner script."*

*"Test volume: 383 Go tests with the race detector, 64 Python tests, and 22 Rego tests — the
full runner exits zero."*

*"Forgery: seven forged, expired and HS256-swapped tokens all return 401, with zero ledger
changes."*

*"Authorisation: an amount over 50,000 returns 403 policy_denied; a foreign sender_id returns
403; a malformed amount returns 400 — and in every case the database is untouched."*

*"Concurrency: twenty parallel transfers against a 100.00 balance — exactly ten succeed, the
final balance is exactly zero."*

*"Fail-closed: stop the policy engine and you get 403 'not attempted'; stop the account service
and you get 400; both auto-recover to 200."*

*"Perimeter and audit: exactly 120 requests per minute, then 429; 1,043 decisions and 663 denials
audited in the last 24 hours, a 63.6 percent denial rate."*

*"Comparison: TLS-only blocks none of the forged requests. A mesh needs sidecars per node — ours
runs on a laptop."*

### What to show

Just the slide here. The numbers come alive in the demo section. If asked where they come from,
say: *"Every one of these is reproducible — there is a single script,
`scripts/test-all.sh`, that builds a disposable stack and replays all of it."*

> **Note on the numbers on this slide:** they are the *live* values from the running stack
> at the time this script was written — not a static screenshot. The audit counters accumulate
> as you demo, so the denial rate and totals will be slightly higher by the time you speak. That
> is fine; it only makes the evidence stronger. The table below is what was observed when this
> script was written:

| Metric (24 h window, observed when this script was written) | Value |
| --- | --- |
| Total decisions | 1,043 |
| Denials | 663 |
| Denial rate | 63.6 % |
| Traces seen | 409 |
| Spans stored | 2,891 |
| Unauthorized attempts | 582 |
| Rate-limited | 56 |

---

## Slide 8 — Demonstration

**Reference:** slide 8.

**This is the live part.** Everything after this line is what you actually run in front of the
audience, in order. Keep `$GW` set from the prep section.

The slide itself says:

> docker compose up --build -d — 11/11 containers healthy; POST /login returns an RS256 JWT
> (sub, roles, device_id).
>
> Transfer 50.00 → 200 + txn_id, balance moves; 60,000 → 403 policy_denied; tampered token → 401.
>
> Stop the policy engine → 403 'not attempted'; restart it → 200. Fail closed, then recover.
>
> Evidence below: audit dashboard, Jaeger trace, Grafana logs — then the live demo.

### 8.0 — Show the stack is healthy

```bash
docker compose ps
```

**Expected (abbreviated):**

```
account-service    running (healthy)
gateway            running (healthy)
idp                running (healthy)
payment-service    running (healthy)
policy-engine      running (healthy)
telemetry          running (healthy)
grafana            running
jaeger             running
loki               running
promtail           running
telemetry-collector running (healthy)
```

**Say:** *"Eleven containers, all healthy. Five of them are the core zero-trust services. The
observability ones — Jaeger, Loki, Grafana, the collector — are what let us prove the rest."*

### 8.1 — Show the gateway is the only door

```bash
curl -s -w ' [%{http_code}]\n' $GW/readyz
# {"status":"ready"} [200]
```

**Say:** *"The gateway is the only published entry point. It only says ready when the three
internal services behind it are actually reachable."*

### 8.2 — Identity: credentials in, signed token out (Person 1)

```bash
curl -s -X POST $GW/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"customer","password":"customer123","device_id":"demo-laptop"}' \
  | python3 -m json.tool
```

**Expected (your actual token will differ):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
  "expires_in": 900,
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
  "token_type": "Bearer",
  "user": {
    "id": "22222222-2222-4222-8222-222222222222",
    "role": "customer",
    "username": "customer"
  }
}
```

**Say:** *"Credentials in, signed RS256 JWT out. The token is short-lived — 900 seconds — and
it carries the user id, the role, and the device id. Every later hop re-verifies this token."*

Now capture the token for the rest of the demo:

```bash
TOKEN=$(curl -s -X POST $GW/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"customer","password":"customer123","device_id":"demo-laptop"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
```

Show what is actually inside the token — the claims every hop will re-verify:

```bash
python3 - "$TOKEN" <<'PYEOF'
import sys, base64, json
p = sys.argv[1].split('.')[1]
p += '=' * (-len(p) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
PYEOF
```

**Expected:**

```json
{
  "iss": "http://idp:8080",
  "sub": "22222222-2222-4222-8222-222222222222",
  "aud": [
    "zerotrust-api-gateway"
  ],
  "exp": 1791963856,
  "iat": 1791962956,
  "jti": "1791962956267777362",
  "roles": [
    "customer"
  ],
  "device_id": "demo-laptop"
}
```

**Say:** *"This is the identity every later hop re-verifies. Issuer, subject, audience, expiry,
issue time, a unique token id, the roles array, and the device id. Nothing here is trusted
because it comes from the gateway — it is signed by the IdP and verified independently."*

### 8.3 — Perimeter: no token → 401 (Person 2)

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":1}'
# {"error":"unauthorized"} [401]
```

**Say:** *"No token at all — 401. The gateway is the only door, and it will not let a request
through without a verifiable bearer token."*

### 8.4 — Perimeter: tampered token → 401 (Person 2)

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer ${TOKEN%????}aaaaaaaa" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":1}'
# {"error":"unauthorized"} [401]
```

**Say:** *"Even with a token present — if I tamper with it, just four characters replaced by
'a' — the signature no longer verifies against the IdP's JWKS, and the gateway rejects it.
The gateway only accepts RS256 tokens with a known key id."*

**If asked what else the gateway rejects**, say there are seven forgery variants in the E2E suite:
missing token, tampered token, HS256 algorithm confusion, expired token, wrong issuer, wrong
audience, and a token with the expiry claim removed. All of them return 401, and none of them
touches the ledger. The suite is `tests/test_e2e.py::test_gateway_rejects_invalid_tokens`.

### 8.5 — Negative identity: wrong password is indistinguishable from a missing user

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"customer","password":"wrong"}'
# {"error":{"code":"invalid_credentials","message":"invalid username or password"}} [401]
```

**Say:** *"A wrong password for an existing user, and a request for a non-existent user, return
byte-identical bodies. The API cannot be used to enumerate accounts. This is not accidental —
the E2E suite asserts `a.json() == b.json()` for exactly these two cases."*

### 8.6 — Money moves: the happy path (Persons 4 & 5)

Show the balance before:

```bash
curl -s -H "Authorization: Bearer $TOKEN" $GW/api/v1/accounts
# {"user_id":"22222222-2222-4222-8222-222222222222","balance":"670.00","status":"ACTIVE"}
```

**Say:** *"The customer currently has 670.00. Now we transfer 50.00 to the admin account."*

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":50.00}'
# {"txn_id":"<uuid>","sender_id":"22222222-...","receiver_id":"11111111-...","amount":50.00,"created_at":"2026-10-14T..."} [200]
```

**Say:** *"200, with a transaction id. Let me read the balance back."*

```bash
curl -s -H "Authorization: Bearer $TOKEN" $GW/api/v1/accounts
# {"user_id":"22222222-...","balance":"620.00","status":"ACTIVE"}
```

**Say:** *"670.00 became 620.00 — exactly 50.00 moved, recorded once in an append-only ledger."*

Now narrate what actually happened, in order. This is the moment to walk back through slide 6:

1. *"The gateway verified the RS256 JWT against the IdP's JWKS."*
2. *"The gateway opened a mutual-TLS connection — TLS 1.3, its own CA-issued client certificate —
   to the payment service."*
3. *"The payment service re-verified the JWT, checked that the sender_id matched the authenticated
   user, and asked the policy engine with the nested payload."*
4. *"The payment service called the account service over a **second** mTLS channel to deduct
   atomically — `UPDATE ... WHERE balance >= amount RETURNING balance`."*
5. *"The account service re-verified the JWT and re-asked the policy engine before touching the
   row."*
6. *"The payment service appended the row to the immutable transactions ledger."*
7. *"Every component emitted a structured JSON decision; the collector shipped it to the audit
   trail, and the spans went to Jaeger."*

### 8.7 — Policy engine: allowed and denied in the same breath (Person 3)

```bash
# Allowed — 50.00, under the threshold
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":50.00}'
# 200

# Denied — 60,000, over the 50,000 fraud threshold
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":60000.00}'
# {"error":{"code":"policy_denied","message":"the authorization policy denied this transfer"}} [403]
```

**Say:** *"Same user, same receiver, same token. The only difference is the amount. At 50.00 the
policy engine says allow. At 60,000 — above the 50,000 threshold — it says deny. The default is
deny; allow is something the policy has to earn."*

**If asked how the policy engine is enforced**, say the healthcheck itself runs
`opa eval --fail` against the default-deny rule, so the container goes unhealthy if that rule ever
disappears. `opa test -v` reports 22 out of 22 passing.

### 8.8 — Sender binding: someone else's account as sender → 403 (Person 4/5 boundary)

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"11111111-1111-4111-8111-111111111111","receiver_id":"22222222-2222-4222-8222-222222222222","amount":1.00}'
# {"error":{"code":"sender_mismatch","message":"sender_id must be the authenticated user's own account"}} [403]
```

**Say:** *"Even with a valid token, I cannot send money from someone else's account. The payment
service checks that the sender_id in the request is the authenticated user's own account. This is
the sender-binding check at the Person 4/5 boundary."*

### 8.9 — Transport contract: no certificate, no connection (Persons 4/5 boundary)

This one runs inside the Docker network, so it proves mTLS is real between services, not just at
the edge:

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
# REFUSED: ReadError
```

**Say:** *"This is the account service trying to reach the payment service over TLS 1.3 with no
client certificate. The payment service hangs up immediately — ReadError. No certificate, no
connection. Even inside the Docker network."*

**Say the important part out loud:** *"These attempts are not silent. They land in the audit trail
as `payment-service / AUTHZ / DENY / handshake_failed` and `... / no_client_certificate`. You will
see them on the dashboard in a moment."*

### 8.10 — Fail-closed: kill the policy engine and try to move money

This is the money shot of the whole demo. Do not skip it.

```bash
docker compose stop policy-engine
```

Wait about two seconds, then:

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":1.00}'
# {"error":{"code":"policy_unavailable","message":"the authorization service could not be reached; the transfer was not attempted"}} [403]
```

**Say the key line out loud, slowly:** *"The authorization service could not be reached — and the
transfer was **not attempted**. When the authorizer is unreachable, the system does nothing rather
than something. That is fail-closed."*

Now restart the policy engine and watch it recover:

```bash
docker compose start policy-engine
```

Wait for it to become healthy — the startup is fast, usually under 10 seconds:

```bash
# poll until healthy
for i in $(seq 1 40); do
  s=$(docker compose ps --format '{{.Service}}\t{{.Status}}' | grep '^policy-engine')
  case "$s" in *healthy*) break;; esac
  sleep 1
done
echo "$s"
# policy-engine\tUp ... (healthy)
```

Then re-run the same transfer:

```bash
curl -s -w ' [%{http_code}]\n' -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":1.00}'
# {"txn_id":"<uuid>","amount":1.00,...} [200]
```

**Say:** *"The policy engine is back, the transfer goes through, and nothing else had to restart.
The system recovered on its own."*

**If asked what happens if the account service goes down instead**, say the E2E suite asserts the
same pattern: account-service outage returns 400, and both services recover to 200 without
restarting anything else.

### 8.11 — One request is one trace across every component (Person 6)

Pick a W3C trace id you control, send a transfer with it, and watch it propagate:

```bash
TID=$(python3 -c "import secrets;print(secrets.token_hex(16))")
TRACE="00-$TID-$(python3 -c 'import secrets;print(secrets.token_hex(8))')-01"

curl -s -D- -o /dev/null -X POST $GW/api/v1/payments/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H "traceparent: $TRACE" \
  -H 'Content-Type: application/json' \
  -d '{"sender_id":"22222222-2222-4222-8222-222222222222","receiver_id":"11111111-1111-4111-8111-111111111111","amount":2.50}' \
  | grep -i 'traceparent\|HTTP/'
# HTTP/1.1 200 OK
# traceparent: 00-<same trace id>-<span id>-01
```

Wait a few seconds for the collector to pick up the decision, then join the spans and security
decisions for that one request:

```bash
curl -s "http://localhost:8088/v1/audit/traces/$TID" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("span_count:",d["trace"]["span_count"],"event_count:",d["trace"]["event_count"],"services:",d["trace"]["services"])'
# span_count: 6 event_count: 7 services: ['account-service', 'gateway', 'payment-service', 'policy-engine']
```

**Say:** *"One request, one trace id, six spans and seven security events across four services —
gateway, payment, account and the policy engine. The same trace is browsable in Jaeger, and the
same decision records are in the audit trail. You can go from a security question to a distributed
trace and back."*

Show that Jaeger has it:

```bash
curl -s -o /dev/null -w 'jaeger %{http_code}\n' "http://localhost:16686/api/traces/$TID"
# jaeger 200
```

**Say:** *"Jaeger returns 200 for that trace id. Open
http://localhost:16686/trace/$TID and you can see the whole waterfalls — the gateway span, the
payment spans, the account span, the policy query."*

### 8.12 — The audit dashboard (Person 6)

Open the dashboard live:

```
http://localhost:8088/dashboard
```

And show the summary API while the audience looks at it:

```bash
curl -s "http://localhost:8088/v1/audit/summary?window=24h" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin)["summary"]; print("total",d["total"],"denials",d["denials"],"rate",round(d["denial_rate"]*100,1),"traces",d["trace_count"],"spans",d["span_count"],"unauthorized",d["unauthorized_attempts"],"ratelimited",d["rate_limited"])'
```

**Observed when this script was written:**

```
total 1043 denials 663 rate 63.6 traces 409 spans 2891 unauthorized 582 ratelimited 56
```

**Say:** *"1,043 decisions in the last 24 hours. 663 of them were denials — a 63.6 percent denial
rate. 582 unauthorized attempts, 56 rate-limited. Every one of these is individually queryable,
and every one is joined to a trace."*

Show that the dashboard itself cannot be forged:

```bash
curl -s -w ' [%{http_code}]\n' -X POST http://localhost:8088/v1/audit/events \
  -H 'Content-Type: application/json' \
  -d '{"decision":"DENY"}'
# 401
```

**Say:** *"You cannot forge an audit decision by POSTing to the dashboard. It is not a log you
append to — it is a queryable store that only the collector writes to."*

Show a single real record — this one is the mTLS probe from a few steps ago:

```bash
curl -s "http://localhost:8088/v1/audit/events?decision=DENY&limit=1" \
  | python3 -m json.tool
```

**Say:** *"Here is one real record. Service, category, decision, reason, the trace id, and the raw
payload. This is the mTLS handshake that the account service attempted a few steps ago — refused,
and now auditable."*

### 8.13 — Centralised logs (Person 6)

Open Grafana live:

```
http://localhost:3300/d/zt-logs
```

**Say:** *"Every container in the project ships here — gateway, idp, account, payment, policy-engine,
the collector, Jaeger, Loki, promtail, telemetry. One place to search the logs."*

Optionally show the Loki service list:

```bash
curl -s http://localhost:3100/loki/api/v1/label/service/values
# ["account-service","gateway","grafana","idp","jaeger","loki","payment-service","policy-engine","promtail","telemetry","telemetry-collector"]
```

### 8.14 — The audit pipeline itself is observable

```bash
curl -s http://localhost:8089/metrics \
  | grep telemetry_collector_records_shipped_total
# telemetry_collector_records_shipped_total <N>
```

**Say:** *"The collector that ships the audit trail is itself observable — shipped records,
dropped records, failed batches. When I ran this, the dropped count was zero and the shipped count
was growing with every request."*

---

## Slide 9 — Conclusion

**Reference:** slide 9.

### What to say

*"We delivered a working zero-trust reference implementation: per-request identity, ABAC at every
hop, TLS 1.3 mutual TLS, fail-closed behaviour, and a fully audited decision trail."*

*"We verified it end to end three ways: 469 automated assertions across Go, Python and Rego; a
live walkthrough of every flow; and a cold-start rebuild from scratch. All green."*

*"Three engineering findings worth calling out: per-service migration namespacing on a shared
database, keeping the audit trail separate from raw logs, and recovering from dependency outages
without data loss."*

*"The next phase is already specced — IdP hardening with login rate limiting, account lockout, a
TLS listener and JWKS key rotation; an authenticated policy endpoint; TLS for the audit ingest
channel; mTLS performance benchmarks; and a multi-node deployment."*

*"Close on the two headlines: it works, and it can prove it works."*

### What to show

Just the slide. Refer back to the live evidence you just showed on slide 8 if anyone asks for
proof.

---

## Slide 10 — References

**Reference:** slide 10.

### What to say

*"These are the standards and papers our design rests on, in IEEE format."*

* *[1] NIST SP 800-207, Zero Trust Architecture — Rose, Borchert, Mitchell and Connelly, 2020.*
* *[2] BeyondCorp — Ward and Beyer, 2014.*
* *[3] SPIFFE — the workload identity framework.*
* *[4] JWT — RFC 7519, Jones, Bradley and Sakimura, 2015.*
* *[5] TLS 1.3 — RFC 8446, Rescorla, 2018.*
* *[6] OPA and Rego — the policy engine and its language.*
* *[7] W3C Trace Context — Kanzhelev et al., 2021 — the wire format we use for cross-service traces.*
* *[8] Istio — the service-mesh reference point we chose not to use.*"

### What to show

Just the slide. If anyone wants exact URLs, they are on the slide.

---

## Demo timing guide

If you are working against a clock, here is a rough budget:

| Segment | Slides | Approx. time |
| --- | --- | --- |
| Intro + literature + motivation + problem + architecture | 2–6 | 4–5 min |
| **Live demo** (everything in §8) | 8 | 8–10 min |
| Results + conclusion + references | 7, 9, 10 | 2–3 min |

The live demo is the long pole. If you are short on time, do these steps and skip the rest:
readyz → login → show claims → no-token 401 → tampered 401 → transfer 50 → balance → over-limit
403 → sender-mismatch 403 → stop policy-engine → 403 not attempted → restart → 200 → one traced
transfer → audit dashboard → Jaeger → Grafana.

---

## What to do if something breaks mid-demo

| Symptom | Fix |
| --- | --- |
| `/readyz` not 200 | Wait. The gateway only reports ready when IdP, account and payment answer over their real transports. `docker compose ps` and look for `(healthy)` on those three. |
| 429 mid-demo | The gateway's global window is 120 requests per 60 seconds. Wait a minute, or `docker compose restart gateway` — but restart *before* the demo, not during. |
| Policy engine not healthy after restart | Give it 10–15 seconds. The healthcheck runs `opa eval --fail` against the default-deny rule, so it will not report healthy until that rule is loaded. |
| Trace not showing in the audit join | Wait a few seconds — the collector ships on a short schedule. Re-query the trace id. |
| IdP not reachable on localhost | By design — the IdP has no published port. Use the gateway's `/login`, `/token`, `/jwks.json`, and `/.well-known/openid-configuration`. |
| The demo token expired | Re-run the login command from §8.2. Tokens live 900 seconds. |
| Ports 18080/18088/13300 busy | The disposable `dss-e2e` stack from `scripts/test-all.sh` is still up. `docker compose -p dss-e2e down`. |

The full gotcha table is in [docs/poc-presentation.md](docs/poc-presentation.md) §12.

---

## One command that replays all of it

If anyone asks how to reproduce the numbers on slide 7:

```bash
./scripts/test-all.sh
```

This builds a **disposable** stack — its own project name, its own Postgres, its own ports —
and runs every suite against it. It never touches the presentation stack or the shared database.
Last run: exit 0.

The suites it runs:

| Stage | Suite | Expected |
| --- | --- | --- |
| 1 | Go `-race` tests for idp, payment-service, telemetry + `go vet` | all green |
| 2 | `opa test -v` + `opa check --strict` | PASS 22/22 |
| 3 | pytest: account-service/tests, test_security.py, test_gateway.py | 31 passed |
| 4 | pytest: tests/test_e2e.py with DSS_E2E=1 | 33 passed |
| 5 | `docker compose ps` of the disposable stack | everything healthy |

 JUnit and JSON artifacts land in `test-results/`.

---

## Verification of this script

This script was written against the running stack and every command in it was executed and its
output observed before it was written down. If you want to re-verify the whole thing end to end,
the canonical command is still:

```bash
./scripts/test-all.sh
```

That exercises the code. The commands in §8 exercise the **running** stack, which is what the
audience will see. Both must be green for the presentation to be trustworthy.
