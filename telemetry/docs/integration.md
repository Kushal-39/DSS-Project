# Integrating with the audit pipeline

Who this is for: Persons 1–5, and anyone wiring the stack up in Compose.
It answers three questions per component — *what do I have to do*, *how do I
know it worked*, and *what will quietly break it*.

The short version: **you almost certainly have to do nothing.** The pipeline
reads container stdout, so a component is audited by existing. The rest of this
file is the exact field vocabulary, so a decision you already log lands in the
right category instead of being classified as noise.

---

## 1. The three ways in

| Path | Endpoint | When to use it |
| --- | --- | --- |
| **Automatic (default)** | *none* — write structured JSON to stdout | Always. This is the path with no library and no coupling. |
| **Push** | `POST /v1/audit/events` | A component that deliberately submits a batch of decisions rather than logging them. |
| **OpenTelemetry** | `POST /v1/traces`, `POST /v1/logs` | A component already instrumented with an OTel SDK. Point the exporter at `http://telemetry:8088` with `OTEL_EXPORTER_OTLP_PROTOCOL=http/json`. |

Push and OTLP are authenticated with `X-Telemetry-Token: $TELEMETRY_INGEST_TOKEN`
(or `Authorization: Bearer`). Stdout needs no credential — it is read from the
Docker API by the collector, which holds the token itself.

**On the Transport Contract (docs/division.md §2):** the audit channel is
service-to-service traffic, so it can run over TLS 1.3 with mutual certificate
verification against the shared CA as soon as that CA exists — set
`TELEMETRY_TLS_CERT_FILE`, `TELEMETRY_TLS_KEY_FILE`, `TELEMETRY_TLS_CA_FILE` and
`TELEMETRY_TLS_REQUIRE_CLIENT_CERT=true` on the service and the collector, and
point `TELEMETRY_URL` at `https://`. Until then it is HTTP and bearer-token
authenticated, like every other channel in this repository. If you are Person 2
and the CA is yours, that is the only integration step this pipeline needs from
you.

The read API (`GET /v1/audit/summary`, `/v1/audit/events`,
`/v1/audit/traces/{trace_id}`, `/dashboard`) is open unless `TELEMETRY_READ_TOKEN`
is set.

---

## 2. The field vocabulary

One JSON object per line. Only the first four rules matter; everything else is
for richness.

| Purpose | Field names accepted (first match wins) |
| --- | --- |
| **Event type** | `msg`, `event`, `event_type`, `event_name`, `event.name`, `name` |
| **Verdict** | `decision`, `verdict`, `outcome`, `result`, `allow` (boolean) |
| **Reason** | `reason`, `deny_reason`, `error_code` |
| **Time** | `time`, `ts`, `timestamp`, `occurred_at` (RFC3339 or unix) |
| **Who** | `user_id`, `sub`, `subject`, `user`, `username`, `enduser.id`; `roles` / `role`. A **nested** `subject: {user_id, roles}` is promoted automatically — that is the implemented policy contract. |
| **Request** | `method` / `http.request.method`; `path` / `url` / `route` / `url.path`; `status` / `status_code` / `http.response.status_code`; `remote_addr` / `ip` / `client_ip` / `client.address` |
| **Authorisation detail** | `action` / `operation`; `resource` / `resource_id` |
| **Trace context** | `traceparent` (`00-<32 hex>-<16 hex>-01`), or a bare `trace_id` |
| **Latency** | `duration_ms`, `latency_ms` |

`log/slog`'s JSON handler already emits `time`, `level` and `msg`, so a service
using it is compliant by default.

### Known event types

These are recognised by name and classified without any extra fields:

| Event type | Category | Verdict |
| --- | --- | --- |
| `http_request`, `access`, `request` | ACCESS | from the status code |
| `login_attempt`, `login`, `authenticate` | AUTH | from `outcome` |
| `access_decision`, `authz_decision`, `policy_decision`, `authorize`, `authz` | AUTHZ | from `decision`/`allow` |
| `rate_limited`, `rate_limit` | RATE_LIMIT | DENY |
| `token_rejected` | AUTH | DENY |
| `request_blocked`, `access_denied`, `forbidden`, `unauthorized` | ACCESS | DENY |
| `upstream_error`, `http_panic`, `panic`, `verification_unavailable`, `readiness_check_failed`, `token_issue_failed`, `internal_error`, `fatal` | ERROR | ERROR |

Anything else is classified from its explicit verdict, then from its HTTP/gRPC
status, then from the last word of its event name (`mtls_handshake_rejected`,
`token-expired`, `signature_invalid`). A record with none of those is treated as
operational noise and skipped — **a decision that carries no signal is worse
than useless here, it is invisible.** If you invent a name, either end it with an
unambiguous outcome word (`..._denied`, `..._blocked`, `..._rejected`,
`..._refused`, `..._expired`, `..._revoked`, `..._invalid`) or send an explicit
`decision`.

### What is deliberately not an audit event

These are dropped even though they are valid JSON with a status code, because
they are the platform talking to itself rather than anyone making a decision:

* Bare probe lines on `/healthz`, `/readyz`, `/livez`, `/health`, `/health/live`,
  `/health/ready`, `/healthcheck`, `/metrics`, `/favicon.ico`, `/robots.txt`.
  One service probing every 15 seconds is thousands of records a day, and in a
  live run of this stack they were 97% of the trail in a fifteen minute window —
  which buries the denials the dashboard exists to show. **Attach a `decision`,
  `reason` or `action` to the line and it is kept**: a probe endpoint that starts
  refusing callers is a real signal.
* Startup banners, migration progress, `db: connected`, `serve: listening` and
  other operational lines with no event name and no verdict.
* Unknown failures (`retry_failed`, `cache.miss`). An unknown failure is as
  likely to be infrastructure as security, and a trail full of retry warnings
  stops being read.

Everything dropped here is still in Loki, so nothing is lost — it is just not
counted as a decision. `telemetry_records_skipped_total` on `/metrics` is how
many records were classified this way.

### Always log `time` — in UTC

The event's identity is a hash of its content, so re-ingesting the same record
(a collector retry, a container restart re-reading its log file) is deduplicated
**only if the record has a timestamp**. Without one it is timestamped at
ingestion, and two deliveries become two genuine-looking observations. Every
service here uses `log/slog`, which does this for free.

It has to be UTC. A record dated in the future is stored — the producer said
what it said, and forensics keeps it — but **no dashboard window will ever show
it**, because a window ends at *now*. Logging local time with a `Z` suffix is the
usual cause, and it is easy to do by accident: on this machine `date` reads
13:27 while the containers read 07:57, so a hand-written
`"time":"2026-09-21T13:27:00Z"` is six hours ahead and invisible. The pipeline
counts and names these rather than hiding them:

```bash
curl -s localhost:8088/metrics | grep future_dated     # expect 0
curl -s localhost:8088/v1/audit/events?limit=1          # newest event: is its occurred_at plausible?
```

`telemetry_events_future_dated_total` above zero, or a `ingest_future_dated`
warning in the telemetry log naming your service, means a producer's clock (or
its timezone handling) is wrong.

---

## 3. Per component

### Person 1 — Identity & Token Authority

**Already integrated, no change needed.** The IdP's existing lines become audit
events:

```json
{"time":"…","level":"INFO","msg":"login_attempt","outcome":"denied","username":"admin"}
  → AUTH / DENY / invalid_credentials, subject admin

{"time":"…","level":"INFO","msg":"http_request","method":"POST","path":"/token","status":200,…}
  → ACCESS / PERMIT / ok
```

`role` and `user_id` on the permitted login are read too, so the trail shows
which account and role obtained a token.

**Five-minute check**

```bash
docker compose logs --since 5m idp | grep login_attempt | tail -3
curl -s 'http://localhost:8088/v1/audit/summary?window=15m' | jq '.summary.by_category'
# expect AUTH to be non-zero after a login attempt
```

**What would break it:** logging the password or the issued JWT. The first 8 KiB
of every record is stored verbatim in `audit_events.raw` for forensics, so
secrets in a log line become secrets in the audit store.

### Person 2 — API Gateway & Perimeter Ingress

Log the decision, not just the outcome. The gateway produces the strongest
signal in the system, because it is where traffic is refused:

```json
{"time":"…","msg":"http_request","method":"POST","path":"/api/v1/payment","status":401,
 "remote_addr":"…","traceparent":"00-…-…-01","duration_ms":2}
  → ACCESS / DENY / unauthorized

{"time":"…","msg":"token_rejected","reason":"signature_invalid","user_id":"…","traceparent":"00-…-…-01"}

{"time":"…","msg":"rate_limited","remote_addr":"…","path":"/login"}     → RATE_LIMIT / DENY

{"time":"…","msg":"verification_unavailable","error":"jwks fetch failed"} → ERROR
```

Two details worth getting right:

* **Always forward `traceparent`.** The gateway is the first hop, so the trace
  id it arrives with is the one every later decision joins on. If the header is
  absent, generate one and log it.
* A `503` from an unreachable JWKS endpoint is an ERROR, not a DENY. Sending
  `verification_unavailable` (or any 5xx) keeps "the guard was down" distinct
  from "the caller was refused" — those are different incidents.

**Five-minute check**

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/login \
     -H 'Content-Type: application/json' -d '{"username":"x","password":"y"}'   # expect 401
curl -s 'http://localhost:8088/v1/audit/events?decision=DENY&limit=5' | jq '.events[] | {service,event_type,path,status,reason}'
# expect your gateway's denial, with the service name "gateway" and a trace id
```

### Person 3 — Policy Engine & ABAC Evaluator

The engine itself is OPA (`openpolicyagent/opa:1.20.2`) with the policies in
`policy-engine/policies/`, queried at
`POST http://policy-engine:8181/v1/data/authz/allow`. Nothing about auditing
requires the engine to change — but **today its verdicts reach the trail through
its callers, not through the engine**, because OPA's decision log is off. See
"Making the engine auditable" below.

**Your callers' line** (Persons 2, 4, 5) is what the pipeline reads, and the
implemented contract shape is the nested one from `docs/policymaker.md` — note
that `docs/division.md` §"Policy Request Contract" shows a *flat* `input` whose
roles are top-level, and the engine denies that shape by default:

```json
{"time":"…","msg":"access_decision","service":"payment-service",
 "input":{"subject":{"user_id":"uuid-from-jwt","roles":["customer"]},
          "action":"TRANSFER","resource":"account_987",
          "context":{"amount":60000,"ip_address":"192.168.1.50","mTLS_verified":true}},
 "result":{"allow":false},
 "reason":"threat_level_high"}
  → AUTHZ / DENY / threat_level_high, subject uuid-from-jwt, roles [customer],
    remote_addr 192.168.1.50, action TRANSFER, resource account_987
```

The nested `subject` and `context` objects are understood: `user_id`, `roles` and
`ip_address` are promoted to first-class fields, while `raw` keeps the payload in
exactly the shape the caller wrote. `{"allow":false}` (flat), a bare
`decision`, and `outcome` all work too.

**Making the engine auditable (a one-line change for Person 3)**

Person 3's README lists `decision_logs.console=true` as deferred hardening. When
you want the engine's own verdicts in the audit trail — including the calls that
*no* caller logged, such as a deny the caller never got to record — add one flag
to the `policy-engine` service's command:

```yaml
      - --set=decision_logs.console=true
```

The pipeline already understands the resulting records (they are tested):

```json
{"decision_id":"9adac1e2-…","msg":"Decision Log","type":"openpolicyagent.org/decision_logs",
 "input":{"subject":{"user_id":"…","roles":["customer"]},"action":"TRANSFER",
          "context":{"amount":60000,"ip_address":"192.168.1.50"}},
 "result":{"allow":false},"time":"2026-09-21T08:00:00.123456789Z"}
  → AUTHZ / DENY / policy_denied, subject and client promoted from input,
    request id = OPA's own decision_id
```

OPA writes those records as JSON on its **stderr**; the collector reads both
streams, so nothing else is needed. Do not enable it in the baseline PR if you
consider it out of scope — but know that the integration is finished on this
side, and that the switch is one flag rather than a shim.

One honest limitation: **OPA's decision log carries no trace context.** Its
records join to a flow only if the *caller* also logs the verdict with its
`traceparent`, which is why the caller-side line above remains the primary path
and the engine's own log is the belt-and-braces copy. If you want the engine's
decisions to join traces directly, the traceparent would have to be passed into
the `input` (e.g. `input.context.traceparent`) and echoed by the policy; that is
a contract change for Persons 3, 4 and 5 to agree on, not something this
pipeline can infer.

On gRPC, log the canonical names — `rpc.service`, `rpc.method` and `grpc.code`
(numeric or `PERMISSION_DENIED`) — and the call appears as
`/authz.PolicyService/Check` with the HTTP-equivalent status, so
`PERMISSION_DENIED` is a DENY and `OK` is a PERMIT.

**Five-minute check** (the engine publishes no host port, so call it from inside
the compose network):

```bash
docker compose exec idp wget -qO- --header='Content-Type: application/json' \
  --post-data='{"input":{"subject":{"user_id":"u","roles":["customer"]},"action":"TRANSFER","resource":"account_987","context":{"amount":50,"ip_address":"192.168.1.50","mTLS_verified":true}}}' \
  http://policy-engine:8181/v1/data/authz/allow
# → {"result":{"allow":true}}   (60000 instead of 50 → {"result":{"allow":false}})
curl -s 'http://localhost:8088/v1/audit/events?category=AUTHZ&limit=5' | jq '.events[] | {service,subject,roles,action,resource,remote_addr,decision,reason}'
```

**What would break it:** logging only the *request* and not the verdict. The
`input` envelope alone has no `allow`/`decision` field, so it is skipped — which
is correct, since a request that was never answered is not a decision.

### Person 4 — Microservice A (Account Service)

You re-check policy before business logic. Log both halves of that:

```json
{"time":"…","msg":"access_decision","user_id":"…","action":"read","resource":"account_987",
 "decision":"permit","service":"account-service","traceparent":"00-…-…-01"}
```

mTLS rejections are the failure mode that is easy to miss: a client with no
certificate never reaches a handler, so nothing logs it unless the TLS layer
does. Emit a line for it (`msg":"mtls_handshake_rejected"`), or the single most
common integration failure in this project leaves no trace at all.

**Five-minute check**

```bash
docker compose logs --since 5m account-service | grep -E 'mtls|access_decision' | tail -5
curl -s 'http://localhost:8088/v1/audit/summary?window=15m' | jq '.summary.by_service'
```

### Person 5 — Payment & Transaction Service

Same shape, plus one instruction: name the high-risk action explicitly, so the
re-verification is distinguishable from an ordinary read.

```json
{"time":"…","msg":"access_decision","user_id":"…","action":"TRANSFER","resource":"account_987",
 "decision":"deny","reason":"threat_level_high"}
```

If you expose gRPC, the `rpc.*` / `grpc.code` convention above applies unchanged.

**Five-minute check**

```bash
curl -s 'http://localhost:8088/v1/audit/events?category=AUTHZ&decision=DENY&limit=10' \
  | jq '.events[] | select(.service=="payment-service") | {action,resource,reason}'
```

### The platform / Compose wiring

| Service | Port | Notes |
| --- | --- | --- |
| `telemetry` | 8088 | Ingest, read API, dashboard. `/readyz` pings the store. |
| `telemetry-collector` | 8089 | Its own `/healthz`, `/readyz`, `/metrics`. Reads the Docker socket read-only. |
| `jaeger` | 16686 | Span browser. |
| `loki` / `grafana` | 3100 / 3300 | Full log search. |

The collector only ever issues `GET` on the Docker API. It needs the socket's
group id (`TELEMETRY_DOCKER_GID`) and, on an SELinux host, `label=disable` —
both already set in the root `docker-compose.yml`.

**Table ownership:** telemetry writes `audit_events` and `spans` and reads
nothing else. Its migration bookkeeping is namespaced
(`telemetry_schema_migrations`) because golang-migrate's default
`schema_migrations` table is per-*database*, and every service here migrates the
same shared instance — two services using the default silently make each other
skip migrations. **If your service runs `golang-migrate`, set a unique
`x-migrations-table`.** See `README.md` §5.

---

## 4. The five-minute end-to-end check

Run the checks for the components that exist in your checkout; the ones for the
gateway, account service and payment service are the contract they should be
built against, and are marked below where the service is still pending.

With the stack up (`docker compose up --build -d`), run one login and watch it
travel the whole pipeline:

```bash
TOKEN=$(curl -s -X POST localhost:8080/login -H 'Content-Type: application/json' \
        -d '{"username":"admin","password":"admin123"}' | jq -r .access_token)

curl -s -o /dev/null -w 'gateway: %{http_code}\n' localhost:8080/api/v1/accounts -H "Authorization: Bearer $TOKEN"
curl -s -o /dev/null -w 'gateway: %{http_code}\n' localhost:8080/api/v1/accounts              # expect 401

# 1. Did the collector see it?          -> shipped count rises
curl -s localhost:8089/metrics | grep -E 'shipped|dropped|ready'

# 2. Did the pipeline store it?         -> denials and unauthorised attempts
curl -s 'http://localhost:8088/v1/audit/summary?window=15m' | jq '.summary | {by_category,by_service,denials,unauthorized_attempts}'

# 3. Can it be joined to a trace?       -> spans AND events on one trace id
TRACE=$(curl -s 'http://localhost:8088/v1/audit/events?decision=DENY&limit=1' | jq -r '.events[0].trace_id')
curl -s "http://localhost:8088/v1/audit/traces/$TRACE" | jq '{spans: (.trace.spans|length), events: (.trace.events|length)}'

# 4. Is everything still in the centralized log store?
curl -s 'http://localhost:3100/loki/api/v1/label/service/values' | jq
```

Then open the dashboard at <http://localhost:8088/dashboard> and the span browser
at <http://localhost:16686>.

If step 1 shows records shipped but step 2 shows nothing stored, the records are
being classified as noise: compare your line against §2 and check for `time` and
a recognised event name. `GET /metrics` on 8088 exposes
`telemetry_records_skipped_total`, which is exactly that count.
