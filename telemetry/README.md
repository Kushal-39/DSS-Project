# Telemetry — Observability, Distributed Tracing & Centralized Logging

**Person 6's deliverable** (docs/division.md):

> Deploy centralized log ingestion (ELK/Loki) and distributed tracing
> (Jaeger/Zipkin via OpenTelemetry). Build a central audit logging consumer
> that ingests security decision logs from the API Gateway, Microservices, and
> Policy Engine.
>
> **Deliverable:** Telemetry receiver and audit dashboard tracking blocked
> requests, unauthorized access attempts, and trace flows across all
> components.

Everything in this directory is self-contained. The only file it touches
outside it is an **additive** block in the root `docker-compose.yml`; the
`idp` service and the `networks` block are untouched.

---

## 1. What is running

```
                        ┌──────────────────────────────────────────┐
  IdP ─┐                │  telemetry  (this component)             │
  gateway ─┐            │                                          │
  policy-engine ─┤      │  POST /v1/audit/events  explicit decisions│
  account-svc ─┤  push  │  POST /v1/audit/logs    shipped stdout    │
  payment-svc ─┘ ──────▶│  POST /v1/traces        OTLP/JSON spans   │
  OTel SDKs ───────────▶│  POST /v1/logs          OTLP/JSON logs    │
                        │            │                             │
  every container ─────▶│  cmd/shipper (central audit consumer)     │
      stdout            │            │                             │
                        │            ▼                             │
                        │   normalise ──▶ audit_events + spans     │
                        │   (classify,     (PostgreSQL)            │
                        │    deduplicate)         │                │
                        │            ┌────────────┴─────────────┐   │
                        │            ▼                          ▼  │
                        │  GET /v1/audit/summary      /v1/traces ──┼──▶ Jaeger
                        │  GET /v1/audit/events                    │    (UI :16686)
                        │  GET /v1/audit/traces/{id}               │
                        │  GET /dashboard  (audit dashboard)       │
                        └──────────────────────────────────────────┘

  every container stdout ──▶ promtail ──▶ Loki (:3100) ──▶ Grafana (:3300)
```

| Service | Port | What it is |
| --- | --- | --- |
| `telemetry` | 8088 | The audit ingest API, read API and dashboard. **This is the deliverable.** |
| `telemetry-collector` | 8089 | `cmd/shipper`: the central audit logging consumer. Has its own `/healthz`, `/readyz` (Docker API reachable) and `/metrics`. |
| `jaeger` | 16686 | Distributed tracing UI (OTLP spans, mirrored by telemetry). |
| `loki` | 3100 | Central log store. |
| `promtail` | — | Ships every container's stdout to Loki. |
| `grafana` | 3300 | Log exploration over Loki (datasource provisioned; 3300 because 3000 is usually taken locally). |

**Start here: <http://localhost:8088/dashboard>**

---

## 2. The three things this component has to do

### 2.1 Collect security decisions from every component

Five components emit structured JSON logs and OpenTelemetry spans
(docs/flow.md §6). None of them has to change: the collector reads container
stdout over the Docker API, keeps the records that carry a security signal,
tags each one with the service that produced it, and posts them to
`POST /v1/audit/logs`.

A record is classified into a category and a verdict (`PERMIT` / `DENY` /
`ERROR` / `INFO`) by matching the event names the project already emits:

| Producer event | Category | Verdict |
| --- | --- | --- |
| `http_request` + status | `ACCESS` | `PERMIT` for 2xx/3xx, `DENY` for 401/403/429, `ERROR` for 5xx |
| `login_attempt` (`outcome`) | `AUTH` | `DENY`/`invalid_credentials`, or `PERMIT`/`authenticated` |
| `access_decision` (`allow`) | `AUTHZ` | the Policy Engine's verdict |
| `rate_limited` | `RATE_LIMIT` | `DENY`/`rate_limited` |
| `token_rejected` | `AUTH` | `DENY` with the producer's reason |
| `http_panic`, `upstream_error`, `fatal`, … | `ERROR` | `ERROR` |
| anything else with no verdict and no request shape | — | **skipped** (Loki's job) |

Components that prefer to push directly use `POST /v1/audit/events` with the
same payloads; both paths run through the same normaliser, so they cannot
disagree.

### 2.2 Ingest traces and join them to decisions

`POST /v1/traces` accepts OTLP/JSON — the wire format every OpenTelemetry SDK
can produce with `OTEL_EXPORTER_OTLP_PROTOCOL=http/json` — and stores the
spans. The W3C trace id from `traceparent` (docs/flow.md §3) is the only
identifier all components already share, so it is the join key: for a given
trace you get the spans *and* every audit decision taken inside it, in order.

Received spans are then mirrored to Jaeger (`TELEMETRY_FORWARD_OTLP_ENDPOINT`),
so telemetry acts as a real collector: one export from the producer, a copy
stored for the audit join, a copy forwarded for visual browsing.

### 2.3 Answer the security questions

The dashboard (<http://localhost:8088/dashboard>) tracks exactly what the
deliverable names:

* **blocked requests** — `deny` verdicts, broken down by reason, service and client;
* **unauthorized access attempts** — rejected credentials and policy denials,
  counted **separately from rate limiting** so a burst of throttling cannot
  mask an intrusion attempt;
* **trace flows across all components** — the trace explorer joins spans and
  decisions for one request.

It is a single embedded HTML page with no build step and no external
dependency, so a reviewer runs one command and opens one URL.

---

## 3. Run it

```bash
# From the repository root. The root .env must be unlocked first
# (CONTRIBUTING.md §3): git-crypt unlock /path/to/zerotrust-key.key
docker compose up --build
```

Then open <http://localhost:8088/dashboard>.

No database of your own? `TELEMETRY_STORE=memory docker compose up --build`
runs the pipeline and dashboard with a volatile store.

> **If the `telemetry` container exits immediately**, read its log: it will say
> which variable is missing. The root `.env` is git-crypt encrypted, so the keys
> below can only be added by whoever holds the key — telemetry deliberately
> **refuses to boot without `TELEMETRY_INGEST_TOKEN`** rather than run an audit
> endpoint that anyone on the network can forge records into. Add the three
> required keys and `docker compose up -d telemetry telemetry-collector` is
> enough; nothing else needs restarting.

### Environment variables

Add these to the root `.env` (see `.env.example` for the full list with
comments):

| Variable | Required | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | yes (postgres mode) | Shared instance; telemetry owns `audit_events` and `spans` |
| `TELEMETRY_INGEST_TOKEN` | yes | Authenticates collectors; `openssl rand -hex 32` |
| `TELEMETRY_READ_TOKEN` | no | Protects the read API + dashboard (open when unset) |
| `TELEMETRY_STORE` | no | `postgres` (default) or `memory` (volatile, demo only) |
| `TELEMETRY_FORWARD_OTLP_ENDPOINT` | no | Mirror spans to another collector, e.g. `http://jaeger:4318` |
| `TELEMETRY_RETENTION` | no | Audit retention (default `720h`) |
| `TELEMETRY_SHIP_EXCLUDE` | no | Services the collector ignores (default `telemetry`) |
| `TELEMETRY_SHIP_ADDR` | no | The collector's own status listener (default `:8089`, empty disables) |
| `TELEMETRY_SHIP_BACKFILL` | no | First-read history per container (default `30m`, `0s` reads everything) |
| `TELEMETRY_TLS_CERT_FILE` / `_KEY_FILE` | no | Serve the ingest API over TLS 1.3 (both, or neither) |
| `TELEMETRY_TLS_CA_FILE` | no | The shared self-signed CA that signed the peer's certificate |
| `TELEMETRY_TLS_REQUIRE_CLIENT_CERT` | no | Refuse a collector that presents no certificate (default `false`) |
| `TELEMETRY_TLS_SERVER_NAME` | no | Collector only: the name to verify in the API's certificate |
| `TELEMETRY_DOCKER_GID` | no | gid of the host docker socket: `stat -c '%g' /var/run/docker.sock` |

The service refuses to start without `DATABASE_URL` (in postgres mode) or
without `TELEMETRY_INGEST_TOKEN`, rather than booting with an incomplete audit
trail. `TELEMETRY_INSECURE_INGEST=true` is the only way to run ingest open, it
is meant for a local demo, and the service logs a warning on every start.

---

## 4. API

Ingest (authenticated with `X-Telemetry-Token` or `Authorization: Bearer`):

| Method | Path | Body |
| --- | --- | --- |
| `POST` | `/v1/audit/events` | an event object, an array, or `{"events":[...]}` |
| `POST` | `/v1/audit/logs` | one JSON record per line (NDJSON), an array, or an envelope |
| `POST` | `/v1/traces` | OTLP/JSON `ExportTraceServiceRequest` |
| `POST` | `/v1/logs` | OTLP/JSON `ExportLogsServiceRequest` — decisions exported by an OTel SDK |

The OTLP paths take JSON, not the SDK's default protobuf. A protobuf export is
refused with **415 and the exact variable that fixes it**
(`OTEL_EXPORTER_OTLP_PROTOCOL=http/json`) rather than a 400 that sends the
reader looking at their payload.

Ingest responses are receipts, not just 200s:

```json
{"accepted": 2, "duplicates": 0, "skipped": 2}
```

`duplicates` means the record was already stored (a collector retry, a
container restart re-reading its log file); `skipped` means the record carried
no security signal. Both are normal.

Read:

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/v1/audit/summary?window=24h` | counts, denial rate, timeline, top denial reasons, latest denials |
| `GET` | `/v1/audit/events` | `decision`, `category`, `service`, `reason`, `subject`, `trace_id`, `q`, `since`, `until`, `limit`, `offset` |
| `GET` | `/v1/audit/traces/{traceID}` | spans + decisions for one flow; 404 when nothing is known about it |
| `GET` | `/dashboard` | the audit dashboard |

Operations (never authenticated, so Docker and the platform can probe them):
`/healthz`, `/readyz` (pings the audit store) and `/metrics` (Prometheus text).

### TLS and mTLS

The audit channel is internal service-to-service traffic, so the project's
Transport Contract (docs/division.md §2 — TLS 1.3, mutual certificate
verification against the shared self-signed CA) applies to it. **It is
configuration, not code**: with no TLS variables set the API answers plain HTTP
and authenticates collectors with the bearer token, which is what the rest of
this repository does today. Set the four variables above and the ingest API only
answers TLS 1.3 peers, verifying a collector's certificate when it presents one
and refusing peers without one when `TELEMETRY_TLS_REQUIRE_CLIENT_CERT=true`.
The collector reads the same variables to verify the API and present its own
certificate.

Three deliberate choices, each of which the tests assert:

* **TLS 1.3 is a floor, not a preference.** A client that can only offer 1.2 is
  refused rather than negotiated down to; naming a version in a contract and
  then accepting less is how a contract becomes decoration.
* **The CA is pinned.** A client trusts the certificate you gave it, not the
  system pool, so a certificate from a public authority is not a reason to trust
  the audit API. Likewise the API never accepts an unauthenticated peer when a
  client certificate is required: the token is not the only thing standing
  between an attacker and the security record.
* **`verified-if-given` is the default mode.** With a CA but without
  `TELEMETRY_TLS_REQUIRE_CLIENT_CERT`, a presented certificate is verified and
  an absent one is merely anonymous — the staged-rollout path that does not
  break every collector the moment a CA appears.

The certificates only have to be minted once the shared CA exists. To try the
path before then, `internal/certtest` generates a throwaway authority, which is
what the tests use.

The `window` parameter is clamped to `TELEMETRY_MAX_WINDOW` (default 30 days),
so a public read endpoint cannot be used to make the database scan everything.

---

## 5. Schema

`telemetry/migrations/` (applied automatically at container start, per
docs/database.md §4) creates two tables this service owns exclusively:

* `audit_events` — one row per decision: verdict, reason, subject, roles,
  method/path/status, client, trace/span id, and the original producer payload
  (bounded at 8 KiB) for forensics.
* `spans` — the flattened OTLP spans, so a decision can be joined to the flow
  it happened inside.

Components reach this data over the ingest API, never by querying these tables
(docs/database.md §2).

> **Note for every service in this repo.** golang-migrate records applied
> versions in a table called `schema_migrations`, which is per *database*, not
> per service — and every service here migrates the *same shared instance*.
> The first service to boot writes version 1, and the next one is then told
> "migrations already up to date" and silently skips creating its tables. It
> is not hypothetical: it broke the IdP's seed in this project's own end-to-end
> run. Telemetry namespaces its bookkeeping as
> `telemetry_schema_migrations`; other services should do the same
> (`?x-migrations-table=<service>_schema_migrations`).

---

## 6. What was verified, end to end

Not "it compiles" — every claim below was observed against the real services,
a real PostgreSQL 16 instance, and the real IdP:

```bash
docker compose up -d --build        # 9 services, all healthy
curl -X POST localhost:8080/login -d '{"username":"admin","password":"wrong"}'        # 401
curl -X POST localhost:8080/login -d '{"username":"admin","password":"admin123"}'     # 200
```

| Check | Observed |
| --- | --- |
| IdP decisions reach the audit trail | `AUTH / DENY / invalid_credentials` with subject `admin`; `AUTH / PERMIT / authenticated` with the user UUID — ingested from the IdP's own container logs, no IdP change |
| Blocked requests and unauthorized attempts | summary reported 13 denials / 13 unauthorized attempts, `by_reason`: `invalid_credentials` 6, `unauthorized` 6, `threat_level_high` 1 |
| Trace join | `GET /v1/audit/traces/4bf92f35…` → 2 spans **and** 22 decisions, services `["idp"]`, 12 denials |
| OTLP ingest + mirror | 2 spans accepted; Jaeger's API then listed the trace under service `idp` |
| Idempotency | re-posting an identical export → `{"accepted":0,"duplicates":2}` |
| Ingest auth | no token → 401, wrong token → 401, right token → 200 |
| Dashboard | 200, 23 KB, all panels populated, no console errors |
| Centralized logging | Loki held streams for every container in the project — including `policy-engine`, which was added later and needed no configuration — labelled `service`/`container`/`level`/`event` |
| Person 3's real contract | the *nested* payload from `docs/policymaker.md` (`input.subject.user_id`, `input.subject.roles`, `input.context.ip_address`) → subject, roles and client address all promoted into stored rows; the flat variant from `docs/division.md` is also accepted |
| The Policy Engine's own verdicts | with `--set decision_logs.console=true`, OPA 1.20.2's decision log reached the trail via container logs: `AUTHZ / PERMIT / policy_allowed` for a 50 transfer and `AUTHZ / DENY / policy_denied` for 60000, each with its `decision_id` as the request id, subject `uuid-1111-2222`, `roles [customer]` and client `192.168.1.50`/`203.0.113.9` — the engine needed no code change and no log shim |
| Grafana (datasource) | Loki datasource provisioned on first boot, with the trace-id field that pivots a log line into Jaeger |
| Grafana (dashboards) | the log dashboard provisioned from JSON into the *Zero-Trust* folder and rendering live data: 5.86k log lines, 4 errors, 12 warnings, 710 log rows across the log panels |
| Every dashboard query is valid and returns data | all 11 panel targets executed through Grafana's own Loki proxy (`/api/datasources/proxy/uid/loki/…`) rather than only written down: 12 series for volume by service, and the counting panels reading `0` in a quiet window instead of "No data" |
| Tests | `go test -race ./...` green; the Postgres integration test green against real Postgres |
| OTLP logs signal | a decision exported as an OTel log record was stored as `AUTHZ / DENY / threat_level_high`, attributed to the resource's `service.name`, and joined to the span on the same trace id |
| Policy Engine's ABAC envelope | `{"input":{…"context":{"ip":…}}}` → subject, action, resource and client address all promoted to first-class fields (verified in the database, not just the API) |
| gRPC decisions | `rpc.service`/`rpc.method`/`grpc.code: PERMISSION_DENIED` → path `/payments.TransactionService/Transfer`, status 403, `ACCESS / DENY / forbidden` |
| Protobuf exports | `POST /v1/logs` with `application/x-protobuf` → 415 naming `OTEL_EXPORTER_OTLP_PROTOCOL=http/json` |
| The collector can be observed | its own `/readyz` on 8089 reported `following 8 containers`, `queued 37`, `shipped 37`, `dropped 0`, `failed 0`, `skipped 119`, and Docker showed it **healthy**. `queued` is what makes a delivery stall distinguishable from an idle stack: read-but-not-shipped is the one failure a `shipped` counter alone cannot show |
| Read auth and the dashboard sign-in | no credential → 401, wrong token → 401; `GET /dashboard?token=<read token>` → 302 to `/dashboard` with an `HttpOnly; SameSite=Strict` cookie (no token left in the URL), and that cookie alone then opened the dashboard **and** the API the page calls. `/healthz`, `/readyz` and `/metrics` stay open for the platform |
| Container hardening is real | `docker inspect` on the running services: `ReadonlyRootfs=true`, `CapDrop=[ALL]`, `no-new-privileges:true` — and both still serve traffic, so the hardening is exercised rather than declared |
| The migration rollback works | against real PostgreSQL: `migrate` idempotent, `status` reported version 1 not dirty, the DOWN script dropped `audit_events` and `spans` while leaving telemetry's own `telemetry_schema_migrations`, and a re-run restored the schema |
| Retention actually deletes, and says what | an expired decision and an expired span were ingested, the service restarted, and it logged `purge_complete removed_events 1 removed_spans 1` — with the recent rows still present, so the sweep is bounded and honest rather than merely configured |
| Probe traffic stays out of the trail | before the fix, 60 of 62 events in a 15 minute window were the IdP's `/readyz`; after it, no new probe is stored and the window holds only decisions |
| Clock skew is visible | a record dated 6 hours ahead was stored (forensics keeps it) and counted: `telemetry_events_future_dated_total 1` plus an `ingest_future_dated` warning naming the delta and the cause |

```bash
cd telemetry

# Unit tests (no database needed).
go test -race ./...

# The real SQL: migrations, upserts, every filter, the aggregate query,
# the trace join, and retention. Point it at a THROWAWAY database.
TELEMETRY_TEST_DATABASE_URL='postgres://user:pw@host:5432/db?sslmode=disable' \
  go test ./internal/store/... -run TestPostgresStore -v

# The migration lifecycle, including the DOWN script, which drops tables. The
# second variable is the acknowledgement that makes that safe to run by
# accident: point the URL at a throwaway database, never the shared instance.
TELEMETRY_TEST_DATABASE_URL='postgres://user:pw@host:5432/db?sslmode=disable' \
TELEMETRY_TEST_DESTRUCTIVE=1 \
  go test ./internal/db/... -run TestMigrateDownAndVersionAgainstPostgres -v
```

The two variables above are the only ones the tests read, and they are
intentionally absent from `.env.example`: it is a deployment template, and a
destructive toggle in it would eventually be set in a deployment.

### Bugs this run found (and fixed)

The end-to-end runs were not a formality; they caught thirteen real defects that
unit tests written from the same assumptions would have missed:

1. **OTLP ids were mangled.** The decoder confused hex characters with bytes,
   padding a 32-character trace id to 64. Spans then round-tripped through
   ingest perfectly and simply never joined to a single decision.
2. **Nanosecond timestamps lost precision.** Parsing `1758440000123500000` as a
   float64 dropped the low nanoseconds (a 32 ns drift). Fixed by keeping
   integers integral.
3. **A mixed log batch was rejected with 400.** One unstructured line threw
   away the decisions in the same batch. (Regression test:
   `TestParseLogsHandlesNewlineDelimitedBatches`.)
4. **The migration table collided with the IdP's**, breaking the IdP's seed —
   see the note in §5.
5. **An in-flight span (NULL `ended_at`) failed the whole trace lookup** with a
   scan error instead of returning the flow.
6. **The collector followed its own container.** Docker sets `HOSTNAME` to the
   *short* container id while the API reports the long one, so the equality
   check never matched and the collector shipped the log lines that its own
   shipping produced.

7. **The audit trail was 97% probe traffic.** Every service's `/readyz` was
   audited as an ACCESS permit, so 60 of the 62 events in a fifteen minute window
   were the IdP answering a health check — which dilutes the denial rate the
   dashboard exists to show. Probe paths are now excluded unless the producer
   attaches a verdict to them (`docs/integration.md`).
8. **A future-dated record was invisible and silent.** A producer logging local
   time with a `Z` suffix has every decision stored — and excluded from every
   window, because a window ends at *now*. Found by doing exactly that while
   verifying this change. It is now counted
   (`telemetry_events_future_dated_total`) and named in a warning, instead of
   being discovered by someone asking why the dashboard is empty.
9. **An OTLP log record of the same decision classified differently from a
   stdout line.** A string `body` was read as the message but not as the event
   name, so `access_decision` exported over OTLP landed in ACCESS rather than
   AUTHZ. The decoded `severityNumber` was also ignored, which is worse than not
   decoding it. Both are fixed, and the parity is now a test.
10. **The stored decision depended on the transport that carried it.** OTLP
    attributes are flat, so an envelope that arrives nested over stdout arrives
    as `input.subject.user_id` over OTLP. The classifier read the nested form
    only, which meant a policy decision stored with no subject, no roles and no
    client address — or, when the flat form carried no verdict field either,
    dropped entirely and counted as chatter. The envelope is now rebuilt from
    its dotted form before anything reads it, so all three transports produce
    the same row (`TestFromMapReadsAFlattenedOTLPEnvelope`).
11. **A record marshalled into the OTLP body was treated as prose.** A producer
    that logs a marshalled object puts the whole record in `body`; read as
    text, it had no field the classifier could use, so a decision exported that
    way was silently dropped. `body` is now parsed when it holds a JSON object
    (`TestDecodeLogsReadsARecordMarshalledIntoTheBody`).

12. **The retention log under-reported what it deleted.** `Telemetry purge`
    removes from two tables — `audit_events` and `spans` — and reported one
    count, so a sweep that removed one decision *and* one span logged
    `removed 1`, and a sweep that removed only expired spans logged nothing at
    all. It now reports `removed_events` and `removed_spans` separately, because
    those are different things and an operator deciding whether the trail is
    shrinking has to be able to tell them apart.
13. **`TELEMETRY_STORE=memory` never purged spans.** One interface, two
    implementations, and the demo backend deleted events while keeping every
    span forever — so the trace view grew without bound in exactly the mode a
    reviewer is most likely to run, while the same retention setting kept
    Postgres bounded. A demo that behaves differently from production is a demo
    of something else.

Finding 10 was found by exporting a decision three ways and diffing the stored
rows, which is the only way this class of bug shows up: every counter was
healthy, the pipeline reported `dropped 0`, and the trail was simply missing
what it exists to record. Finding 12 was found the same way — by reading the
service's own log line next to the database and noticing the arithmetic did not
add up.

Two integration-shape findings came out of the same run: SELinux denies
container access to `/var/run/docker.sock` even for root (hence
`security_opt: label=disable` on the two services that read it), and Promtail
3.1 does not publish `__meta_docker_container_state`, so a `keep` rule on it
silently produced label-less streams that Loki rejected.

---

## 7. Layout

```
telemetry/
  cmd/telemetry/          the service: serve + migrate subcommands
  cmd/shipper/            the central audit logging consumer
  internal/audit/         the event model, the normaliser, the parsers, aggregation
  internal/store/         the Store contract, Postgres and in-memory backends
  internal/otlp/          OTLP/JSON decoding and the Jaeger mirror
  internal/collector/     the Docker API client and the log shipper
  internal/api/           the HTTP surface and the embedded dashboard
  internal/config/        fail-fast configuration
  internal/db/            pool + embedded migration runner
  migrations/             the audit schema, embedded in the binary
  observability/          Loki, Promtail and Grafana configuration, including
                          the provisioned log dashboards (as code)
```

See `observability/README.md` for why there are two log paths,
**`docs/integration.md` for the per-component contract** (the field vocabulary,
each person's five-minute check, and what would silently break it), and
`docs/decisions.md` for the reasoning behind the design choices.

## 8. Integrating a new component

Nothing to install, nothing to import:

1. Log structured JSON to stdout with `time`, `level` and `msg` (the IdP's
   `slog` setup is the reference), and include `traceparent` when you have it.
2. Run as a Compose service in this project. The collector follows it
   automatically (label discovery) and tags its records with the service name.
3. That is it. Your `http_request` lines become ACCESS decisions, your
   `login_attempt` lines become AUTH decisions, and your trace ids join them to
   spans.

If you would rather push explicitly, `POST /v1/audit/events` with
`{"msg":"...","decision":"DENY","reason":"...","user_id":"...","traceparent":"..."}`
takes the same normalisation path.

**Read `docs/integration.md` next.** It is the contract rather than the tour: the
exact field names each component should use, the OpenTelemetry semantic
conventions that are also understood, what is deliberately *not* an audit event,
and a five-minute check per person. Two rules from it are worth repeating here,
because both were learned the hard way in this stack's own end-to-end run:

* **Log UTC.** A record dated in the future is stored but no dashboard window
  will ever show it, because a window ends at *now*.
* **Never log credentials.** The first 8 KiB of every record is stored verbatim
  in `audit_events.raw` for forensics.
