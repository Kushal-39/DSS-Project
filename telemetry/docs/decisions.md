# Telemetry — design decisions

Why this component is shaped the way it is. Each entry states the decision, the
reason, and what it costs, so a reviewer can disagree with the reasoning rather
than guess at it.

---

## 1. Two stores, not one: Loki for logs, PostgreSQL for decisions

**Decision.** Container stdout goes to Loki (promtail). The structured records
that carry a security verdict are *also* classified, normalised and written to
this service's own `audit_events` table.

**Why.** "All the logs" and "the security record" are different products with
different requirements:

* A log store is optimised for volume, full-text search and short retention.
  An audit trail has to be queryable by *decision* ("how many requests were
  blocked in the last hour, by reason, by client?"), answerable for years, and
  it must not silently lose records.
* Copying the whole log stream into the audit trail does the opposite: it buries
  the decisions under startup banners and retry warnings, and it couples the
  security record's retention to a debug log's.
* Loki's label model would break under the cardinality of an audit trail
  (subject, client, path). A relational table indexes those columns for free.
* Person 6's deliverable names both an audit consumer *and* centralized log
  ingestion. One store cannot be honest about both.

**Cost.** Two paths over the same stdout, so a change in log shape can affect
one and not the other. Mitigated by deriving both from the same container
stdout rather than asking components to emit twice, and by testing the
classification against the real producers' lines.

---

## 2. The audit consumer reads container stdout, not component code

**Decision.** `cmd/shipper` follows containers over the Docker API, keeps the
structured records, tags each with the service it came from, and forwards it.
No component imports a telemetry library.

**Why.**

* Five people are writing five services in parallel. A collector that requires
  each of them to adopt a client library, in five different languages, creates
  five integration bugs and five reasons for the audit trail to have a hole.
* The IdP never names itself in a log line. The collector knows which container
  the bytes came from, so it supplies what the producer omitted — the audit
  trail says `service: idp` without the IdP changing.
* A component that exists is auditable. Nothing to remember, nothing to keep in
  sync.

**Cost.** The collector needs access to the Docker socket, which is the most
privileged thing in the stack (see §7), and it depends on the container log
driver. Both are documented, filtered (label discovery plus an explicit exclude
list) and read-only.

---

## 3. Decisions are idempotent, and a batch is never all-or-nothing

**Decision.** Every event gets a content-derived id, and ingest is
`ON CONFLICT DO NOTHING`. A batch containing unstructured lines records the
structured ones and counts the rest as `skipped`.

**Why.**

* Collectors retry, containers restart and re-read their log files, and a
  dropped stream is re-read with an overlap. All of that re-delivers records.
  Without idempotency the audit trail inflates, and an inflated count of
  "unauthorized attempts" is worse than no count.
* The first end-to-end run rejected a whole batch with 400 because one line was
  a startup banner. Losing the decisions in that batch to complain about the
  banner is the wrong trade, so `skipped` is a normal, reported outcome.

**Cost.** The id has to include everything that distinguishes two records —
including the verdict fields, because a payload large enough to be truncated to
a placeholder would otherwise make two different decisions look identical.

---

## 4. Ingest is authenticated; reads are open by default

**Decision.** `TELEMETRY_INGEST_TOKEN` is required (the service refuses to
start without it, or without an explicit `TELEMETRY_INSECURE_INGEST=true`).
`TELEMETRY_READ_TOKEN` is optional and open when unset. Comparisons are
constant-time.

**Why.** An unauthenticated ingest endpoint lets anyone with network access
forge or flood the security record — the audit trail becomes a liability. The
read side is a different risk profile: it is read-only, it leaks no secrets,
and requiring a token by default would put a step between a reviewer and the
deliverable they were asked to look at. It is one variable to change.

**Cost.** A token, not mTLS, on the internal ingest path. mTLS would be
stronger, but the project's Transport Contract applies to service-to-service
traffic between the request path components, and introducing a second CA
expectation here would add a failure mode (expired certs) to the pipeline whose
whole job is to observe failures. The token is also what lets a *non*-Compose
collector (a sidecar, a host agent) push without holding a client certificate.

---

## 5. Telemetry accepts OTLP and mirrors it

**Decision.** `POST /v1/traces` accepts OTLP/JSON, stores the spans for the
trace join, and forwards the original export to another collector (Jaeger) when
`TELEMETRY_FORWARD_OTLP_ENDPOINT` is set.

**Why.** Spans are needed twice: structurally, to join decisions to the flow
they happened inside, and visually, to browse in Jaeger. Asking each component
to export twice would drift. One ingest point, one copy stored, one copy
mirrored, is what a collector is for.

A mirror failure is deliberately **not** fatal: the audit copy has already been
written, so failing the request would only make the producer retry and
duplicate work. It is logged and counted instead.

**Cost.** A second dependency on the export path. It degrades to "the audit
trail is complete, Jaeger is missing spans", which is the right priority.

---

## 6. The dashboard is an embedded HTML page, not a Grafana dashboard

**Decision.** The audit dashboard is a single vanilla HTML file baked into the
binary with `go:embed`. Grafana is deployed too, but only as Loki's front end.

**Why.**

* The deliverable is "the audit dashboard". A Grafana dashboard is a JSON file,
  a provisioned datasource, a plugin version and a login — four things that can
  be wrong when a reviewer runs the mandated `docker compose up --build`.
  A page served by the service itself has no build step and no configuration.
* The questions are specific (blocked requests, unauthorized attempts, trace
  flows) and the API already answers them; wiring a generic tool to specific
  questions is more work than drawing them.
* Grafana remains available for what it is genuinely better at: reading the log
  store, which is why it is still in the compose file.

**The log views are provisioned as code, and that is the split.** "Grafana is for
logs, the service is for decisions" is only useful if the log views survive a
fresh clone, so `observability/grafana/provisioning/dashboards/` holds the
provider and the dashboard JSON, and a change to them is a reviewable diff rather
than something one person clicked. The two UIs therefore answer different
questions and are not meant to converge: Grafana shows the raw lines (including
the unstructured ones the audit trail deliberately ignores) and counts them from
Loki; `/dashboard` shows what was *decided*, from PostgreSQL, with the trace join.

**Cost.** Hand-written SVG and DOM code, and no alerting. Alerting is the
obvious next step and would be built on `/metrics` plus the read API.

---

## 7. The Docker socket, and where it is confined

**Decision.** Exactly two services read the Docker socket (`telemetry-collector`
and `promtail`), read-only, as a non-root user via `group_add`, with
`security_opt: label=disable` for SELinux hosts.

**Why.** Reading container stdout is what makes the "no component changes"
approach possible, and there is no less privileged way to do it from inside
Compose. The confinement is deliberate: read-only mount, one shared group
instead of root, an explicit label filter so it only reads this project's
containers, and a documented production alternative (a socket proxy that
allowlists the read-only container and log endpoints).

**Cost.** A container with Docker-socket access is a privileged container, and
in a project about zero trust that deserves to be stated plainly rather than
hidden. The mitigation is the socket proxy, and it is written down here and in
the compose comments rather than assumed.

---

## 8. `TELEMETRY_STORE=memory` exists, and is loud about it

**Decision.** The memory backend is selectable, logs a warning on startup, and
is explicitly not the default.

**Why.** A reviewer with no database access still has to be able to see the
deliverable work. The alternative — refusing to start without `DATABASE_URL`
and no escape hatch — makes the whole component look broken for an
environmental reason.

**Cost.** A store that silently loses the audit trail if it is used by mistake.
Mitigated by requiring an explicit opt-in, warning on every start, and saying so
in the compose file and the README.

---

## 9. Probe paths are not audit events

**Decision.** A bare `http_request` on `/healthz`, `/readyz`, `/livez`,
`/health`, `/metrics`, `/favicon.ico` or `/robots.txt` is classified as noise
and skipped. Attach a `decision`, `reason` or `action` and it is kept.

**Why.** A health probe is the platform talking to itself: no subject, no
resource, no adversary. Every service here probes on an interval, so one service
produces thousands of records a day. In a live run of this stack, **60 of the 62
events in a fifteen minute window were the IdP's own readiness probe** — the
audit trail was 97% scaffolding, and the denial rate the dashboard exists to
show was diluted by traffic that can never be denied.

**Cost.** A real denial on a probe path would be missed — but a probe answer of
401 on `/healthz` means the platform cannot reach itself, which belongs in Loki
and in the container's health status, not in a security record. The escape hatch
is deliberate: a producer that attaches a verdict is making a statement, and
statements are kept.

---

## 10. The collector is observable, and its readiness means something

**Decision.** `cmd/shipper` serves `/healthz`, `/readyz` and `/metrics` on 8089.
`/readyz` reports **not ready** until a container discovery has succeeded and
fails once the Docker API has been unreachable for three discovery intervals.

**Why.** An observability component that cannot be observed is a joke, but the
substance is the definition of ready. A collector whose socket mount is broken,
or whose SELinux label blocks it, is *running*, *healthy* and collecting
**nothing** — with the Docker healthcheck disabled and no readiness endpoint,
that failure is invisible until someone asks why the dashboard is empty. Here it
shows up as `unhealthy`, as `telemetry_collector_ready 0`, and as
`containers_followed 0`.

A failure to bind the port is logged as a warning and is **not** fatal: losing a
metrics port must never stop the audit trail.

**The counters are chosen so a stall is visible, not just a total.** `queued`
counts records accepted into the pipeline and is reported next to `shipped`,
`dropped` and `failed`, so "reading but not delivering" — the ingest API
refusing everything, a token that no longer matches — shows up as a growing gap
between two numbers rather than as the same steady `shipped 0` an idle stack
shows. A queue-full shed is counted separately from a batch that failed, because
one is audit data lost and the other is audit data not yet delivered. For the
same reason the collector's readiness reports *why* it is not ready, and
`queued == shipped` is the invariant to check after the flush interval settles.

**Cost.** One more port, and a readiness definition that has to be kept honest
(it was written after watching a live run, which is why it reports the container
count and the discovery age).

---

## 11. One normaliser for every transport

**Decision.** Structured stdout, explicit pushes, OTLP log records and OTLP
spans all land in the same event model, and an OTLP log record is flattened into
exactly the field map a JSON log line produces. The normaliser also accepts the
OpenTelemetry semantic conventions (`http.request.method`, `url.path`,
`http.response.status_code`, `client.address`, `enduser.id`) and the RPC
conventions (`rpc.service`, `rpc.method`, `grpc.code`).

**Why.** Person 6's job is to be the place every component's decision lands, so
the pipeline should not care *how* a decision arrived:

* The project's own contract is structured JSON, so that path needs nothing from
  anyone. But a service instrumented with an OTel SDK exports by default, and
  "point your exporter at telemetry" should be a complete integration rather
  than half of one.
* Parity is a correctness property, not a nicety: a string `body` of
  `access_decision` exported over OTLP was originally classified into ACCESS
  while the identical stdout line classified into AUTHZ. Same decision, two
  answers, depending on transport — the kind of divergence that makes a security
  record untrustworthy. There is now a test asserting the parity.
* The Policy Engine's ABAC envelope (`{"input":{…}}`) and OPA's decision log
  (`{"result":{…}}`) put the interesting fields one level down. A record that
  cannot be read is a decision that never appears, and the failure is silent.
* **The nesting is not always an object.** OTLP attributes are flat by
  definition, so the same envelope arrives as `input.subject.user_id`. Reading
  only the object form meant a policy decision stored with no subject, no roles
  and no client address — or, with no verdict field either, dropped and counted
  as chatter. The envelope is now rebuilt from its dotted form before anything
  reads it, and only the envelope: `http.request.method` and `rpc.service` are
  legitimately dotted and are never rewritten. Test:
  `TestFromMapReadsAFlattenedOTLPEnvelope` proves the nest, the flat and the
  dotted encodings produce the same decision.
* **A marshalled record inside `body` is a record, not prose.** An SDK whose
  producer logs a marshalled object puts the whole thing in `body`; read as
  text it had no field the classifier could use, so the decision was dropped
  silently (`TestDecodeLogsReadsARecordMarshalledIntoTheBody`).
* **Precedence is stated, not accidental.** When a record carries the client
  address both inside the envelope and as `client.address`, the envelope wins:
  that is the address the decision was evaluated against, so it is the one the
  verdict is about. Behind a proxy the two disagree, and recording the proxy
  would answer "who was denied?" wrongly.
* A gRPC service reports a gRPC status, not an HTTP one. Without the mapping,
  every call it serves would carry no status the classifier recognises — so
  `PERMISSION_DENIED` is mapped to 403 and becomes a DENY.

**Cost.** A tolerant field vocabulary (many aliases per fact) that has to stay
honest: each alias exists because a real producer uses it, and
`internal/audit/integration_test.go` names the producer next to the assertion so
a contract change breaks the test that says which integration to fix.

---

## 12. Clock skew is surfaced, not smoothed over

**Decision.** A record whose timestamp is more than five minutes ahead of the
pipeline's own clock is stored, counted
(`telemetry_events_future_dated_total`) and warned about by name — but every
read window still ends at *now*.

**Why.** A producer logging local time with a `Z` suffix, or with a wrong clock,
has every decision stored and **excluded from every dashboard window**. This was
found by doing exactly that while verifying this component, which is what makes
it worth a decision entry rather than a footnote: the failure is invisible from
both ends — the producer sees 200s, the dashboard sees nothing.

Two alternatives were rejected. Clamping or "fixing" the timestamp destroys the
producer's own evidence, and the raw payload is kept for forensics precisely
because it is what the producer actually said. Widening the window to tolerate
skew hides a configuration bug indefinitely and breaks the meaning of `window`
for everyone else. Counting it produces a number, a log line naming the service
and the delta, and a one-line check (`docs/integration.md`) — so a misconfigured
producer is diagnosable in seconds instead of being a mystery.

**Cost.** The problem is *reported* rather than prevented, which is only helpful
if someone reads `/metrics` or the logs. Acceptable because the same warning
appears in Loki with everything else, and because the fix belongs in the
producer.

---

## 13. The normaliser follows the *implemented* contract, not the aspirational one

**Decision.** The Policy Engine is read in the nested shape from
`docs/policymaker.md` — `input.subject.{user_id,roles}` and
`input.context.ip_address` — and OPA's own decision log is recognised as a
policy decision. `raw` keeps the payload in the shape its producer wrote.

**Why.** Once Person 3's engine landed on `main`, the contract stopped being a
guess: the engine evaluates `input.subject.roles`, and
`docs/division.md`'s flat example is *denied by default*. Had the normaliser kept
reading only the flat shape, every authorisation decision in this project would
have been stored as a row with **no subject, no roles and no client address** —
the three columns every question about a denial is answered from. A silently
impoverished audit trail is worse than a missing one, because it looks complete.

OPA's decision log is the other half: Person 3 has deferred
`--set decision_logs.console=true`, so today the engine's verdicts reach the
trail through its callers. Recognising the log means that when they flip the
flag, the engine's own verdicts — including the calls no caller logged — become
first-class events with no shim, no parser and no change on my side. That was
verified end to end against OPA 1.20.2 itself: `AUTHZ / PERMIT / policy_allowed`
and `AUTHZ / DENY / policy_denied`, each carrying its `decision_id`.

**Cost.** The field vocabulary grows another dialect, and it is the one field set
most likely to change as Persons 4 and 5 start sending real payloads. Mitigated
by naming the producer in the test (`integration_test.go`) so a contract drift
breaks the test that says which integration to fix, and by attributing a
recognised OPA record to `policy-engine` through the collector rather than
hardcoding a service name.

---

## 14. The Transport Contract is configuration, not a rewrite

**Decision.** The audit channel can run over mutual TLS 1.3 against the shared
CA (`TELEMETRY_TLS_*`), and by default it does not: with nothing configured the
API answers plain HTTP and authenticates collectors with the bearer token.

**Why.** docs/division.md §2 names TLS 1.3 with mutual certificate verification
as one of three interfaces everyone must adhere to from day one, and the
collector pushing into the ingest API *is* service-to-service traffic. But no
component in this repository serves TLS today — not the IdP, not the policy
engine, not Loki — and the shared CA is Person 2's deliverable. So there are two
bad options and one good one:

* Pretending the token is compliant. It is not, and the gap is exactly the kind
  of thing a reviewer is asked to catch (CONTRIBUTING.md §5: "are they enforcing
  mTLS?").
* Requiring TLS now. Nothing could talk to anything until the CA exists, so the
  mandated `docker compose up --build` would fail, which CONTRIBUTING.md §4
  treats as grounds to reject the change.
* **Making compliance a configuration change.** The code path exists, is tested
  against a real handshake, and turns on the moment certificates exist — without
  touching a deployment that has none.

Three sub-decisions were made deliberately and are asserted by tests, because a
security setting that is only 
expected to work is a setting that is not working:

* **TLS 1.3 is a floor.** A 1.2-only client is refused rather than negotiated
down to. A contract that names a version and then accepts less is decoration.
* **The CA is pinned rather than added to the system pool.** This is an internal
  channel; a certificate from a public authority is not a reason to trust the
  audit API. Same reasoning in the other direction: with a client certificate
  required, a valid token alone no longer reaches the ingest endpoint.
* **`verified-if-given` is the default with a CA but without the requirement**,
  so an upgrade mid-flight authenticates whoever has a certificate without
  shutting out whoever does not yet.

**Cost.** Four more variables and a code path that most deployments will not
exercise, which is a real maintenance surface: a bug in the TLS path would only
appear when somebody enables it. Mitigated by testing it rather than assuming it
— the round trip is exercised through the *real* ingest handler, including the
refusals, and `internal/certtest` mints the throwaway CA so the tests need no
fixtures (and no checked-in private key).
