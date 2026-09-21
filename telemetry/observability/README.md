# Observability backends

Configuration for the third-party backends Person 6 deploys alongside the
telemetry service. The service itself (`cmd/telemetry`, `cmd/shipper`) is the
part that had to be built; these are wiring.

| Path | Backend | Role |
| --- | --- | --- |
| `loki/loki-config.yml` | Grafana Loki | Central log store. Receives every container's stdout. |
| `promtail/promtail-config.yml` | Grafana Promtail | Ships container stdout to Loki (Docker service discovery). |
| `grafana/provisioning/datasources/loki.yml` | Grafana | Datasource provisioning so Loki is queryable on first boot. |
| `grafana/provisioning/dashboards/` | Grafana | The log dashboards, as code: `dashboards.yml` is the provider and `dashboards/json/zt-logs.json` is the dashboard itself. |

## Two paths, on purpose

The same stdout is consumed twice, by design:

**Everything → Loki.** Promtail follows every container *in this Compose
project* (docker_sd plus a `keep` rule on `com.docker.compose.project`, so it
never hoovers up whatever else a developer is running) and pushes to Loki. This
is where you grep raw request lines, stack traces and anything that was not
structured JSON. If you override `COMPOSE_PROJECT_NAME`, update the regex in
`promtail/promtail-config.yml` and `TELEMETRY_SHIP_PROJECT` together, so both
paths still cover exactly the same containers.

**Decisions → the audit trail.** `cmd/shipper` follows the same containers,
keeps only the structured records that carry a security signal, tags each one
with the service it came from, and posts them to
`POST /v1/audit/logs` on the telemetry service. Those records land in the
`audit_events` table with a PERMIT/DENY/ERROR/INFO verdict, which is what the
dashboard's counters and the trace join are built from.

Splitting them matters. A log store answers "what did this container print?";
an audit trail answers "what did the system decide, and can I prove it later?".
The audit trail must not be a copy of the log stream — it has to survive
retention windows, avoid unbounded cardinality, and stay queryable for
decisions specifically. Keeping both means neither has to compromise.

Jaeger is the fourth backend, configured entirely through its own image
environment (see `docker-compose.yml`): the telemetry service receives OTLP
spans, stores the copy the trace join needs, and mirrors the export onward to
Jaeger so spans remain browsable visually.

## The log dashboard is committed, not clicked together

Grafana's dashboard is provisioned from
`grafana/provisioning/dashboards/json/zt-logs.json`, so "deploy centralized log
ingestion" means every machine gets the same views, and a change to them is a
reviewable diff. It answers, from the logs:

| Panel | Question |
| --- | --- |
| Log lines, Errors, Warnings, Security decisions in the logs | How much is happening, and how much of it is going wrong, right now? |
| Log volume by service / Errors and warnings by service | Which component is talking, which has gone quiet, and where the spikes are. |
| Blocked and refused, as the components logged them | Refused logins (`outcome=denied`) and rejected requests (4xx/5xx), from the producers' own words. |
| Refused and rejected — log lines, Live logs | The raw lines behind the counts, with the `TraceID` link that opens the flow in Jaeger. |

Two deliberate limits. It is **not** the audit UI: permits, denials and trace
joins are counted in PostgreSQL by the telemetry service and rendered at
`/dashboard`, because a log store is not an audit trail (see the section below).
And the counting panels use `or vector(0)`, so a quiet window reads `0` rather
than "No data" — "nothing happened" and "the query is broken" must not look the
same.

The separate `service` variable filters every panel at once; `All` is the
default because the first question about a distributed system is usually
"what is everyone doing", not "what is the IdP doing".

## Retention, and why the two stores differ

| Store | Kept for | Enforced by |
| --- | --- | --- |
| Loki (everything every container printed) | 7 days (`retention_period: 168h`) | Loki's compactor, which must be enabled for the retention to mean anything |
| PostgreSQL audit trail (decisions only) | 30 days by default (`TELEMETRY_RETENTION`) | the telemetry service's own purge on an interval (`TELEMETRY_RETENTION_INTERVAL`) |

A debug log and a security record have different lifetimes, and the shorter one
belongs to the log store. Both are bounded: an unbounded log store is a disk
incident, and an unbounded audit trail is a liability.

Loki's retention is silent by design (the compactor deletes chunks), so the
evidence that it is on is the configuration plus `retention_enabled: true` on the
compactor — without that second setting, `retention_period` does nothing. The
audit trail's purge is the opposite: each sweep that removes something logs
`purge_complete` with `removed_events` and `removed_spans` reported separately,
because "the audit trail shrank" and "which half of it shrank" are different
questions.

## Ports

| Service | Port | URL |
| --- | --- | --- |
| Telemetry ingest + read API | 8088 | http://localhost:8088/dashboard |
| Jaeger UI | 16686 | http://localhost:16686 |
| Loki API | 3100 | http://localhost:3100/ready |
| Grafana | 3300 | http://localhost:3300 |

Grafana's dashboard is at http://localhost:3300/d/zt-logs (folder *Zero-Trust*).
Grafana's anonymous admin access is enabled for local development only
(`GF_AUTH_ANONYMOUS_ENABLED`) — it is a convenience for a reviewer, not a
production setting, and the compose file says so where it is set.
