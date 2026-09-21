# Observability backends

Configuration for the third-party backends Person 6 deploys alongside the
telemetry service. The service itself (`cmd/telemetry`, `cmd/shipper`) is the
part that had to be built; these are wiring.

| Path | Backend | Role |
| --- | --- | --- |
| `loki/loki-config.yml` | Grafana Loki | Central log store. Receives every container's stdout. |
| `promtail/promtail-config.yml` | Grafana Promtail | Ships container stdout to Loki (Docker service discovery). |
| `grafana/provisioning/…` | Grafana | Datasource provisioning so Loki is queryable on first boot. |

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

## Ports

| Service | Port | URL |
| --- | --- | --- |
| Telemetry ingest + read API | 8088 | http://localhost:8088/dashboard |
| Jaeger UI | 16686 | http://localhost:16686 |
| Loki API | 3100 | http://localhost:3100/ready |
| Grafana | 3300 | http://localhost:3300 |

Grafana's anonymous admin access is enabled for local development only
(`GF_AUTH_ANONYMOUS_ENABLED`) — it is a convenience for a reviewer, not a
production setting, and the compose file says so where it is set.
