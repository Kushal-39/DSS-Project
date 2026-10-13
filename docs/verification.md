# Integrated verification — 2026-10-14

The final run of `scripts/test-all.sh` passed with the normal deployment running
simultaneously. The test project uses separate loopback ports and a disposable
PostgreSQL container; destructive SQL and balance-changing tests never target
the configured Supabase database.

| Suite | Result |
| --- | --- |
| IdP Go tests/subtests, including real migration/seed/rollback tests | 26 passed, no skips |
| Payment Go tests/subtests, including real immutable ledger tests | 139 passed, no skips |
| Telemetry Go tests/subtests, including real store and migration tests | 218 passed, no skips |
| Go race detector and `go vet` | Passed for every Go module |
| OPA policy tests and strict compilation | 22 passed |
| Python account, transport, JWT cache, and gateway regressions | 31 passed |
| Live end-to-end tests | 33 passed |
| Docker images and configured deployment | Built; all readiness checks passed |

The live suite verified successful exact-cent deductions and ledger inserts,
canonical and alias payment routes, private account reads, invalid amounts,
forged/missing/expired/wrong-issuer/wrong-audience tokens, sender ownership,
policy thresholds, inactive/insufficient accounts, TLS 1.2 and missing-client
certificate refusals, restricted probe identities, isolated runtime keys,
transport-refusal auditing, concurrent balance exhaustion, dependency outages
and recovery, append-only ledger enforcement, restart persistence, global
rate-limit recovery, and live logs/spans/audit joins through Loki and Jaeger.

The concurrency assertion was exact: twenty simultaneous requests for ten
units against a balance of one hundred produced ten successes, ten refusals,
a zero balance, and exactly ten new ledger rows. A separate regression keeps
a stalled TLS peer open while a valid client connects, proving a refused or
stalled handshake cannot serialize subsequent payment traffic.

The normal `docker compose up --build -d --wait` deployment was also checked
against the configured database: gateway readiness 200, login 200,
authenticated account read 200, unauthenticated business request 401, and
telemetry/collector/Grafana/Jaeger readiness APIs 200. No successful financial
transfer was sent to that database during this deployment check.

Machine-readable Go results and JUnit reports are in ignored `test-results/`.
`test-results/summary.txt` contains the latest aggregate. The financial protocol
limits described in the root README remain part of the supplied contract:
receiver credit is unspecified, and a successful debit followed by a failed
ledger append requires reconciliation.
