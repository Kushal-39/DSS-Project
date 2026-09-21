#!/bin/sh
# Telemetry container entrypoint.
#
# Mandated lifecycle (docs/database.md §4): migrations run automatically at
# container start, against DATABASE_URL, BEFORE the web server boots.
#
#   1. migrate   — apply pending audit schema migrations (idempotent)
#   2. exec serve — hand PID 1 to the server for correct signal handling
#
# `set -e` + `set -u`: any missing or invalid required environment variable
# aborts the container immediately with a clear error (fail fast). This service
# deliberately refuses to start rather than run with a broken configuration —
# a telemetry service that half-works produces a silently incomplete audit
# trail, which is worse than an obvious crash.
set -eu

echo "[telemetry] entrypoint: starting (pid $$)"

echo "[telemetry] step 1/2: applying audit schema migrations..."
/app/telemetry migrate

echo "[telemetry] step 2/2: starting the ingest API and audit dashboard..."
exec /app/telemetry serve
