#!/bin/sh
# IdP container entrypoint.
#
# Mandated lifecycle (docs/database.md §4): migrations run automatically at
# container start, against DATABASE_URL, BEFORE the web server boots.
#
#   1. migrate — apply pending schema migrations (idempotent)
#   2. seed    — insert bootstrap users (idempotent)
#   3. exec serve — hand PID 1 to the server for correct signal handling
#
# `set -e` + `set -u`: any missing/invalid required environment variable
# aborts the container immediately with a clear error (fail fast).
set -eu

echo "[idp] entrypoint: starting (pid $$)"

echo "[idp] step 1/3: running database migrations..."
/app/idp-server migrate

echo "[idp] step 2/3: seeding bootstrap users..."
/app/idp-server seed

echo "[idp] step 3/3: starting web server..."
exec /app/idp-server serve
