#!/bin/sh
# Payment & Transaction Service container entrypoint.
#
# Mandated lifecycle (docs/database.md §4): migrations run automatically at
# container start, against DATABASE_URL, BEFORE the web server boots.
#
#   1. migrate up — apply the ledger migrations (idempotent)
#   2. exec serve — hand PID 1 to the server for correct signal handling
#
# `set -e` + `set -u`: any missing or invalid required environment variable
# aborts the container immediately with a clear error (fail fast). This service
# refuses to start without its mTLS material rather than serving financial
# endpoints in cleartext, so a missing certificate is a startup failure by
# design — the message says which variable is missing.
set -eu

echo "[payment-service] entrypoint: starting (pid $$)"

echo "[payment-service] step 1/2: applying ledger migrations..."
/app/payment-server migrate up

echo "[payment-service] step 2/2: starting the mTLS API on :8081..."
exec /app/payment-server serve
