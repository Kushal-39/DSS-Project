#!/bin/sh
# Account Service container entrypoint.
#
# Mandated lifecycle (docs/database.md §4):
# Migrations run automatically on startup before accepting incoming traffic.
#
# `set -eu`: fail immediately if any command or variable fails.
set -eu

echo "[account-service] entrypoint: starting (pid $$)"

# In container runtime, uvicorn runs the FastAPI application.
# Database connection and schema migrations are automatically executed
# in the application lifespan startup handler.
echo "[account-service] starting web server on port ${PORT:-8082}..."
exec python -m src.main
