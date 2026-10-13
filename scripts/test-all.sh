#!/usr/bin/env bash
# Build the disposable stack and run every suite, including real SQL tests.
set -euo pipefail
cd "$(dirname "$0")/.."
export DSS_TEST_DATABASE_PORT="${DSS_TEST_DATABASE_PORT:-55432}"
export TELEMETRY_DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"
compose=(docker compose -p dss-e2e -f docker-compose.yml -f compose.test.yml)
mkdir -p test-results
python3 -m venv .venv-test
.venv-test/bin/pip install -r account-service/requirements.txt -r tests/requirements.txt
"${compose[@]}" up --build -d --wait --wait-timeout 180
for name in idp_checks payment_checks telemetry_checks; do
    exists=$("${compose[@]}" exec -T postgres psql -U postgres -Atc "SELECT 1 FROM pg_database WHERE datname='$name'")
    if [[ "$exists" != 1 ]]; then
        "${compose[@]}" exec -T postgres createdb -U postgres "$name"
    fi
done
export IDP_TEST_DATABASE_URL="postgres://postgres:dss-test@localhost:${DSS_TEST_DATABASE_PORT}/idp_checks?sslmode=disable"
export PAYMENT_TEST_DATABASE_URL="postgres://postgres:dss-test@localhost:${DSS_TEST_DATABASE_PORT}/payment_checks?sslmode=disable"
export TELEMETRY_TEST_DATABASE_URL="postgres://postgres:dss-test@localhost:${DSS_TEST_DATABASE_PORT}/telemetry_checks?sslmode=disable"
export TELEMETRY_TEST_DESTRUCTIVE=1
for service in idp payment-service telemetry; do
    (cd "$service" && go test -race -count=1 -json ./... && go vet ./...) > "test-results/$service.jsonl"
done
"${compose[@]}" exec -T policy-engine opa test -v /policies | tee test-results/policy.txt
"${compose[@]}" exec -T policy-engine opa check --strict /policies
export PYTHONPATH="$PWD:$PWD/account-service"
export ENVIRONMENT=test
.venv-test/bin/python -m pytest account-service/tests tests/test_security.py tests/test_gateway.py --junitxml=test-results/python.xml
DSS_E2E=1 .venv-test/bin/python -m pytest tests/test_e2e.py -v --tb=short --junitxml=test-results/e2e.xml
"${compose[@]}" ps
