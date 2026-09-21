module telemetry

go 1.23.0

// Same database stack as the IdP (Person 1): pgx for queries, golang-migrate
// for the schema. Everything else — OTLP parsing, the Docker log tailer, the
// audit dashboard, mTLS — is standard library only.
require (
	github.com/golang-migrate/migrate/v4 v4.18.3
	github.com/jackc/pgx/v5 v5.7.4
)

require (
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/lib/pq v1.10.9 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/text v0.23.0 // indirect
)
