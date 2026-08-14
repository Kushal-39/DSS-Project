// Package migrations embeds the SQL schema migrations and the seed script
// into the binary so the container can run them at startup without needing
// the source tree or external migration tooling.
//
// golang-migrate only parses files matching NN_migration.up.sql /
// NN_migration.down.sql, so seed.sql is ignored by the migration engine and
// executed separately by the "seed" subcommand.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
