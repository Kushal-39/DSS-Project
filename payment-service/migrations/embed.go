// Package migrations embeds the SQL schema migrations into the binary, so the
// container applies them at startup without the source tree or any external
// migration tooling (docs/database.md §4).
//
// golang-migrate only recognises NN_name.up.sql / NN_name.down.sql, so any
// non-migration SQL placed here would simply be ignored.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
