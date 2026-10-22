// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ledger holds the FoxByte Blackbox — the RECORD layer. It is a
// set of PostgreSQL event triggers + tables, installed into the primary and
// inherited by every copy-on-write branch, that capture, attribute, and enforce
// policy on every schema change (DDL) the database sees.
package ledger

import _ "embed"

// Schema is the idempotent SQL that installs (or upgrades) the ledger into a
// database. Apply it with a superuser connection to the target branch.
//
// SchemaName is the schema every Blackbox object lives in. Brand-free: it is
// written into each database, and renaming it would hide the history.
// TestSchemaNameMatchesSQL keeps it in step with ledger.sql.
const SchemaName = "bb"

// PrivateSchemaName holds what no client may reach: application identity's
// install secret and the function that makes its MACs (identity.sql). A schema
// of its own because ledger.sql grants db_client EXECUTE on everything in
// SchemaName. Like SchemaName it is the engine's, never a user's: everything
// that lists, counts, guards or tracks a user's tables leaves both out.
const PrivateSchemaName = "bb_f1"

//go:embed ledger.sql
var Schema string
