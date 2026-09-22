// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import _ "embed"

// SchemaV2 is the idempotent SQL for the Blackbox 2.0 additions. Apply it
// after Schema, with a superuser connection to the target branch. It never
// alters an object Schema owns, so existing ledgers and hash chains are untouched.
//
//go:embed ledger_v2.sql
var SchemaV2 string

// SchemaData guards and records data changes the event triggers cannot see:
// TRUNCATE, and agents' UPDATE and DELETE (audit v2 G04). Apply it after the
// other schemas; it adds triggers to every user table, and to each new one.
//
//go:embed datachanges.sql
var SchemaData string
