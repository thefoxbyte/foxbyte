// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import _ "embed"

// SchemaExt is the idempotent SQL for the Blackbox 2.0 capture table
// (bb.ledger_ext): xid/lsn, agent provenance and the destructive-DDL override,
// keyed by ledger row id. Apply it after Schema, with a superuser connection to
// the target branch. It never alters an object Schema owns, so existing ledgers
// and hash chains are untouched.
//
// Standard, deliberately: this is richer *recording*, and SchemaCheckpoints
// below is *proof*. The split between them is where the editions divide.
//
//go:embed ledger_ext.sql
var SchemaExt string

// SchemaData guards and records data changes the event triggers cannot see:
// TRUNCATE, and agents' UPDATE and DELETE (audit v2 G04). Apply it after the
// other schemas; it adds triggers to every user table, and to each new one.
//
//go:embed datachanges.sql
var SchemaData string
