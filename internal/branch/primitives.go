// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import "github.com/thefoxbyte/foxbyte/internal/ledger"

// The few primitives the paid edition needs from this package.
//
// Code under enterprise/ cannot reach an unexported helper, and the core must
// never import enterprise/ — the dependency only ever points inwards. So the
// handful of operations a paid feature genuinely needs are named here rather
// than exporting the internals one at a time as each move demands it.
//
// Deliberately small and deliberately boring: run some SQL on a branch, turn
// the guardrails off for a moment, quote an identifier. Anything a paid feature
// wants beyond this is a sign the split is in the wrong place.
//
// These are wrappers, not moves: the unexported originals are untouched and
// every existing caller still uses them, so nothing that works today changes.

// ExecSQL runs a statement on a branch's database.
func ExecSQL(target, sql string) error { return psqlExec(target, sql) }

// QuerySQL runs a statement on a branch and returns its output, unaligned and
// untitled (psql -tAc) — the counterpart to ExecSQL, for the paid features that
// ask the database a question rather than tell it something.
func QuerySQL(target, sql string) (string, error) {
	return capture("docker", "exec", container(target), "psql", "-U", pgUser, "-d", pgDatabase, "-tAc", sql)
}

// QuoteLiteral renders s as a SQL string literal.
func QuoteLiteral(s string) string { return sqlQuote(s) }

// LedgerQuery runs a query against a branch as the superuser and returns its
// non-empty output lines — one JSON document per row, for the ledger queries.
// Distinct from QuerySQL because the Blackbox tables are not readable by the
// client role, which is the point of them.
func LedgerQuery(name, sql string) ([]string, error) { return ledgerLines(name, sql) }

// LedgerRows reads a branch's Blackbox entries, optionally filtered. The paid
// features that compare two branches' records need them as rows rather than as
// the JSON LedgerQuery returns.
func LedgerRows(name string, withExt bool, where string) ([]ledger.Row, error) {
	return loadLedgerRows(name, withExt, where)
}

// CommonPrefix is how many leading entries two branch histories share, which is
// where they split. Shared rather than copied: `blackbox diff` and a change
// request ask the same question, and two answers to it would eventually
// disagree about where a branch forked.
func CommonPrefix(a, b []ledger.Row) int { return commonPrefix(a, b) }

// LedgerV2Tables reports which of the richer Blackbox tables a branch has.
func LedgerV2Tables(name string) (ext, checkpoints bool, err error) { return ledgerV2Tables(name) }

// TruthyEnv reads one of this engine's boolean environment variables.
func TruthyEnv(key string) bool { return truthyEnv(key) }

// QuoteLiteralOrNull renders an optional string as a SQL literal or NULL.
func QuoteLiteralOrNull(p *string) string { return sqlTextOrNull(p) }

// PolicyQuery runs a statement against a branch's policy tables and returns its
// output lines, with the policy gate's own errors made readable.
func PolicyQuery(name, sql string) ([]string, error) { return policyLines(name, sql) }

// ResolveBranch checks a branch name and defaults an empty one to main.
func ResolveBranch(name string) (string, error) { return ledgerBranchName(name) }

// ExecScript runs a multi-statement SQL script on a branch over stdin, aborting
// at the first error. Applying a change request is several statements that must
// stand or fall together, which ExecSQL's one statement at a time cannot do.
func ExecScript(target, sql string) error { return psqlStdin(target, sql) }

// SetGuard enables or disables the Blackbox guardrail event trigger on a
// branch. A pipeline turns it off while it rebuilds its own tables, because the
// guardrails exist to stop a person dropping something by accident, not to stop
// a pipeline doing the thing it was asked to do.
func SetGuard(target string, enabled bool) { setGuard(target, enabled) }

// QuoteIdent renders a name as a Postgres identifier, preserving its case.
func QuoteIdent(s string) string { return sqlIdent(s) }

// Report announces progress through a long operation. Progress.Step is a field
// rather than a method, so this is the exported, nil-safe way to call it from
// outside the package — the same thing the unexported step does for the code in
// here.
func (p *Progress) Report(done, total int, label string) { p.step(done, total, label) }
