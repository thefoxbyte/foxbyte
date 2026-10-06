// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

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

// ResolveBranch checks a branch name and defaults an empty one to main.
func ResolveBranch(name string) (string, error) { return ledgerBranchName(name) }

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
