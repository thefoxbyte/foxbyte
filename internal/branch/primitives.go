// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

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

// ExecSQLAs is ExecSQL on behalf of a. For an ordinary account the SQL runs as
// that account's own role with psql's backslash commands off (see As); for the
// operator it is ExecSQL.
func ExecSQLAs(target, sql string, a As) error {
	if !a.confined() {
		return ExecSQL(target, sql)
	}
	return pipeInto(target, a.restricted(strings.NewReader(sql+"\n")),
		"psql", "-q", "-U", a.Account, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1")
}

// QuerySQLAs is QuerySQL on behalf of a, as ExecSQLAs is to ExecSQL. On failure
// the output is psql's error.
func QuerySQLAs(target, sql string, a As) (string, error) {
	if !a.confined() {
		return QuerySQL(target, sql)
	}
	cmd := execSudo("docker", "exec", "-i", "-e", pgImportOptions, container(target),
		"psql", "-q", "-U", a.Account, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1", "-tA")
	cmd.Stdin = a.restricted(strings.NewReader(sql + "\n"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return strings.TrimSpace(stderr.String()), err
	}
	return strings.TrimSpace(string(out)), nil
}

// EnsureDblink puts the Blackbox's dblink back on a branch where its triggers
// look for it. A pipeline's staging step renames public, and dblink with it.
func EnsureDblink(target string) error { return ensureDblink(target) }

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

// OpenSuper connects to the branch's database as the superuser, over pgx. For
// a paid feature that must read every table whatever its grants and policies
// say (a personal-data scan) and needs values as values: psql's text output
// cannot carry a tab or a newline inside one.
func OpenSuper(ctx context.Context, name string) (*pgx.Conn, error) {
	return stateConn(ctx, container(ServingBranch(name)), pgDatabase)
}

// OpenAs connects to the branch's database as account's own login role, the
// role the console and the gateway log that person in as: a member of
// db_client, so grants and row-level security apply to it as they would to any
// query of theirs. "" is the operator at the machine, who gets the superuser.
// For a paid feature that must show a person only what they could read anyway
// (a reviewer's masked samples).
func OpenAs(ctx context.Context, name, account string) (*pgx.Conn, error) {
	if account == "" {
		return OpenSuper(ctx, name)
	}
	target := ServingBranch(name)
	if err := EnsureUserRole(target, account); err != nil {
		return nil, fmt.Errorf("preparing %s's role on %s: %w", account, name, err)
	}
	ip, err := containerIP(container(target))
	if err != nil {
		return nil, fmt.Errorf("finding %s: %w", name, err)
	}
	cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://%s:5432/%s", ip, pgDatabase))
	if err != nil {
		return nil, err
	}
	cfg.User, cfg.Password = account, UserRolePassword(account)
	return pgx.ConnectConfig(ctx, cfg)
}

// QuoteIdent renders a name as a Postgres identifier, preserving its case.
func QuoteIdent(s string) string { return sqlIdent(s) }

// Report announces progress through a long operation. Progress.Step is a field
// rather than a method, so this is the exported, nil-safe way to call it from
// outside the package — the same thing the unexported step does for the code in
// here.
func (p *Progress) Report(done, total int, label string) { p.step(done, total, label) }
