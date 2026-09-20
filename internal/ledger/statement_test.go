// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"regexp"
	"strings"
	"testing"
)

// Rules and risk flags judge the statement that runs, not everything a client
// sent with it. What makes that safe lives in SQL; these pin the parts a later
// edit could quietly undo. The behaviour itself is exercised by integration-v2 §6b.
func TestSchemaStatementMatching(t *testing.T) {
	ledgerSQL, policySQL := lf(Schema), lf(SchemaPolicy)

	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION bb._sql_statements(q text)",
		"CREATE OR REPLACE FUNCTION bb._statement_texts(p_event text, p_tag text, p_ctx text)",
		"CREATE UNLOGGED TABLE IF NOT EXISTS bb.statement_cursor",
		"REVOKE ALL ON bb.statement_cursor FROM PUBLIC;",
		"t := bb._statement_texts('end', TG_TAG, ctx);",
		// the guardrail's error is a public contract (docs/policy-errors.md)
		"'guardrail: % is blocked by policy (set bb.allow_destructive=on to override)'",
	} {
		if !strings.Contains(ledgerSQL, want) {
			t.Errorf("ledger.sql is missing %q", want)
		}
	}

	// A client that could call the position function could line a blocked statement
	// up with a harmless one's text. The revoke must come after the blanket grant.
	grant := strings.Index(ledgerSQL, "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA bb TO db_client;")
	revoke := strings.Index(ledgerSQL, "REVOKE EXECUTE ON FUNCTION bb._statement_texts(text, text, text) FROM PUBLIC, db_client;")
	if grant < 0 || revoke < 0 || revoke < grant {
		t.Errorf("_statement_texts must be revoked from clients after the blanket grant (grant at %d, revoke at %d)", grant, revoke)
	}
	if regexp.MustCompile(`(?i)grant[^;]*bb\.statement_cursor[^;]*to`).MatchString(ledgerSQL + policySQL) {
		t.Error("clients must not be granted anything on bb.statement_cursor")
	}

	// Risk flags and rules no longer match the raw query directly.
	if regexp.MustCompile(`\bq ~\*`).MatchString(ledgerSQL) {
		t.Error("ledger.sql matches a risk pattern against the whole query (q ~*) instead of the statement texts")
	}
	if strings.Contains(policySQL, "q ~* pattern") || !strings.Contains(policySQL, "texts := bb._statement_texts('start', TG_TAG, ctx);") {
		t.Error("the policy gate must match rules against bb._statement_texts, not the whole query")
	}
	if !strings.Contains(policySQL, "unnest(bb._statement_candidates(statement, command))") {
		t.Error("the policy preview must match the way the gate does")
	}

	// A blocked attempt is written through dblink; if this transaction already holds
	// the Blackbox append lock that write waits for us forever. Both writers check.
	for name, sql := range map[string]string{"ledger.sql (guardrail)": ledgerSQL, "policy.sql (gate)": policySQL} {
		lock := strings.Index(sql, "IF bb._holds_chain_lock() THEN")
		write := strings.Index(sql, "INSERT INTO bb.schema_ledger")
		if lock < 0 || write < 0 {
			t.Errorf("%s: lock check at %d, BLOCKED write at %d", name, lock, write)
			continue
		}
		// the check has to guard the dblink write, so it comes first
		if blocked := strings.Index(sql[lock:], "'BLOCKED','policy'"); blocked < 0 {
			t.Errorf("%s: no BLOCKED write follows the lock check", name)
		}
	}

	// flag is an action that does something now, and typos are refused.
	for _, want := range []string{"action = 'flag'", "CHECK (action IN ('block','flag','allow')) NOT VALID", "CREATE TABLE IF NOT EXISTS bb.policy_history"} {
		if !strings.Contains(ledgerSQL, want) {
			t.Errorf("ledger.sql is missing %q", want)
		}
	}
}
