// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"regexp"
	"strings"
	"testing"
)

// sqlFunction returns one function's definition, from its CREATE to the end
// of its body.
func sqlFunction(t *testing.T, src, name string) string {
	t.Helper()
	i := strings.Index(src, "CREATE OR REPLACE FUNCTION "+name+"(")
	if i < 0 {
		t.Fatalf("%s is gone", name)
	}
	body := src[i:]
	return body[:strings.Index(body, "\n$$;")]
}

// An entry's statement holds the values a change wrote, so no client may read
// the column (audit PRIV-3): every other column is granted one by one, and the
// table-wide grant is taken back on every start, so an existing install loses
// it too. Before the event triggers go on, or every start records the change.
func TestClientsCannotReadStatementText(t *testing.T) {
	if regexp.MustCompile(`GRANT SELECT ON [^;]*bb\.schema_ledger`).MatchString(Schema) {
		t.Error("ledger.sql grants SELECT on the whole of bb.schema_ledger again")
	}
	revoke := strings.Index(Schema, "REVOKE SELECT ON bb.schema_ledger FROM PUBLIC, db_client;")
	grant := regexp.MustCompile(`GRANT SELECT \(([^)]*)\)\s+ON bb\.schema_ledger TO db_client;`).FindStringSubmatchIndex(Schema)
	if revoke < 0 || grant == nil {
		t.Fatal("ledger.sql no longer revokes the table and grants its columns")
	}
	if revoke > grant[0] {
		t.Error("the columns are granted before the table-wide grant is revoked, which would take them back")
	}
	on := strings.Index(Schema, "CREATE EVENT TRIGGER bb_guard_start")
	if grant[0] > on {
		t.Error("the column grants come after the event triggers are on")
	}
	cols := map[string]bool{}
	for _, c := range strings.Split(Schema[grant[2]:grant[3]], ",") {
		cols[strings.TrimSpace(c)] = true
	}
	if cols["statement"] {
		t.Error("the statement column is granted to db_client")
	}
	// What existing readers select: the console, the entries list, the chain.
	for _, c := range []string{"id", "at", "actor", "actor_kind", "tool", "session", "branch",
		"command_tag", "object_type", "object_identity", "status", "risk", "prev_hash", "row_hash"} {
		if !cols[c] {
			t.Errorf("column %s is no longer granted to db_client", c)
		}
	}
}

// The text is still there for whoever may read it, through functions that run
// as the owner and check the caller themselves. Both must be on the list the
// sealing event trigger reads, or the next start takes EXECUTE back.
func TestStatementTextThroughDefinerFunctions(t *testing.T) {
	allowed := allowedCallable(t)
	for _, f := range []string{"ledger_statement", "ledger_verify"} {
		if !allowed[f] {
			t.Errorf("bb.%s is not on the client-callable list, so it would be sealed", f)
		}
	}
	fn := sqlFunction(t, Schema, "bb.ledger_statement")
	for _, want := range []string{
		"SECURITY DEFINER SET search_path = pg_catalog",
		// Admins: the same test as the guardrail override.
		"bb._may_override()",
		// Their own: the login role, which a session cannot change, and never
		// a shared role, whose actor is only what the session said.
		"session_user NOT IN ('dbadmin', 'db_client', 'db_agent') AND l.actor = session_user",
	} {
		if !strings.Contains(fn, want) {
			t.Errorf("bb.ledger_statement no longer contains %q", want)
		}
	}
	if strings.Contains(fn, "current_user") {
		t.Error("bb.ledger_statement reads current_user, which is the owner inside a SECURITY DEFINER function")
	}
	if !strings.Contains(Schema, "REVOKE ALL ON FUNCTION bb.ledger_statement(bigint) FROM PUBLIC;") {
		t.Error("bb.ledger_statement is callable by PUBLIC")
	}
	// Verification hashes the whole row, text included, as the owner.
	v := sqlFunction(t, Schema, "bb.ledger_verify")
	if !strings.Contains(v, "SECURITY DEFINER") || !strings.Contains(v, "bb._ledger_hash(s.*)") {
		t.Error("bb.ledger_verify no longer recomputes the hash as the owner")
	}
	// Made before the sweep that grants listed functions to db_client.
	if strings.Index(Schema, "FUNCTION bb.ledger_verify(") > strings.Index(Schema, "DO $seal$") {
		t.Error("the statement functions are made after the sweep that grants them")
	}
}

// An agent's transactions on one table take turns with its budget (audit
// TX-8): spending is visible only after commit, so K open transactions each
// had a whole budget. The behaviour is proved against Postgres; this guards
// what it rests on.
func TestBudgetTurnForAgentsOnly(t *testing.T) {
	turn := sqlFunction(t, SchemaData, "bb._budget_turn")
	// Two int keys: the Blackbox's other advisory locks take one bigint key,
	// a space Postgres keeps apart, so this cannot be taken for the append lock.
	if !strings.Contains(turn, "pg_advisory_xact_lock(hashtext('bb.dml_budget'), hashtext(akey || '/' || root::text))") {
		t.Error("the budget turn is no longer a two-key transaction lock on (agent, table)")
	}
	for _, want := range []string{
		// A wait past lock_timeout ends in a refusal that says why.
		"EXCEPTION WHEN lock_not_available THEN",
		"so that its row budget is not spent twice",
		"ERRCODE = 'lock_not_available'",
		// A snapshot older than the wait is caught by a row every turn
		// touches.
		"ON CONFLICT (actor, rel) DO UPDATE SET at = EXCLUDED.at",
	} {
		if !strings.Contains(turn, want) {
			t.Errorf("bb._budget_turn no longer contains %q", want)
		}
	}
	// Whatever this transaction's isolation: the one before it may have been
	// READ COMMITTED, and must have left its mark on the row all the same.
	if strings.Contains(turn, "transaction_isolation") {
		t.Error("the budget turn's row is touched only at some isolation levels")
	}

	// Taken in bb.guard_impact only where a budget applies, which is inside
	// the agents-only branch, and before the total is read.
	g := sqlFunction(t, SchemaData, "bb.guard_impact")
	agents := strings.Index(g, "IF c.actor_kind = 'agent' AND bb._guard_on() THEN")
	override := strings.Index(g, "IF NOT (allow IN ('on','true','1') AND bb._may_override()) THEN")
	budget := strings.Index(g, "IF b.max_rows IS NOT NULL THEN")
	call := strings.Index(g, "PERFORM bb._budget_turn(akey, root);")
	read := strings.Index(g, "SELECT coalesce(sum(s.n), 0) INTO spent FROM bb.dml_spent s")
	if agents < 0 || override < 0 || budget < 0 || call < 0 || read < 0 {
		t.Fatalf("bb.guard_impact changed shape (agents %d, override %d, budget %d, turn %d, read %d)", agents, override, budget, call, read)
	}
	if !(agents < override && override < budget && budget < call && call < read) {
		t.Error("the budget turn must be taken for a budgeted agent only, and before the total is read")
	}
	if strings.Count(SchemaData, "bb._budget_turn(") != 2 { // its definition and the one call
		t.Error("the budget turn is taken somewhere other than bb.guard_impact's budget branch")
	}
	// No lock is taken anywhere else in the file, people's writes included.
	if n := strings.Count(SchemaData, "pg_advisory_xact_lock("); n != 1 {
		t.Errorf("datachanges.sql takes %d advisory locks, want the one budget turn", n)
	}
}
