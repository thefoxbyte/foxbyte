// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"strings"
	"testing"
)

// A blocked attempt is recorded through a second connection, and a wait there
// is invisible to Postgres' deadlock detector: another transaction holding the
// append lock used to hang the refused client. Every path goes through the one
// connection that carries timeouts, and failing to record stays a WARNING.
func TestBlockedRecordConnectionCarriesTimeouts(t *testing.T) {
	if !strings.Contains(Schema, `options='-c lock_timeout=2s -c statement_timeout=5s'`) {
		t.Error("the blocked-attempt connection lost its timeouts")
	}
	if !strings.Contains(Schema, "'host=/var/run/postgresql dbname='") {
		t.Error("the blocked-attempt connection no longer uses the Unix socket")
	}
	i := strings.Index(Schema, "CREATE OR REPLACE FUNCTION bb._record_blocked(stmt text)")
	if i < 0 {
		t.Fatal("bb._record_blocked is gone")
	}
	body := Schema[i:]
	body = body[:strings.Index(body, "$$;")]
	if !strings.Contains(body, "EXCEPTION WHEN OTHERS THEN\n  RAISE WARNING") {
		t.Error("a failure to record a blocked attempt must be a WARNING, so the refusal still happens")
	}
	if strings.Contains(body, "SECURITY DEFINER") {
		t.Error("bb._record_blocked must not run as its owner: a client could write entries through it")
	}

	// Nothing talks to dblink except the helpers.
	for what, sql := range map[string]string{"ledger.sql": Schema, "datachanges.sql": SchemaData} {
		if n := strings.Count(sql, "PERFORM dblink_exec("); (what == "ledger.sql" && n != 1) || (what != "ledger.sql" && n != 0) {
			t.Errorf("%s has %d direct dblink_exec call(s); the blocked path belongs in bb._record_blocked", what, n)
		}
	}
	if n := strings.Count(SchemaData, "PERFORM bb._record_blocked(format("); n != 3 {
		t.Errorf("datachanges.sql records %d blocked paths through the helper, want 3 (TRUNCATE, unqualified DML, impact)", n)
	}
}

// The defaults for client logins, and that an administrator's choice survives
// the re-run on every start.
func TestClientRolesGetTimeoutDefaults(t *testing.T) {
	for _, want := range []string{
		"ARRAY['lock_timeout=60s', 'idle_in_transaction_session_timeout=10min']",
		"WHERE d.setrole = r.oid AND d.setdatabase = 0",
		"pg_has_role(oid, 'db_client', 'MEMBER')",
	} {
		if !strings.Contains(Schema, want) {
			t.Errorf("ledger.sql no longer contains %q", want)
		}
	}
	if strings.Contains(Schema, "statement_timeout=0") {
		t.Error("client logins should not have their statement timeout touched")
	}
}
