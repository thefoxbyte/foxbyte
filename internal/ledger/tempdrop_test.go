// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"strings"
	"testing"
)

// A session's own temporary table may be dropped; everything else DROP TABLE
// touches stays guarded. The guard at ddl_command_start can only see text, so it
// lets a drop naming a temporary table of the session through, and the sql_drop
// trigger, which sees what was dropped, refuses it if anything is not temporary.
// The behaviour itself is checked against a server in scripts/integration_test.sh
// (section 8a).
func TestTemporaryTableDropsAreLetThrough(t *testing.T) {
	sql := lf(Schema)
	body := func(name string) string {
		i := strings.Index(sql, "CREATE OR REPLACE FUNCTION "+name)
		if i < 0 {
			t.Fatalf("%s is gone", name)
		}
		b := sql[i:]
		return b[:strings.Index(b, "\n$$;")]
	}

	hint := body("bb._names_own_temp_table(q text)")
	for _, want := range []string{"pg_my_temp_schema() <> 0", "c.relnamespace = pg_my_temp_schema()", "SET search_path = pg_catalog"} {
		if !strings.Contains(hint, want) {
			t.Errorf("bb._names_own_temp_table no longer has %q", want)
		}
	}
	if strings.Contains(hint, "SECURITY DEFINER") {
		t.Error("bb._names_own_temp_table needs no rights of its own")
	}

	guard := body("bb.guard_ddl_start()")
	skip := strings.Index(guard, "IF TG_TAG = 'DROP TABLE' AND bb._names_own_temp_table(current_query()) THEN")
	override := strings.Index(guard, "bb._may_override()")
	record := strings.Index(guard, "bb._record_blocked(")
	if skip < 0 || override < 0 || record < 0 || skip < override || skip > record {
		t.Errorf("the guard must let a temporary table's drop through after the override check and before recording (skip %d, override %d, record %d)", skip, override, record)
	}

	drop := body("bb.log_ddl_drop()")
	for _, want := range []string{
		"SELECT 1 FROM bb.policy WHERE op = TG_TAG AND action = 'block'",
		"evtname = 'bb_guard_start'", // the guard switched off for an import is off here too
		"AND bb._may_override())",
		"WHERE (original OR normal) AND NOT is_temporary",
		"AND NOT (schema_name IS NULL AND address_names[1] = 'pg_temp')",
		"IF bb._holds_chain_lock() THEN",
		"VALUES (%L,%L,%L,%L,%L,%L,%L,'BLOCKED','policy')",
		"'guardrail: % is blocked by policy (set bb.allow_destructive=on to override)'",
		"USING ERRCODE = 'insufficient_privilege'",
	} {
		if !strings.Contains(drop, want) {
			t.Errorf("bb.log_ddl_drop no longer has %q", want)
		}
	}
	// The refusal comes before anything is recorded as a drop.
	if r, w := strings.Index(drop, "RAISE EXCEPTION 'guardrail:"), strings.Index(drop, "FOR r IN SELECT * FROM pg_event_trigger_dropped_objects()"); r < 0 || w < 0 || r > w {
		t.Errorf("bb.log_ddl_drop must refuse before it records (refusal %d, record %d)", r, w)
	}
	// Temporary objects' drops are still left out of the record.
	if !strings.Contains(drop, "WHERE NOT is_temporary AND original LOOP") {
		t.Error("bb.log_ddl_drop records temporary objects' drops again")
	}
}
