// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"strings"
	"testing"
)

// CREATE OR REPLACE TRIGGER keeps a guard's name and changes what it does, so
// a guard is compared with what the Blackbox installs, not by name. The
// behaviour is proved against a real server; this guards the shape of it.
func TestGuardTriggersCannotBeReplaced(t *testing.T) {
	for _, want := range []string{
		"g.tgfoid = to_regprocedure('bb.guard_truncate()') AND g.tgtype = 34",
		"g.tgfoid = to_regprocedure('bb.record_dml()') AND g.tgtype = 24",
		"g.tgfoid = to_regprocedure('bb.guard_dml()') AND g.tgtype = 26",
		"g.tgfoid = to_regprocedure('bb.guard_impact()') AND g.tgtype = 27",
		"g.tgfoid = to_regprocedure('bb.track_row()') AND g.tgtype = 23",
		// A guard narrowed to one column, or to a condition, is no guard.
		"g.tgattr::text <> ''",
		"bb._normal_when(bb._impact_when())",
	} {
		if !strings.Contains(Schema, want) {
			t.Errorf("ledger.sql no longer contains %q", want)
		}
	}
	for _, want := range []string{
		"r.command_tag = 'CREATE TRIGGER' AND r.object_type = 'trigger' AND NOT bb._override_in_force()",
		"AND NOT bb._is_own_trigger(t.oid);",
		"t.tgname LIKE 'bb\\_%' AND n.nspname NOT IN ('bb','bb_f1')",
		"'CREATE TRIGGER','trigger',%L,%L,'BLOCKED','policy'",
	} {
		if !strings.Contains(SchemaData, want) {
			t.Errorf("datachanges.sql no longer contains %q", want)
		}
	}
}

// The recorder's skip list goes by name, so it must also ask for the
// definition, or a replaced guard is passed over as plumbing.
func TestRecorderSkipsOnlyTheInstalledGuards(t *testing.T) {
	if !strings.Contains(Schema, "guard_impact) on '\n       AND bb._is_own_trigger(r.objid) THEN CONTINUE;") {
		t.Error("log_ddl_end skips a trigger by its name alone")
	}
	// The check is defined in ledger.sql beside its caller, for a recorder
	// upgraded before datachanges.sql has been re-run.
	if strings.Index(Schema, "FUNCTION bb._is_own_trigger") > strings.Index(Schema, "FUNCTION bb.log_ddl_end") {
		t.Error("bb._is_own_trigger must be defined before bb.log_ddl_end")
	}
}
