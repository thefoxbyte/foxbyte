// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"strings"
	"testing"
)

// The 2.0 additions must stay additive: they may add objects next to the base
// ledger but never redefine or alter anything ledger.sql owns, or existing
// ledgers and hash chains could change underneath users.
// What used to be ledger_v2.sql is now two files on opposite sides of the
// edition line: ledger_ext.sql here, checkpoints.sql in enterprise/schema. This
// file tests the half this package owns; enterprise/schema tests the other, and
// the invariants are the same ones, applied to each.
func schemaV2() string { return SchemaExt }

func TestSchemaV2IsAdditive(t *testing.T) {
	if SchemaExt == "" {
		t.Fatal("ledger_ext.sql is empty — is it embedded?")
	}
	forbidden := ForbiddenInAdditiveSchema()
	for _, re := range forbidden {
		if loc := re.FindStringIndex(SchemaExt); loc != nil {
			t.Errorf("ledger_ext.sql touches a base-ledger object: %q", SchemaExt[loc[0]:loc[1]])
		}
	}
	// The base schema must not have picked up 2.0 objects either.
	if strings.Contains(Schema, "ledger_ext") {
		t.Error("ledger.sql references ledger_ext; 2.0 objects belong in ledger_ext.sql")
	}
}

// Every 2.0 trigger must be fail-safe and honour the kill switch, and the
// install must not leave replication-role changes behind.
func TestSchemaV2Safety(t *testing.T) {
	SchemaV2 := schemaV2()
	for _, want := range []string{
		"EXCEPTION WHEN OTHERS THEN",                  // capture errors become warnings
		"current_setting('bb.v2', true), '') = 'off'", // kill switch
		"IF bb._capture_disabled() THEN",              // …checked inside the fail-safe block
		"s.setrole = 0",                               // …honoured database-wide
		"rolname = session_user",                      // …or in a superuser's own session
		"SET session_replication_role = replica;",     // install isn't recorded as user DDL
		"SET session_replication_role = DEFAULT;",     // …and is restored
		"REVOKE UPDATE, DELETE, TRUNCATE ON bb.ledger_ext FROM PUBLIC;",
		"CREATE TABLE IF NOT EXISTS bb.ledger_ext", // idempotent
	} {
		if !strings.Contains(SchemaV2, want) {
			t.Errorf("ledger_ext.sql is missing %q", want)
		}
	}
	// Guards whose job is to refuse a write must raise; every other 2.0 trigger
	// must catch its own errors. checkpoints.sql has a raising guard of its own
	// (contiguity) and is counted the same way, in enterprise/schema.
	const raisingGuards = 1 // deny_ext_change (append-only)
	if strings.Count(SchemaV2, "RETURNS trigger") != strings.Count(SchemaV2, "EXCEPTION WHEN OTHERS THEN")+raisingGuards {
		t.Error("every capture trigger except the raising guard must catch its own errors")
	}
}

// A client's own SET bb.v2 = 'off' must not skip capture: the switch is read
// only through bb._capture_disabled, never directly by a trigger.
func TestCaptureKillSwitchNotClientSettable(t *testing.T) {
	SchemaV2 := schemaV2()
	fn := strings.Index(SchemaV2, "CREATE OR REPLACE FUNCTION bb._capture_disabled()")
	body := strings.Index(SchemaV2, "CREATE OR REPLACE FUNCTION bb.capture_ext()")
	if fn < 0 || body < 0 || fn > body {
		t.Fatal("bb._capture_disabled must be defined before capture_ext")
	}
	if strings.Count(SchemaV2, "current_setting('bb.v2'") != 1 {
		t.Error("bb.v2 must be read in exactly one place, bb._capture_disabled")
	}
	disabled := SchemaV2[fn:body]
	for _, want := range []string{"pg_db_role_setting", "s.setrole = 0", "c.cfg = 'bb.v2=off'", "rolsuper", "SECURITY DEFINER"} {
		if !strings.Contains(disabled, want) {
			t.Errorf("bb._capture_disabled is missing %q", want)
		}
	}
}
