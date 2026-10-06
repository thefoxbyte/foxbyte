//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package schema

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// The paid schemas are layered on top of ledger.sql exactly as ledger_ext.sql
// is, and the same rule applies to all of them: nothing added later may
// redefine what wrote a chain, or every chain already written stops verifying.
//
// The list of forbidden objects comes from internal/ledger so that this and the
// test of the free half cannot drift into enforcing different rules about the
// same base.
func TestThePaidSchemasAreAdditive(t *testing.T) {
	for name, sql := range paidSchemas() {
		if sql == "" {
			t.Fatalf("%s is empty — is it embedded?", name)
		}
		for _, re := range ledger.ForbiddenInAdditiveSchema() {
			if loc := re.FindStringIndex(sql); loc != nil {
				t.Errorf("%s touches a base-ledger object: %q", name, sql[loc[0]:loc[1]])
			}
		}
	}
}

// Every schema here installs with the ledger's own event triggers suppressed,
// and restores that afterwards. Without the restore the connection would go on
// to run user DDL unrecorded.
func TestThePaidSchemasInstallQuietlyAndRestore(t *testing.T) {
	for name, sql := range paidSchemas() {
		if name == "impact.sql" {
			continue // only functions over the catalog; it creates nothing to record
		}
		for _, want := range []string{
			"SET session_replication_role = replica;",
			"SET session_replication_role = DEFAULT;",
		} {
			if !strings.Contains(sql, want) {
				t.Errorf("%s is missing %q", name, want)
			}
		}
	}
}

// checkpoints.sql's half of the invariant the free ledger_ext.sql keeps: a
// trigger whose job is to refuse a write may raise, and every other one must
// catch its own errors rather than aborting the change that fired it.
func TestCheckpointTriggersAreSafe(t *testing.T) {
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS bb.ledger_checkpoints",                      // idempotent
		"REVOKE UPDATE, DELETE, TRUNCATE ON bb.ledger_checkpoints FROM PUBLIC;", // append-only
	} {
		if !strings.Contains(schemaCheckpoints, want) {
			t.Errorf("checkpoints.sql is missing %q", want)
		}
	}
	const raisingGuards = 1 // checkpoint_contiguous
	if got, want := strings.Count(schemaCheckpoints, "RETURNS trigger"),
		strings.Count(schemaCheckpoints, "EXCEPTION WHEN OTHERS THEN")+raisingGuards; got != want {
		t.Errorf("checkpoints.sql defines %d trigger function(s); %d handle their own errors and %d may raise",
			got, strings.Count(schemaCheckpoints, "EXCEPTION WHEN OTHERS THEN"), raisingGuards)
	}
}

// checkpoints.sql reuses bb.deny_ext_change, which ledger_ext.sql defines — so
// the free half has to be installed first, and is: EnsureLedgerV2 runs the free
// set before asking the paid installer for anything. Asserted because the split
// put the definition and its use in different files, in different licences, and
// nothing else would notice the order being changed.
func TestCheckpointsDependOnTheFreeHalf(t *testing.T) {
	if !strings.Contains(schemaCheckpoints, "bb.deny_ext_change()") {
		t.Skip("checkpoints.sql no longer reuses the capture table's append-only guard")
	}
	if !strings.Contains(ledger.SchemaExt, "FUNCTION bb.deny_ext_change()") {
		t.Error("checkpoints.sql calls bb.deny_ext_change, which ledger_ext.sql no longer defines")
	}
}

// The gate writes a blocked attempt through dblink. If this transaction already
// holds the Blackbox append lock that write waits for us forever, so it checks
// first — the same contract ledger.sql's guardrail keeps, tested beside it in
// internal/ledger.
func TestTheGateChecksTheChainLockBeforeWriting(t *testing.T) {
	lock := strings.Index(schemaPolicy, "IF bb._holds_chain_lock() THEN")
	write := strings.Index(schemaPolicy, "INSERT INTO bb.schema_ledger")
	if lock < 0 || write < 0 {
		t.Fatalf("policy.sql (gate): lock check at %d, BLOCKED write at %d", lock, write)
	}
	if blocked := strings.Index(schemaPolicy[lock:], "'BLOCKED','policy'"); blocked < 0 {
		t.Error("policy.sql (gate): no BLOCKED write follows the lock check")
	}
}

// Rules match the statement that runs, not everything a client sent with it.
func TestTheGateMatchesStatementsNotTheWholeQuery(t *testing.T) {
	if strings.Contains(schemaPolicy, "q ~* pattern") ||
		!strings.Contains(schemaPolicy, "texts := bb._statement_texts('start', TG_TAG, ctx);") {
		t.Error("the policy gate must match rules against bb._statement_texts, not the whole query")
	}
	if !strings.Contains(schemaPolicy, "unnest(bb._statement_candidates(statement, command))") {
		t.Error("the policy preview must match the way the gate does")
	}
}

// A client must never be granted anything on the statement cursor: with it they
// could line a blocked statement up with a harmless one's text.
func TestNoClientGrantOnTheStatementCursor(t *testing.T) {
	for name, sql := range paidSchemas() {
		if strings.Contains(strings.ToLower(sql), "grant") && strings.Contains(sql, "bb.statement_cursor") {
			t.Errorf("%s grants something on bb.statement_cursor", name)
		}
	}
}

func paidSchemas() map[string]string {
	return map[string]string{
		"checkpoints.sql": schemaCheckpoints,
		"policy.sql":      schemaPolicy,
		"impact.sql":      schemaImpact,
	}
}
