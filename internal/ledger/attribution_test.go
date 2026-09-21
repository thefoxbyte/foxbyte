// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"regexp"
	"strings"
	"testing"
)

// actor_kind must be derived from the login role, not read from the session.
// bb.actor_kind is an ordinary session setting, so while _ctx believed it a
// client could `SET bb.actor_kind = 'human'` and have an agent's changes
// recorded as a person's — the one thing this record exists to prevent. The
// behaviour itself is proved in integration-v2 §1c (a human claiming to be an
// agent and an agent claiming to be human are both recorded truthfully); this
// test guards the derivation against being quietly replaced by the setting
// again.
func TestActorKindDerivedFromRole(t *testing.T) {
	ctx := ctxFunction(t)

	for _, want := range []string{
		// An agent branch's own role is always an agent…
		"WHEN session_user LIKE 'agent-%'",
		// …unless the role is named for an email address (a person whose
		// address happens to start with "agent-").
		"position('@' in session_user) = 0",
		// A per-user role is a person.
		"WHEN session_user NOT IN ('dbadmin','db_client') THEN 'human'",
	} {
		if !strings.Contains(ctx, want) {
			t.Errorf("_ctx no longer derives the kind from the role: missing %q", want)
		}
	}

	// The injected setting may only be consulted for the shared roles, which
	// have no identity of their own — never as the first answer.
	kindLine := regexp.MustCompile(`(?s)OUT actor_kind.*?current_setting\('bb\.actor_kind'`)
	if !kindLine.MatchString(ctx) {
		t.Fatal("_ctx does not mention bb.actor_kind at all; expected it as the shared-role fallback")
	}
	before, _, _ := strings.Cut(ctx, "current_setting('bb.actor_kind'")
	if !strings.Contains(before, "session_user LIKE 'agent-%'") {
		t.Error("the session setting is consulted before the role is examined")
	}
}

// ctxFunction returns the body of bb._ctx from the embedded schema.
func ctxFunction(t *testing.T) string {
	t.Helper()
	const marker = "CREATE OR REPLACE FUNCTION bb._ctx("
	i := strings.Index(Schema, marker)
	if i < 0 {
		t.Fatal("bb._ctx is not in the schema")
	}
	rest := Schema[i:]
	end := strings.Index(rest, "$$;")
	if end < 0 {
		t.Fatal("bb._ctx has no end")
	}
	return rest[:end]
}

// SchemaName is what the shell library and the uninstaller are generated from,
// so it must be what the SQL actually creates. If the two drift, tools go
// looking for a schema that is not there.
func TestSchemaNameMatchesSQL(t *testing.T) {
	if !strings.Contains(Schema, "CREATE SCHEMA IF NOT EXISTS "+SchemaName) {
		t.Errorf("ledger.sql does not create schema %q", SchemaName)
	}
	// And every object in it is qualified with the same name.
	if !strings.Contains(Schema, SchemaName+".schema_ledger") {
		t.Errorf("ledger.sql does not put schema_ledger in %q", SchemaName)
	}
}
