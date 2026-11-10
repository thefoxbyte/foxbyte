// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"regexp"
	"strings"
	"testing"
)

// allowedCallable reads ledger.sql's list of what a client may call.
func allowedCallable(t *testing.T) map[string]bool {
	t.Helper()
	i := strings.Index(Schema, "CREATE OR REPLACE FUNCTION bb._client_callable()")
	if i < 0 {
		t.Fatal("bb._client_callable is gone")
	}
	body := Schema[i:]
	body = body[:strings.Index(body, "$$;")]
	body = body[strings.Index(body, "SELECT ARRAY["):]
	allowed := map[string]bool{}
	for _, m := range regexp.MustCompile(`'(_?[a-z0-9_]+)'`).FindAllStringSubmatch(body, -1) {
		allowed[m[1]] = true
	}
	return allowed
}

// The ledger's entries are forged through what a client can call, so nothing a
// client can call may be a helper that writes one. Nothing grants the whole
// schema any more, and the seal is applied both to what exists and to what is
// made later (which, for most schema files, is made under a replica session).
func TestClientsCannotCallTheHelpers(t *testing.T) {
	if strings.Contains(Schema, "ON ALL FUNCTIONS IN SCHEMA bb") {
		t.Error("ledger.sql grants the whole of schema bb again")
	}
	for _, want := range []string{
		"format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, db_client', f::regprocedure)",
		"AND p.prosecdef AND NOT p.proname = ANY (bb._client_callable())",
		"WHEN TAG IN ('CREATE FUNCTION', 'ALTER FUNCTION', 'CREATE PROCEDURE', 'ALTER PROCEDURE', 'ALTER ROUTINE')",
		"ALTER EVENT TRIGGER bb_seal_functions ENABLE ALWAYS;",
		"SET search_path = pg_catalog SET session_replication_role = replica",
	} {
		if !strings.Contains(Schema, want) {
			t.Errorf("ledger.sql no longer contains %q", want)
		}
	}
	// On every start, before capture is switched on, like the other privileges.
	sweep := strings.Index(Schema, "DO $seal$")
	on := strings.Index(Schema, "CREATE EVENT TRIGGER bb_guard_start")
	if sweep < 0 || on < 0 || sweep > on {
		t.Errorf("the sweep over existing functions must run before capture is on (sweep %d, capture %d)", sweep, on)
	}

	allowed := allowedCallable(t)
	for _, forbidden := range []string{"_record_impact", "_attach_data_triggers", "_statement_texts",
		"guard_ddl_start", "log_ddl_end", "guard_truncate", "capture_ext", "_capture_disabled"} {
		if allowed[forbidden] {
			t.Errorf("bb.%s is client-callable: a client could use the owner's rights through it", forbidden)
		}
	}
}

// Everything the client-side code calls as a client is on the list. What the
// engine calls as its superuser needs no grant, and neither does a function
// the docs name only for operators.
func TestClientCalledFunctionsAreOnTheList(t *testing.T) {
	allowed := allowedCallable(t)
	for _, name := range []string{"act_for", "app_actor", "app_actor_label", "app_identity_mode",
		"_ledger_hash", "_ext_hash", "policy_check", "blast_radius"} {
		if !allowed[name] {
			t.Errorf("bb.%s is called by clients and is not on the list", name)
		}
	}
}

// Every SECURITY DEFINER function the free schemas define is either on the
// list, named to be sealed, or simply not; what must hold is that the list
// does not grow by accident to include a definer that writes the ledger.
func TestOnlyActForIsAClientCallableDefiner(t *testing.T) {
	allowed := allowedCallable(t)
	def := regexp.MustCompile(`(?is)FUNCTION bb\.([a-z0-9_]+)\([^)]*\)[^;$]*?SECURITY DEFINER`)
	for _, sql := range []string{Schema, SchemaData, SchemaExt, SchemaTracking, SchemaIdentity} {
		for _, m := range def.FindAllStringSubmatch(sql, -1) {
			if allowed[m[1]] && m[1] != "act_for" {
				t.Errorf("bb.%s is SECURITY DEFINER and client-callable: review it, then allow it here", m[1])
			}
		}
	}
}
