// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/url"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// The default columns are a contract: the SDKs and the console were built
// against them, and the contract tests assert them exactly. Extra columns are
// opt-in, so a client that asks for nothing gets what it always got.
func TestLedgerSQLDefaultColumns(t *testing.T) {
	sql := ledgerSQL(url.Values{})
	for _, unwanted := range []string{"session", "prev_hash", "row_hash", "app_for", "ledger_ext"} {
		if strings.Contains(sql, unwanted) {
			t.Errorf("the default query selects %q, which clients were not built for:\n%s", unwanted, sql)
		}
	}
	for _, want := range []string{"at", "actor", "actor_kind", "tool", "branch", "command_tag", "object_identity", "statement", "status", "risk"} {
		if !strings.Contains(sql, want) {
			t.Errorf("the default query lost %q:\n%s", want, sql)
		}
	}
}

// with=chain is what lets the console show that an entry is linked to the one
// before it, and lets it offer to branch from before an entry — which needs the
// id the default response never carried.
func TestLedgerSQLWithChain(t *testing.T) {
	sql := ledgerSQL(url.Values{"with": {"chain"}})
	for _, want := range []string{", id", "prev_hash", "row_hash"} {
		if !strings.Contains(sql, want) {
			t.Errorf("with=chain did not add %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "session") {
		t.Errorf("with=chain should not add session:\n%s", sql)
	}
}

// Both together, in one request, which is what the Blackbox page asks for.
func TestLedgerSQLWithSessionAndChain(t *testing.T) {
	sql := ledgerSQL(url.Values{"with": {"session,chain"}})
	for _, want := range []string{"session", "id", "prev_hash", "row_hash"} {
		if !strings.Contains(sql, want) {
			t.Errorf("with=session,chain did not add %q:\n%s", want, sql)
		}
	}
	// Spacing around the names is how the columns reach the client; a malformed
	// list would fail at the database rather than here.
	if strings.Count(sql, "prev_hash") != 1 || strings.Count(sql, "session") != 1 {
		t.Errorf("a column was added twice:\n%s", sql)
	}
}

// An unknown value is ignored rather than reaching the database.
func TestLedgerSQLIgnoresUnknownWith(t *testing.T) {
	sql := ledgerSQL(url.Values{"with": {"session, chain , nonsense"}})
	if strings.Contains(sql, "nonsense") {
		t.Errorf("an unknown `with` value reached the query:\n%s", sql)
	}
	// Whitespace around the names is accepted, as a hand-written URL will have it.
	for _, want := range []string{"session", "prev_hash"} {
		if !strings.Contains(sql, want) {
			t.Errorf("padding stopped %q being added:\n%s", want, sql)
		}
	}
}

// with=for says who each change was made for, and reads the keys reported
// compromised from the account store into the query, so nobody reading a
// Blackbox needs access to the branch's copy of the keys.
func TestLedgerSQLWithFor(t *testing.T) {
	old := compromisedKeys
	compromisedKeys = func() []branch.CompromisedKey {
		return []branch.CompromisedKey{{Issuer: "o'shop", Kid: "k1", Since: 1792659600}}
	}
	t.Cleanup(func() { compromisedKeys = old })
	sql := ledgerSQL(url.Values{"with": {"for,chain"}, "actor": {"alice"}})
	for _, want := range []string{"AS app_for", "AS app_state", "AS app_kid", "AS app_note",
		"LEFT JOIN LATERAL (SELECT to_jsonb(x) AS j FROM bb.ledger_ext x WHERE x.ledger_id = bb.schema_ledger.id) app_ext ON true",
		"VALUES ('o''shop', 'k1', 1792659600::bigint)", "(key reported compromised)", "actor ILIKE '%alice%'", "prev_hash"} {
		if !strings.Contains(sql, want) {
			t.Errorf("with=for should contain %q:\n%s", want, sql)
		}
	}
	twice := ledgerSQL(url.Values{"with": {"for,for"}})
	if strings.Count(twice, ") app_ext ON true") != 1 || strings.Count(twice, ") app_sess ON true") != 1 {
		t.Errorf("each join once, however the columns were asked for:\n%s", twice)
	}
	// Whom the agent session was started for (Agent API act_for).
	for _, want := range []string{"FROM bb.agent_sessions y WHERE y.session_id = bb.schema_ledger.session", "AS session_for"} {
		if !strings.Contains(sql, want) {
			t.Errorf("with=for should contain %q:\n%s", want, sql)
		}
	}
	compromisedKeys = func() []branch.CompromisedKey { return nil }
	if sql := ledgerSQL(url.Values{"with": {"for"}}); !strings.Contains(sql, "SELECT NULL::text, NULL::text, NULL::bigint WHERE false") {
		t.Errorf("with no compromised key, the list should be empty, not missing:\n%s", sql)
	}
}
