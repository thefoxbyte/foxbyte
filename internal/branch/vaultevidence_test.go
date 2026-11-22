// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func goodKey(label, role string) VaultEvidenceKey {
	return VaultEvidenceKey{Label: label, Role: role, Gen: 1, Current: true, Created: "2026-11-01T10:00:00Z",
		Sensitive: true, AlwaysSensitive: true, NeverExtractable: true, Local: true}
}

// A machine where everything FoxByte checks holds, an HSM rather than the
// software token, every branch clean, and nothing declared yet.
func goodFacts() vaultFacts {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	ran := now.Add(-24 * time.Hour)
	f := vaultFacts{
		machine: vaultMachine{set: true, db: true, svc: true, internal: true, onNetwork: []string{"fox-vault", "fox-vault-db"}, socketMode: 0o600},
		anchor:  VaultAnchor{Holds: true, Note: "entry 9 is as the security log saw it"},
		decl:    map[string]*auth.VaultDeclaration{},
		now:     now, since: now.Add(-90 * 24 * time.Hour),
	}
	f.svc.Token.Maker, f.svc.Token.Model, f.svc.Token.Serial = "Thales", "Luna 7", "12345"
	f.svc.Log.Entries = 9
	f.kind = VaultKindEvidence{Kind: "aadhaar", Records: 3, Keys: []VaultEvidenceKey{goodKey("vault-aadhaar-data-1", "data"), goodKey("vault-aadhaar-index-1", "index")},
		Activity: VaultActivity{Calls: map[string]int{"tokenise": 2}},
		Branches: []VaultBranchExposure{{Branch: "main", State: "running", Run: 4, Ran: &ran}}}
	return f
}

func verdicts(rows []VaultRule) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		out[r.Para] = r.Verdict
	}
	return out
}

func TestAadhaarRulesVerdicts(t *testing.T) {
	f := goodFacts()
	v := verdicts(aadhaarRules(f))
	// Met by what FoxByte checks or builds in.
	for _, p := range []string{"2", "3", "7(a)", "7(b)", "7(c)", "7(d)", "7(e)", "7(h)", "7(k)", "8"} {
		if v[p] != VaultMet {
			t.Errorf("para %s: %s", p, v[p])
		}
	}
	// The customer's, open until declared; 7(f) not met while FoxByte does
	// not back up the vault database.
	for _, p := range []string{"4", "5", "6", "7(g)", "7(i)", "7(j)", "9", "10"} {
		if v[p] != VaultOpen {
			t.Errorf("para %s: %s, want open", p, v[p])
		}
	}
	if v["7(f)"] != VaultNotMet {
		t.Errorf("7(f): %s", v["7(f)"])
	}
	if len(aadhaarRules(f)) != 19 {
		t.Errorf("%d rows", len(aadhaarRules(f)))
	}

	// Declared: met; hosting on premises makes SOC 2 not applicable; para 9
	// needs both its items.
	for _, it := range []string{"hosting", "no-input-storage", "network-zone", "monitoring", "retention", "hsm-certificate", "auth-apps"} {
		f.decl[it] = &auth.VaultDeclaration{Kind: "aadhaar", Item: it, Value: "x", DeclaredBy: "a@x.com"}
	}
	f.decl["hosting"].Value = "On premises, Mumbai DC"
	v = verdicts(aadhaarRules(f))
	for _, p := range []string{"4", "5", "7(g)", "7(i)", "7(j)", "10"} {
		if v[p] != VaultMet {
			t.Errorf("declared para %s: %s", p, v[p])
		}
	}
	if v["6"] != VaultNotApplicable || v["9"] != VaultOpen {
		t.Errorf("6: %s, 9: %s", v["6"], v["9"])
	}
	f.decl["hsm-access"] = &auth.VaultDeclaration{Item: "hsm-access", Value: "MFA, 3 roles"}
	if v := verdicts(aadhaarRules(f)); v["9"] != VaultMet {
		t.Errorf("9 with both: %s", v["9"])
	}
	// A declaration never covers a failed check.
	f.kind.Keys[0].Extractable = true
	if v := verdicts(aadhaarRules(f)); v["9"] != VaultNotMet {
		t.Errorf("9 with a key that can leave: %s", v["9"])
	}
}

func TestAadhaarRulesFindWhatFails(t *testing.T) {
	f := goodFacts()
	f.svc.Token.Software = true
	f.machine.internal = false
	f.machine.published = "fox-vault: 8200/tcp"
	f.anchor = VaultAnchor{Holds: false, Note: "entries were cut off its end"}
	f.kind.Branches[0].Numbers, f.kind.Branches[0].Flag = 3, "3 Aadhaar number(s) found in its tables"
	rows := aadhaarRules(f)
	v := verdicts(rows)
	for _, p := range []string{"2", "3", "4", "7(c)", "7(d)", "7(g)", "7(h)", "8"} {
		if v[p] != VaultNotMet {
			t.Errorf("para %s: %s, want not met", p, v[p])
		}
	}
	for _, r := range rows {
		if r.Para == "8" && !strings.Contains(r.Checks[0].Detail, "software token") {
			t.Errorf("para 8 says why: %+v", r.Checks)
		}
		if r.Para == "3" && !strings.Contains(r.Checks[0].Detail, "main: 3 Aadhaar number(s)") {
			t.Errorf("para 3 names the branch: %+v", r.Checks)
		}
	}
	// No branch read at all is no evidence that none holds a number.
	f.kind.Branches = nil
	if v := verdicts(aadhaarRules(f)); v["3"] != VaultNotMet {
		t.Errorf("no branches: %s", v["3"])
	}
}

func TestExposureFlag(t *testing.T) {
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	fresh, old := now.Add(-48*time.Hour), now.Add(-40*24*time.Hour)
	if f := exposureFlag(VaultBranchExposure{Ran: &fresh}, now); f != "" {
		t.Errorf("clean: %q", f)
	}
	if f := exposureFlag(VaultBranchExposure{Ran: &old, Numbers: 2, LogNumbers: 1}, now); f != "2 Aadhaar number(s) found in its tables; 1 in its logs; its latest report is 40 days old" {
		t.Errorf("flagged: %q", f)
	}
}

func TestVaultActivity(t *testing.T) {
	keys := []VaultEvidenceKey{goodKey("vault-aadhaar-data-2", "data")}
	keys[0].Created = "2026-11-20T00:00:00Z"
	at := func(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }
	es := []vaultEntry{
		{Action: "tokenise", Kind: "aadhaar", N: 5, Result: "done 5", At: at("2026-11-21T00:00:00Z")},
		{Action: "update", Kind: "aadhaar", N: 2, Result: "done 1, another key holds it 1", At: at("2026-11-21T00:00:00Z")},
		{Action: "delete", Kind: "aadhaar", N: 3, Result: "not found 1, done 2", At: at("2026-11-21T00:00:00Z")},
		{Action: "delete", Kind: "aadhaar", N: 4, Result: "done 4", At: at("2026-11-19T00:00:00Z")}, // before the key: shredded by it
		{Action: "delete", Kind: "text", N: 1, Result: "done 1", At: at("2026-11-21T00:00:00Z")},
	}
	a := vaultActivity(es, "aadhaar", keys)
	if a.Calls["delete"] != 2 || a.Values["tokenise"] != 5 || a.Changed != 3 || a.DataKeyMade != "2026-11-20T00:00:00Z" {
		t.Fatalf("%+v", a)
	}
}
