// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Facts where every check passes and everything is declared.
func goodSafeguards() safeguardFacts {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	reviewed := now.Add(-24 * time.Hour)
	f := safeguardFacts{now: now, target: Target{Kind: "s3", Bucket: "b", Encrypted: true},
		backups: BackupHealth{Newest: now.Add(-2 * time.Hour).Format(time.RFC3339), AgeHours: 2, Schedule: "every 24h"},
		restore: RestoreCheck{At: now.Add(-48 * time.Hour).Format(time.RFC3339), OK: true}, restored: true, restoreEvery: 7 * 24 * time.Hour,
		vault: true, auditOn: true, auditDays: 365, auditChain: &ChainReport{Intact: true, Records: 10, Anchored: 10},
		blackbox: "ledger ok", seclog: ledger.Report{Intact: true, Rows: 5}, hardening: &HardeningReport{Summary: map[string]int{HardenPass: 30}},
		access: &SafeguardAccess{Accounts: 3, Admins: 1, Keys: 2, DormantDays: 90}, reviewed: &reviewed, historyDays: 90,
		decl: map[string]*auth.VaultDeclaration{}}
	for _, it := range safeguardItems {
		f.decl[it.Item] = &auth.VaultDeclaration{Item: it.Item, Value: "yes", DeclaredBy: "dpo@x", DeclaredAt: now}
	}
	return f
}

func rule(ev *SafeguardsEvidence, clause string) SafeguardRule {
	for _, r := range ev.Rules {
		if r.Clause == clause {
			return r
		}
	}
	return SafeguardRule{}
}

func TestSafeguardsMetWhenCheckedAndDeclared(t *testing.T) {
	ev := reckonSafeguards(goodSafeguards())
	if len(ev.Rules) != 7 || ev.Summary[VaultMet] != 7 {
		for _, r := range ev.Rules {
			for _, c := range r.Checks {
				if !c.OK {
					t.Logf("%s: %s: %s", r.Clause, c.What, c.Detail)
				}
			}
		}
		t.Fatalf("summary %v", ev.Summary)
	}
	if ev.Format != SafeguardsFormat || !strings.Contains(ev.Rule, "G.S.R. 846(E)") || !strings.Contains(ev.InForce, "13 May 2027") {
		t.Fatalf("the document: %+v", ev)
	}
	for _, r := range ev.Rules {
		if r.Guards == "" || r.NotAgainst == "" || r.Requirement == "" {
			t.Fatalf("%s has no threat model or words", r.Clause)
		}
	}
	// Every list is a list, never null: the console maps over them.
	b, _ := json.Marshal(ev)
	if strings.Contains(string(b), "null") {
		t.Fatalf("a null in the document: %s", b)
	}
	if n := rule(ev, "6(1)(e)").Notes; len(n) != 1 || !strings.Contains(n[0], "Query history") {
		t.Fatalf("history's note: %v", n)
	}
}

func TestSafeguardsOpenWithoutADeclarationAndNotMetOnAFailedCheck(t *testing.T) {
	f := goodSafeguards()
	delete(f.decl, "processors")
	f.backups.Stale = true
	f.target.Encrypted = false
	f.exposure = []VaultBranchExposure{{Branch: "dev", Numbers: 3}}
	ev := reckonSafeguards(f)
	if r := rule(ev, "6(1)(f)"); r.Verdict != VaultOpen || len(r.Declared) != 0 {
		t.Fatalf("(f) undeclared: %+v", r)
	}
	if r := rule(ev, "6(1)(d)"); r.Verdict != VaultNotMet {
		t.Fatalf("(d) with a stale backup: %+v", r)
	}
	a := rule(ev, "6(1)(a)")
	if a.Verdict != VaultNotMet || !strings.Contains(a.Checks[0].Detail, "encrypted: false") || !strings.Contains(a.Checks[2].Detail, "dev: 3 number(s) outside the vault") {
		t.Fatalf("(a): %+v", a)
	}
	// A failed check wins over a missing declaration: not met, not open.
	delete(f.decl, "dr")
	if r := rule(reckonSafeguards(f), "6(1)(d)"); r.Verdict != VaultNotMet {
		t.Fatalf("(d): %+v", r)
	}
}

func TestSafeguardsReadWhatIsMissing(t *testing.T) {
	f := goodSafeguards()
	f.access = &SafeguardAccess{Err: "the access review is not available in this edition"}
	f.reviewed = nil
	f.auditOn, f.auditChain = false, nil
	f.unaudited = []string{"public.people"}
	f.masked, f.unmasked = 2, 4
	f.seclogDays = 30 * 24 * time.Hour
	ev := reckonSafeguards(f)
	if r := rule(ev, "6(1)(b)"); r.Verdict != VaultNotMet || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "point 15") {
		t.Fatalf("(b): %+v", r)
	}
	c := rule(ev, "6(1)(c)")
	if c.Verdict != VaultNotMet || !strings.Contains(c.Checks[1].Detail, "public.people") {
		t.Fatalf("(c): %+v", c)
	}
	if a := rule(ev, "6(1)(a)"); a.Verdict != VaultNotMet || !strings.Contains(a.Checks[len(a.Checks)-1].Detail, "4 confirmed personal-data column(s)") {
		t.Fatalf("(a) with masked accounts: %+v", a)
	}
	if e := rule(ev, "6(1)(e)"); e.Verdict != VaultNotMet || !strings.Contains(e.Checks[1].Detail, "30 day(s)") {
		t.Fatalf("(e): %+v", e)
	}
}

func TestSafeguardDeclarationsAreRecorded(t *testing.T) {
	f := &fakeErasure{}
	f.install(t) // Enterprise, licensed
	s := erasureStore(t)
	if _, err := DeclareSafeguard(s, "nope", "x", "dpo@x"); err == nil || !strings.Contains(err.Error(), "processors") {
		t.Fatalf("an unknown item: %v", err)
	}
	if _, err := DeclareSafeguard(s, "processors", "No Data Processor handles this data.", "dpo@x"); err != nil {
		t.Fatal(err)
	}
	ds, err := SafeguardDeclarations(s)
	if err != nil || len(ds) != 1 || ds[0].Item != "processors" || ds[0].DeclaredBy != "dpo@x" {
		t.Fatalf("declarations: %v %+v", err, ds)
	}
	// Kept apart from the vault's.
	if vs, _ := s.VaultDeclarations("aadhaar", false); len(vs) != 0 {
		t.Fatalf("leaked into the vault's: %+v", vs)
	}
	if _, err := DeclareSafeguard(s, "processors", "", "dpo@x"); err != nil {
		t.Fatal(err)
	}
	if ds, _ := SafeguardDeclarations(s); len(ds) != 0 {
		t.Fatalf("withdrawn: %+v", ds)
	}
}
