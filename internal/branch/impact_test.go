// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

func TestScoreImpact(t *testing.T) {
	if s, level, why := scoreImpact(ImpactReport{}); s != 0 || level != "none" || len(why) != 1 {
		t.Fatalf("not found: %d %s %v", s, level, why)
	}
	items := "public.items"
	r := ImpactReport{
		Found: true, Action: "drop", Destructive: true, RowsEstimate: 50_000,
		Dependents: []ImpactDependent{
			{Type: "view", Identity: "public.totals"},
			{Type: "view", Identity: "public.big"},
			{Type: "table constraint", Identity: "items_order_id_fkey on public.items", Relation: &items},
			{Type: "table constraint", Identity: "orders_pkey on public.orders", SameRelation: true},
			{Type: "index", Identity: "public.orders_note_idx", SameRelation: true},
		},
		Branches: []BranchPresence{{Branch: "qa", Checked: true, Present: true}, {Branch: "old", Checked: false}},
		Policy:   []ledger.PolicyDetail{{RuleID: "drop-column", Action: "block"}},
	}
	// 5 destructive + 6 views + 3 fk + 1 index + 1 other + 1 rows + 1 branch + 5 policy
	s, level, why := scoreImpact(r)
	if s != 23 || level != "high" {
		t.Fatalf("score %d %s: %v", s, level, why)
	}
	joined := strings.Join(why, "\n")
	for _, want := range []string{"+5 drop can lose data", "+6 2 dependent views", "+3 1 constraint on another table", "+1 1 index",
		"+1 about 50000 rows", "+1 also on 1 other running branch", "+5 policy rule drop-column would block it"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reasons lack %q:\n%s", want, joined)
		}
	}
	if s, level, _ := scoreImpact(ImpactReport{Found: true, Action: "create-index"}); s != 1 || level != "low" {
		t.Errorf("harmless change: %d %s", s, level)
	}
	many := ImpactReport{Found: true, Action: "alter"}
	for i := 0; i < 9; i++ {
		many.Branches = append(many.Branches, BranchPresence{Present: true})
	}
	if s, level, _ := scoreImpact(many); s != 6 || level != "medium" {
		t.Errorf("branch bonus is capped at 5: %d %s", s, level)
	}
}

func TestBranchParentParsing(t *testing.T) {
	for in, want := range map[string]string{
		"dbpool/branches/main@for-qa\n": "main",
		"dbpool/branches/qa@for-qa-2":   "qa",
		"-":                             "",
		"":                              "",
		"otherpool/x@snap":              "",
		"dbpool/branches/a/b@s":         "",
	} {
		if got := parentFromZFSOrigin(in); got != want {
			t.Errorf("parentFromZFSOrigin(%q) = %q, want %q", in, got, want)
		}
	}
	show := "qa\n\tName: \t\t\tqa\n\tUUID: \t\t\t9f0c-qa\n\tParent UUID: \t\t3e1f-main\n\tReceived UUID: \t\t-\n"
	if got := parentUUIDFromShow(show); got != "3e1f-main" {
		t.Errorf("parent uuid = %q", got)
	}
	if got := parentUUIDFromShow("main\n\tParent UUID: \t\t-\n"); got != "" {
		t.Errorf("no parent = %q", got)
	}
	list := "ID 256 gen 12 top level 5 uuid 3e1f-main path main\nID 257 gen 14 top level 5 uuid 9f0c-qa path qa\n"
	if got := subvolumeByUUID(list, "3e1f-main"); got != "main" {
		t.Errorf("subvolume = %q", got)
	}
	if got := subvolumeByUUID(list, "nope"); got != "" {
		t.Errorf("unknown uuid = %q", got)
	}
}

func TestFormatImpact(t *testing.T) {
	if got := FormatImpact(ImpactReport{Branch: "main", Target: "nope"}); !strings.Contains(got, "not found") {
		t.Errorf("not found: %q", got)
	}
	via := "public.totals"
	col := "total"
	out := FormatImpact(ImpactReport{
		Branch: "main", Found: true, Target: "public.orders", Type: "table", Column: &col, Action: "drop-column", Destructive: true,
		Score: 11, Level: "medium", Reasons: []string{"+5 x"},
		Dependents: []ImpactDependent{{Type: "view", Identity: "public.big", Dependency: "depends on it", Via: &via}},
		Branches:   []BranchPresence{{Branch: "qa", Checked: true, Present: true, Parent: "main"}},
	})
	for _, want := range []string{"public.orders (table), column total — MEDIUM (score 11)", "drop-column (destructive)", "via public.totals", "qa", "has it", "cloned from main"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func row(id int64, obj, status string, at time.Time) ledger.Row {
	return ledger.Row{ID: id, At: at, CommandTag: "ALTER TABLE", ObjectIdentity: obj, Status: status, Actor: "a"}
}

func TestBuildDiff(t *testing.T) {
	t0 := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	shared := []ledger.Row{row(1, "public.a", "APPLIED", t0), row(2, "public.b", "APPLIED", t0.Add(time.Minute))}
	a := append(append([]ledger.Row{}, shared...), row(3, "public.orders", "APPLIED", t0.Add(2*time.Minute)), row(4, "public.main_only", "APPLIED", t0.Add(3*time.Minute)))
	b := append(append([]ledger.Row{}, shared...), row(3, "public.branch_only", "APPLIED", t0.Add(4*time.Minute)),
		row(4, "public.orders", "APPLIED", t0.Add(5*time.Minute)), row(5, "public.main_only", "BLOCKED", t0.Add(6*time.Minute)))
	d := buildDiff("main", "qa", a, b)
	if d.CommonEntries != 2 || d.ForkAfterID != 2 || d.ForkAfterAt != "2026-09-15T10:01:00Z" {
		t.Fatalf("fork: %+v", d)
	}
	if len(d.AOnly) != 2 || len(d.BOnly) != 3 {
		t.Fatalf("sides: %d %d", len(d.AOnly), len(d.BOnly))
	}
	// Same id on both sides but different content is not shared.
	if d.AOnly[0].ID != 3 || d.BOnly[0].ID != 3 {
		t.Fatalf("ids: %+v %+v", d.AOnly[0], d.BOnly[0])
	}
	// public.orders changed on both; public.main_only was only BLOCKED on qa.
	if len(d.BothTouched) != 1 || d.BothTouched[0].Object != "public.orders" ||
		d.BothTouched[0].AEntries[0] != 3 || d.BothTouched[0].BEntries[0] != 4 {
		t.Fatalf("overlap: %+v", d.BothTouched)
	}

	same := buildDiff("main", "main", a, a)
	if same.CommonEntries != 4 || len(same.AOnly)+len(same.BOnly)+len(same.BothTouched) != 0 {
		t.Fatalf("self diff: %+v", same)
	}
	none := buildDiff("x", "y", nil, b)
	if none.CommonEntries != 0 || none.ForkAfterID != 0 || len(none.BOnly) != 5 {
		t.Fatalf("no shared history: %+v", none)
	}

	d.BParent = "main"
	out := FormatDiff(d)
	for _, want := range []string{"Blackbox diff: main vs qa", "qa was cloned from main", "shared history: 2 entries, up to #2",
		"only on main (2):", "only on qa (3):", "changed on both (1):", "public.orders  main #3  qa #4"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(FormatDiff(none), "no shared history") {
		t.Error("no shared history not reported")
	}
}
