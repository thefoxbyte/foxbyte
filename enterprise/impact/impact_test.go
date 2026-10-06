//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package impact

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

func TestScoreImpact(t *testing.T) {
	if s, level, why := scoreImpact(branch.ImpactReport{}); s != 0 || level != "none" || len(why) != 1 {
		t.Fatalf("not found: %d %s %v", s, level, why)
	}
	items := "public.items"
	r := branch.ImpactReport{
		Found: true, Action: "drop", Destructive: true, RowsEstimate: 50_000,
		Dependents: []branch.ImpactDependent{
			{Type: "view", Identity: "public.totals"},
			{Type: "view", Identity: "public.big"},
			{Type: "table constraint", Identity: "items_order_id_fkey on public.items", Relation: &items},
			{Type: "table constraint", Identity: "orders_pkey on public.orders", SameRelation: true},
			{Type: "index", Identity: "public.orders_note_idx", SameRelation: true},
		},
		Branches: []branch.BranchPresence{{Branch: "qa", Checked: true, Present: true}, {Branch: "old", Checked: false}},
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
	if s, level, _ := scoreImpact(branch.ImpactReport{Found: true, Action: "create-index"}); s != 1 || level != "low" {
		t.Errorf("harmless change: %d %s", s, level)
	}
	many := branch.ImpactReport{Found: true, Action: "alter"}
	for i := 0; i < 9; i++ {
		many.Branches = append(many.Branches, branch.BranchPresence{Present: true})
	}
	if s, level, _ := scoreImpact(many); s != 6 || level != "medium" {
		t.Errorf("branch bonus is capped at 5: %d %s", s, level)
	}
}
