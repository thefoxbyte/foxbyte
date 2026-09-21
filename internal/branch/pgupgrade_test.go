// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bytes"
	"strings"
	"testing"
)

// A plan for an install that should upgrade cleanly; each case breaks one thing.
func healthyPlan() UpgradePlan {
	return UpgradePlan{
		From: "16", To: "18", MainRunning: true,
		All:          []string{"agent-7c2a", "main", "qa"},
		Carry:        []string{"main", "qa"},
		Majors:       map[string]string{"main": "16", "qa": "16", "agent-7c2a": "16"},
		LedgerErrors: map[string]string{}, Applies: map[string][]string{},
		Notes: NotesBetween("16", "18"),
	}
}

func TestUpgradeRefusals(t *testing.T) {
	if r := healthyPlan().Refusals(); len(r) != 0 {
		t.Fatalf("a healthy install should not be refused: %v", r)
	}
	for _, c := range []struct {
		name   string
		mutate func(*UpgradePlan)
		want   string
	}{
		{"no data", func(p *UpgradePlan) { p.From = "" }, "nothing to upgrade"},
		{"data newer than fox", func(p *UpgradePlan) { p.From = "19" }, "update"},
		{"main stopped", func(p *UpgradePlan) { p.MainRunning = false }, "start"},
		{"HA on", func(p *UpgradePlan) { p.HA = true }, "ha disable"},
		{"failed over", func(p *UpgradePlan) { p.HA, p.FailedOver = true, true }, "ha failback"},
		{"earlier upgrade held", func(p *UpgradePlan) { p.HeldLot = "pre-upgrade-pg16" }, "--finalize"},
		{"mixed majors", func(p *UpgradePlan) { p.Majors["qa"] = "18" }, "qa (18)"},
		{"broken Blackbox", func(p *UpgradePlan) { p.LedgerErrors["qa"] = "row 7 edited" }, "Blackbox on qa does not verify"},
	} {
		p := healthyPlan()
		c.mutate(&p)
		r := strings.Join(p.Refusals(), "\n")
		if !strings.Contains(r, c.want) {
			t.Errorf("%s: refusal should mention %q, got %q", c.name, c.want, r)
		}
	}
	// A failover already says "failback"; it should not also say "disable".
	p := healthyPlan()
	p.HA, p.FailedOver = true, true
	if strings.Contains(strings.Join(p.Refusals(), "\n"), "ha disable") {
		t.Error("after a failover the way out is failback, not disable")
	}
}

// The warning is the product here: it must say what is lost and what is kept,
// and put the changes found in the user's own databases first.
func TestUpgradeRenderWarnsStrictly(t *testing.T) {
	p := healthyPlan()
	p.Applies["pg18-vacuum-inheritance"] = []string{"qa"}
	var out bytes.Buffer
	p.Render(&out)
	s := out.String()
	for _, want := range []string{
		"PostgreSQL 16 → 18",
		"offline",
		"Point-in-time restore cannot reach a moment before the upgrade",
		"--rollback", "--finalize",
		"not carried (agent branch)",
		"found in your databases",
		"[found in qa]",
		"https://www.postgresql.org/docs/18/release-18.html",
		"the Blackbox verifies on main, qa",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the plan should say %q:\n%s", want, s)
		}
	}
	first := strings.Index(s, "[found in qa]")
	generic := strings.Index(s, "'ago' is only accepted")
	if first < 0 || generic < 0 || first > generic {
		t.Error("a change found in the user's databases should be listed before the ones that were not")
	}

	p.HA = true
	out.Reset()
	p.Render(&out)
	if !strings.Contains(out.String(), "Refusing to upgrade") || strings.Contains(out.String(), "Before starting") {
		t.Error("a refused plan should say so, and not claim it is ready")
	}
}

func TestUpgradeRenderUpToDate(t *testing.T) {
	var out bytes.Buffer
	UpgradePlan{From: "18", To: "18"}.Render(&out)
	if !strings.Contains(out.String(), "Nothing to do") {
		t.Errorf("got %q", out.String())
	}
}

func TestRollbackRenderNamesWhatIsDeleted(t *testing.T) {
	var out bytes.Buffer
	RollbackPlan{Lot: "pre-upgrade-pg16", Restore: []string{"main", "qa"}, Replaces: []string{"main", "qa"}, Delete: []string{"made-after"}}.Render(&out)
	s := out.String()
	for _, want := range []string{"main, qa", "Deletes made-after", "no older copy"} {
		if !strings.Contains(s, want) {
			t.Errorf("rollback plan should say %q:\n%s", want, s)
		}
	}
}

func TestWrap(t *testing.T) {
	got := wrap("one two three four", 9, "  ")
	if got != "one two\n  three\n  four" {
		t.Errorf("got %q", got)
	}
	if wrap("", 10, "") != "" {
		t.Error("empty in, empty out")
	}
}

// Rollback deletes the upgraded branches; any made after the upgrade are
// clones of the new main, so main must go last.
func TestClonesFirst(t *testing.T) {
	got := strings.Join(clonesFirst([]string{"main", "qa", "after"}), ",")
	if got != "qa,after,main" {
		t.Errorf("got %s, want main last", got)
	}
}
