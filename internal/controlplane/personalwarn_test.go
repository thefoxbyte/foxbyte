// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"strings"
	"sync"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// The branch list carries the unmasked-personal-data badge for the branches
// whose readers see real values, judged as the caller reads them (an agent's
// branch as its agent does), and never wakes a suspended branch to decide.
func TestBranchListBadge(t *testing.T) {
	old := branchExposure
	t.Cleanup(func() { branchExposure = old })
	var mu sync.Mutex
	asked := map[string]string{}
	branchExposure = func(name, account string) (branch.UnmaskedSummary, error) {
		mu.Lock()
		asked[name] = account
		mu.Unlock()
		s := branch.UnmaskedSummary{Branch: name, Scanned: true}
		if name != "clean" {
			s.Columns, s.ByCategory, s.Examples = 2, map[string]int{"aadhaar": 2}, []string{"customers.aadhaar", "leads.aadhaar"}
		}
		return s, nil
	}
	rows := withPersonalData([]branch.BranchInfo{
		{Name: "main", Primary: true, State: "running"},
		{Name: "agent-a", Agent: true, State: "running"},
		{Name: "clean", State: "running"},
		{Name: "asleep", State: "exited"},
	}, "alice@x.com")
	by := map[string]branchRow{}
	for _, r := range rows {
		by[r.Name] = r
	}
	if p := by["main"].PersonalData; p == nil || p.Unmasked != 2 || !strings.Contains(p.Summary, "2 Aadhaar columns") ||
		!strings.Contains(p.Summary, "people using it see real values") {
		t.Errorf("main: %+v", p)
	}
	if p := by["agent-a"].PersonalData; p == nil || !strings.Contains(p.Summary, "agents using it see real values") {
		t.Errorf("agent-a: %+v", p)
	}
	if by["clean"].PersonalData != nil || by["asleep"].PersonalData != nil {
		t.Errorf("a badge where none belongs: clean %+v, asleep %+v", by["clean"].PersonalData, by["asleep"].PersonalData)
	}
	if asked["main"] != "alice@x.com" || asked["agent-a"] != "" {
		t.Errorf("judged as %v", asked)
	}
	if _, ok := asked["asleep"]; ok {
		t.Error("a suspended branch was read for its badge")
	}
}
