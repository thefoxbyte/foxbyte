// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func exposed(name string, cols map[string]int) branch.UnmaskedSummary {
	n := 0
	for _, c := range cols {
		n += c
	}
	return branch.UnmaskedSummary{Branch: name, Scanned: true, Columns: n, ByCategory: cols, Examples: []string{"customers.aadhaar"}}
}

// `fox check` names the branches that hand real personal data to an agent or
// a non-admin account, and the ones with agents on them nobody has scanned. A
// warning, never a failure: unmasked is the default, not a fault.
func TestPersonalDataLine(t *testing.T) {
	t.Run("nothing reaches anyone unmasked", func(t *testing.T) {
		got := personalDataLine([]piiReach{
			{Branch: "main", Summary: branch.UnmaskedSummary{Scanned: true}},
			// Unmasked, but only admins read it: not this line's business.
			{Branch: "admin-dev", Summary: exposed("admin-dev", map[string]int{"email": 1})},
			// Never scanned, but no agent on it.
			{Branch: "qa", Summary: branch.UnmaskedSummary{}},
		}, true)
		if got.state != stateOK {
			t.Errorf("state %d (%s), want ok", got.state, got.detail)
		}
	})

	t.Run("exposed and never scanned are both named", func(t *testing.T) {
		got := personalDataLine([]piiReach{
			{Branch: "main", Accounts: 3, Agents: true, Summary: exposed("main", map[string]int{"aadhaar": 3, "email": 2})},
			{Branch: "agent-b", Agents: true, Summary: branch.UnmaskedSummary{}},
			{Branch: "alice-dev", Accounts: 1, Summary: exposed("alice-dev", map[string]int{"pan": 1})},
		}, true)
		if got.state != stateWarn {
			t.Fatalf("state %d, want a warning, never a failure", got.state)
		}
		for _, want := range []string{
			"main (3 Aadhaar columns, 2 email columns, read unmasked by agents and 3 non-admin accounts)",
			"alice-dev (1 PAN column, read unmasked by 1 non-admin account)",
			"never scanned, with agents on it: agent-b",
			"unmasked by default",
		} {
			if !strings.Contains(got.detail, want) {
				t.Errorf("detail %q does not say %q", got.detail, want)
			}
		}
		if !strings.Contains(got.fix, "mask rule") || !strings.Contains(got.fix, "mask account") {
			t.Errorf("fix %q does not name the commands", got.fix)
		}
	})

	t.Run("standard says masking needs Enterprise", func(t *testing.T) {
		got := personalDataLine([]piiReach{{Branch: "agent-a", Agents: true, Summary: exposed("agent-a", map[string]int{"email": 1})}}, false)
		if got.state != stateWarn || !strings.Contains(got.fix, "need FoxByte Enterprise") || strings.Contains(got.fix, "mask rule") {
			t.Errorf("standard: %+v", got)
		}
	})
}

// `fox branch create` prints the engine's warning after the connection line,
// and nothing when there is nothing to say.
func TestBranchCreateWarns(t *testing.T) {
	old := branchWarnings
	t.Cleanup(func() { branchWarnings = old })
	want := exposed("qa", map[string]int{"aadhaar": 1}).Warning("people and agents given its connection string", "")
	branchWarnings = func(name, account, who, owner string) []string {
		if name != "qa" || account != "" {
			return nil
		}
		return []string{exposed(name, map[string]int{"aadhaar": 1}).Warning(who, owner)}
	}
	var b bytes.Buffer
	printPersonalDataWarnings(&b, "qa")
	if got := b.String(); got != "\nWarning: "+want+"\n" {
		t.Errorf("printed %q", got)
	}
	if !strings.Contains(want, "1 Aadhaar column (customers.aadhaar); people and agents given its connection string see real values") {
		t.Errorf("the warning reads %q", want)
	}
	b.Reset()
	printPersonalDataWarnings(&b, "empty")
	if b.Len() != 0 {
		t.Errorf("printed %q for a branch with nothing to warn about", b.String())
	}
}
