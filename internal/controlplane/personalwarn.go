// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"sync"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/safego"
)

// Unmasked personal data in the console (PRIV-1). Branches are unmasked by
// default, and the console is where most branches are made and handed on, so
// it says so twice: a warning in the answer to creating one, and a badge in
// the branch list on every branch whose confirmed personal data its readers
// see as real values. Neither refuses anything; masking stays opt-in.

// branchExposure is the engine's judgement, as a variable so the tests need no
// database.
var branchExposure = branch.UnmaskedPersonalData

// personalBadge is what the branch list carries for the badge.
type personalBadge struct {
	Unmasked int `json:"unmasked"` // confirmed personal-data columns read as real values
	// Summary is the warning sentence, for the badge's title.
	Summary string `json:"summary"`
}

// branchRow is a branch as the list sends it.
type branchRow struct {
	branch.BranchInfo
	PersonalData *personalBadge `json:"personalData,omitempty"`
}

// readerOf is whose view of a branch the badge shows. An agent's branch is
// read by the agent's own role, which no account masking applies to; any
// other branch, as the person looking at the list reads it.
func readerOf(b branch.BranchInfo, email string) string {
	if b.Agent {
		return ""
	}
	return email
}

// withPersonalData adds the badge to each running branch that needs it. A
// branch not running is not woken for a badge, and a branch whose records
// cannot be read gets none: the list must never fail for it. A few at a time,
// as the records are read with one psql each (and then cached briefly).
func withPersonalData(bs []branch.BranchInfo, email string) []branchRow {
	out := make([]branchRow, len(bs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, b := range bs {
		out[i].BranchInfo = b
		if b.State != "running" || b.Masked == "making" || b.Masked == "failed" {
			continue
		}
		wg.Add(1)
		// In Go's recover wrapper: a panic reading one branch's records costs
		// that branch its badge, never the control plane.
		safego.Go("branch list badge", func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s, err := branchExposure(b.Name, readerOf(b, email))
			if err != nil || !s.Exposed() {
				return
			}
			who := "people using it"
			if b.Agent {
				who = "agents using it"
			}
			out[i].PersonalData = &personalBadge{Unmasked: s.Columns, Summary: s.Warning(who, email)}
		})
	}
	wg.Wait()
	return out
}
