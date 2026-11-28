// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// Searching again (F4, Gate 1 step 5; design, section 15, "re-checked, not
// assumed"). The request keeps no value, so the branches are searched by the
// row keys it kept: a row it deleted must not be there, and a row it cleared
// must still hold what it was cleared to. A branch restored, or a row
// written back, shows here as an outcome lost.

// RecheckTable is one table searched again on one branch.
type RecheckTable struct {
	Schema string `json:"schema"`
	Table  string `json:"table"`
	Action string `json:"action"`
	Keys   int    `json:"keys"`  // row keys searched
	Found  int    `json:"found"` // rows that hold the person again
	Note   string `json:"note,omitempty"`
}

// RecheckBranch is one branch searched again.
type RecheckBranch struct {
	Branch string         `json:"branch"`
	Tables []RecheckTable `json:"tables"`
	Error  string         `json:"error,omitempty"`
}

// ErasureRecheck is what searching every branch again found.
type ErasureRecheck struct {
	Checked  time.Time       `json:"checked"`
	Branches []RecheckBranch `json:"branches"`
}

// Found counts the rows that hold the person again, everywhere.
func (r ErasureRecheck) Found() int {
	n := 0
	for _, b := range r.Branches {
		for _, t := range b.Tables {
			n += t.Found
		}
	}
	return n
}

// Failed lists the branches that could not be searched.
func (r ErasureRecheck) Failed() []string {
	var out []string
	for _, b := range r.Branches {
		if b.Error != "" {
			out = append(out, b.Branch+": "+b.Error)
		}
	}
	return out
}

// RecheckErasure searches main and every branch the request erased again,
// by its row keys, and reads the outcomes with what it found. The search is
// the engine's (Enterprise); the outcomes are free.
func RecheckErasure(s *auth.Store, v ErasureView) (ErasureOutcomes, error) {
	eng, err := erasureEngine()
	if err != nil {
		return ErasureOutcomes{}, err
	}
	if eng.Recheck == nil {
		return ErasureOutcomes{}, fmt.Errorf("this build's erasure engine cannot search again")
	}
	rc := &ErasureRecheck{Checked: time.Now().UTC(), Branches: []RecheckBranch{}}
	if v.Result != nil {
		each := func(name string, plan ErasurePlan, r *ErasureResult) {
			b := RecheckBranch{Branch: name, Tables: []RecheckTable{}}
			if _, err := EnsureRunning(name); err != nil {
				b.Error = err.Error()
			} else if ts, err := eng.Recheck(name, plan, r.Tables); err != nil {
				b.Error = err.Error()
			} else {
				b.Tables = ts
			}
			rc.Branches = append(rc.Branches, b)
		}
		each(v.Branch, v.Plan, v.Result)
		for _, b := range v.Branches {
			if b.Result == nil || b.Plan == nil {
				continue
			}
			if b.State == BranchGone || !activeStorage().exists(b.Branch) {
				continue // deleted since: nothing of it to search
			}
			each(b.Branch, *b.Plan, b.Result)
		}
	}
	o := ErasureOutcomesFor(s, v)
	o.Recheck = rc
	applyRecheck(&o, *rc)
	return o, nil
}

// applyRecheck marks the outcomes a search found lost.
func applyRecheck(o *ErasureOutcomes, rc ErasureRecheck) {
	for i := range o.Outcomes {
		x := &o.Outcomes[i]
		if x.Key != OutcomeLive {
			continue
		}
		var where []string
		for _, b := range rc.Branches {
			for _, t := range b.Tables {
				if t.Found > 0 {
					where = append(where, fmt.Sprintf("%d row(s) of %s.%s on %s", t.Found, t.Schema, t.Table, b.Branch))
				}
			}
		}
		if len(where) > 0 {
			x.State, x.Date = StateLost, nil
			x.Why = "searched again by the request's row keys, " + strings.Join(where, ", ") + " hold the person again: apply the erasure again (a restore past it?)"
		} else if f := rc.Failed(); len(f) > 0 {
			x.Evidence = append(x.Evidence, "Not searched again: "+strings.Join(f, "; "))
		} else {
			x.Evidence = append(x.Evidence, fmt.Sprintf("Searched again at %s by the request's row keys: none holds the person", day(rc.Checked)))
		}
	}
	// A lost outcome is a "never" until the erasure is applied again.
	settleClears(o)
}
