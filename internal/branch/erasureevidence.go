// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/version"
)

// An erasure request's evidence (F4, Gate 1 step 5; design, section 15):
// one document an auditor is handed, saying what was erased where, by whom
// and when, each outcome with its date and what it rests on, the one "clears
// on" date, and what FoxByte cannot reach. Like the request, it keeps no
// value: the values' last four characters, and counts. The row keys identify
// the person, so they are in it only when an admin asks (decided 27 November
// 2026), and the security log says they were.

// ErasureEvidenceFormat names the document.
const ErasureEvidenceFormat = "erasure-evidence/1"

// ErasureEvidenceTable is what the request did to one table on one branch.
type ErasureEvidenceTable struct {
	Schema string            `json:"schema"`
	Table  string            `json:"table"`
	Action string            `json:"action"`
	Rows   int               `json:"rows"`
	Keys   []json.RawMessage `json:"keys,omitempty"` // only with the admin's asking
}

// ErasureEvidenceBranch is one branch the request reached.
type ErasureEvidenceBranch struct {
	Branch  string                 `json:"branch"`
	State   string                 `json:"state"`
	Applied *time.Time             `json:"applied,omitempty"`
	By      string                 `json:"by,omitempty"`
	Rows    int                    `json:"rows"`
	Tables  []ErasureEvidenceTable `json:"tables"`
	Why     string                 `json:"why,omitempty"`
}

// ErasureEvidence is the document.
type ErasureEvidence struct {
	Format    string `json:"format"`
	Generated string `json:"generated"`
	By        string `json:"by"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Edition   string `json:"edition"`

	Request struct {
		ID        int64        `json:"id"`
		State     string       `json:"state"`
		Branch    string       `json:"branch"`
		Note      string       `json:"note,omitempty"`
		Created   time.Time    `json:"created"`
		CreatedBy string       `json:"createdBy"`
		Values    []ErasureRef `json:"values"` // categories and last four characters
	} `json:"request"`
	Branches []ErasureEvidenceBranch `json:"branches"`
	Outcomes ErasureOutcomes         `json:"outcomes"`
	Restores []auth.ErasureRestore   `json:"restores"`
	// Keys says whether the row keys are in the document.
	Keys   bool     `json:"keys"`
	Limits []string `json:"limits"`
}

// ErasureEvidenceOptions are what the evidence is asked for with.
type ErasureEvidenceOptions struct {
	Keys bool
	By   string
}

// ErasureEvidenceFor produces a request's evidence, reading its outcomes now.
// Where this edition can search the branches again, it does, and the
// outcomes say what it found; where it cannot, the evidence says so. Free.
func ErasureEvidenceFor(s *auth.Store, id int64, o ErasureEvidenceOptions) (*ErasureEvidence, error) {
	v, err := GetErasure(s, id)
	if err != nil {
		return nil, err
	}
	ev := &ErasureEvidence{Format: ErasureEvidenceFormat, Generated: time.Now().UTC().Format(time.RFC3339), By: o.By,
		Product: brand.Product, Version: version.Version, Edition: edition.Name(), Keys: o.Keys,
		Branches: []ErasureEvidenceBranch{}, Restores: v.Restores, Limits: []string{}}
	if ev.Restores == nil {
		ev.Restores = []auth.ErasureRestore{}
	}
	ev.Request.ID, ev.Request.State, ev.Request.Branch, ev.Request.Note = v.ID, v.State, v.Branch, v.Note
	ev.Request.Created, ev.Request.CreatedBy, ev.Request.Values = v.Created, v.CreatedBy, v.Refs
	ev.Branches = append(ev.Branches, evidenceBranch(v.Branch, v.State, v.Result, "", o.Keys))
	for _, b := range v.Branches {
		ev.Branches = append(ev.Branches, evidenceBranch(b.Branch, b.State, b.Result, b.Why, o.Keys))
	}
	if v.Result != nil {
		if rc, err := RecheckErasure(s, v); err == nil {
			ev.Outcomes = rc
		} else {
			ev.Outcomes = ErasureOutcomesFor(s, v)
			ev.Outcomes.Notes = append(ev.Outcomes.Notes, "The branches were not searched again: "+err.Error())
		}
	} else {
		ev.Outcomes = ErasureOutcomesFor(s, v)
	}
	ev.Limits = append(ev.Limits, v.Plan.Limits...)
	ev.Limits = append(ev.Limits,
		"The outcomes are read when the evidence is made: a branch restored or remade, a backup pruned or a target changed since shows in the next one.",
		"The backups' date is reckoned from the backup interval and the number kept; it is met once the oldest backup kept started after the last rewrite.",
		ErasureReview)
	if o.Keys {
		s.Audit(auth.EvErasureEvidence, o.By, v.Branch, "", fmt.Sprintf("request #%d's evidence produced, with the row keys", v.ID))
	} else {
		s.Audit(auth.EvErasureEvidence, o.By, v.Branch, "", fmt.Sprintf("request #%d's evidence produced, counts only", v.ID))
	}
	return ev, nil
}

func evidenceBranch(name, state string, r *ErasureResult, why string, keys bool) ErasureEvidenceBranch {
	b := ErasureEvidenceBranch{Branch: name, State: state, Tables: []ErasureEvidenceTable{}, Why: why}
	if r == nil {
		return b
	}
	b.Applied, b.By, b.Rows = atTime(r.Applied), r.By, r.Rows
	for _, d := range r.Tables {
		t := ErasureEvidenceTable{Schema: d.Schema, Table: d.Table, Action: d.Action, Rows: d.Rows}
		if keys {
			t.Keys = d.Keys
		}
		b.Tables = append(b.Tables, t)
	}
	return b
}
