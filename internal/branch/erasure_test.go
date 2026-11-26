// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// fakeErasure stands in for enterprise/dpdp: values are recognised by a
// fixed rule, plans are whatever the test says, and applying records what it
// was asked.
type fakeErasure struct {
	plan     ErasurePlan
	fp       string
	applyFP  string // the fingerprint Apply finds; "" is the stored one
	applyErr error
	applied  []ErasureApply
	settled  int
	onBranch bool

	// The branches besides main, and what each is.
	branches  []BranchInfo
	parents   map[string]string
	made      map[string]time.Time
	gone      map[string]bool
	applyFPOn map[string]string // a branch's fingerprint at apply, when it differs
	appliedOn []string
	seeds     map[string]ErasureSeed // what each branch was planned or applied with
}

func (f *fakeErasure) install(t *testing.T) {
	t.Helper()
	if !edition.Enterprise {
		t.Skip("making and applying a request is Enterprise; go test -tags enterprise runs this")
	}
	edition.SetEntitlement(func(edition.Feature) bool { return true })
	old := erasure
	SetErasure(ErasureEngine{
		Refs: func(vs []ErasureValue) ([]ErasureRef, error) {
			out := []ErasureRef{}
			for _, v := range vs {
				if !strings.Contains(v.Value, "@") {
					return nil, ErrInvalidRequest
				}
				out = append(out, ErasureRef{Categories: []string{"email"}, Last4: v.Value[len(v.Value)-4:]})
			}
			return out, nil
		},
		Plan: func(b string, _ []ErasureValue, _ map[string]string, _ string, seed ErasureSeed) (ErasurePlan, string, ErasureSeed, error) {
			if f.seeds == nil {
				f.seeds = map[string]ErasureSeed{}
			}
			f.seeds["plan:"+b] = seed
			p := f.plan
			p.Branch = b
			fp := f.fp
			if b != "main" {
				fp = f.fp + "@" + b
			}
			return p, fp, ErasureSeed{"public.people": {`["1"]`}}, nil
		},
		Apply: func(b string, a ErasureApply) (ErasurePlan, string, ErasureResult, error) {
			f.applied = append(f.applied, a)
			f.appliedOn = append(f.appliedOn, b)
			if f.seeds == nil {
				f.seeds = map[string]ErasureSeed{}
			}
			f.seeds["apply:"+b] = a.Seed
			if now, ok := f.applyFPOn[b]; ok && now != a.Fingerprint {
				p := f.plan
				p.Branch = b
				return p, now, ErasureResult{}, ErrErasurePlanChanged
			}
			if b != "main" {
				return f.plan, a.Fingerprint, ErasureResult{Rows: 1, Verified: true, Applied: time.Now(),
					Tables:   []ErasureDone{{Schema: "public", Table: "people", Action: ErasureActClear, Rows: 1, Keys: []json.RawMessage{json.RawMessage(`["1"]`)}}},
					Rewrites: []ErasureRewrite{{Schema: "public", Table: "people", State: RewritePending}}}, nil
			}
			if f.applyFP != "" && f.applyFP != a.Fingerprint {
				p := f.plan
				p.Rows++
				return p, f.applyFP, ErasureResult{}, ErrErasurePlanChanged
			}
			if f.applyErr != nil {
				return f.plan, a.Fingerprint, ErasureResult{}, f.applyErr
			}
			return f.plan, a.Fingerprint, ErasureResult{Rows: f.plan.Rows, Verified: true, Applied: time.Now(),
				Tables:   []ErasureDone{{Schema: "public", Table: "people", Action: ErasureActClear, Rows: 1, Keys: []json.RawMessage{json.RawMessage(`["1"]`)}}},
				Rewrites: []ErasureRewrite{{Schema: "public", Table: "people", State: RewritePending}}}, nil
		},
		Settle: func(_ string, _ ErasurePlan, r ErasureResult, only []string) ErasureResult {
			f.settled++
			for i := range r.Rewrites {
				r.Rewrites[i].State = RewriteDone
			}
			now := time.Now()
			r.Vacuumed, r.Statistics = &now, &now
			return r
		},
		AppliedOn: func(string, string) (bool, error) { return f.onBranch, nil },
	})
	oldNames, oldParent, oldMade, oldWake, oldExists := erasureBranchNames, branchParentOf, branchMadeOf, wakeForErase, branchExistsF
	erasureBranchNames = func() ([]BranchInfo, error) {
		var out []BranchInfo
		for _, b := range f.branches {
			if !f.gone[b.Name] {
				out = append(out, b)
			}
		}
		return out, nil
	}
	branchParentOf = func(n string) string {
		if p, ok := f.parents[n]; ok {
			return p
		}
		return "main"
	}
	branchMadeOf = func(n string) (time.Time, bool) { t, ok := f.made[n]; return t, ok }
	wakeForErase = func(string) error { return nil }
	branchExistsF = func(n string) bool { return !f.gone[n] }
	t.Cleanup(func() {
		erasure = old
		edition.SetEntitlement(nil)
		erasureBranchNames, branchParentOf, branchMadeOf, wakeForErase, branchExistsF = oldNames, oldParent, oldMade, oldWake, oldExists
	})
}

func erasureStore(t *testing.T) *auth.Store {
	t.Helper()
	s, _ := requestStore(t)
	return s
}

var asha = []ErasureValue{{Category: "email", Value: "asha@example.com"}}

func TestErasureRequestLifecycle(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main", Rows: 3, Matched: 1, Refs: []ErasureRef{{Categories: []string{"email"}, Last4: ".com"}}}, fp: "fp1"}
	f.install(t)
	s := erasureStore(t)

	v, err := NewErasure(s, "main", asha, nil, "DPO-12", "admin@x")
	if err != nil {
		t.Fatal(err)
	}
	if v.State != auth.ErasurePlanned || v.Fingerprint != "fp1" || v.Plan.Rows != 3 || v.Note != "DPO-12" {
		t.Fatalf("new request: %+v", v)
	}
	// The store keeps no value: the request's record holds only the last four.
	rec, _ := s.Erasure(v.ID)
	for _, field := range []string{rec.Refs, rec.Plan, rec.Events, rec.Note} {
		if strings.Contains(field, "asha") {
			t.Fatalf("the store kept the value: %s", field)
		}
	}

	// Other values are not the request's.
	if _, err := ApplyErasure(s, v.ID, []ErasureValue{{Value: "ravi@example.org"}}, "admin@x"); !errors.Is(err, ErrErasureValues) {
		t.Fatalf("applied with another person's values: %v", err)
	}
	if len(f.applied) != 0 {
		t.Fatal("the engine was reached with the wrong values")
	}

	got, err := ApplyErasure(s, v.ID, asha, "admin@x")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != auth.ErasureApplied || got.Result == nil || !got.Result.Verified || got.Result.Vacuumed == nil ||
		got.Result.RewritesPending() != 0 || f.settled != 1 {
		t.Fatalf("applied: %+v %+v", got.ErasureRequest, got.Result)
	}
	if a := f.applied[0]; a.ID != v.ID || a.UID == "" || a.Fingerprint != "fp1" {
		t.Errorf("the engine was asked %+v", a)
	}
	// Applied once: a second apply, planning again and withdrawing are refused.
	if _, err := ApplyErasure(s, v.ID, asha, "admin@x"); !errors.Is(err, ErrErasureState) {
		t.Errorf("applied twice: %v", err)
	}
	// Planned again once applied, only the branches are: main's plan and its
	// fingerprint stay as they were applied.
	if again, err := ReplanErasure(s, v.ID, asha, "admin@x"); err != nil || again.State != auth.ErasureApplied || again.Fingerprint != "fp1" {
		t.Errorf("planned again once applied: %v %+v", err, again.ErasureRequest)
	}
	if _, err := WithdrawErasure(s, v.ID, "admin@x"); err == nil {
		t.Error("withdrew an applied request")
	}
	list, err := ListErasures(s)
	if err != nil || len(list) != 1 || list[0].ID != v.ID {
		t.Fatalf("list: %v %+v", err, list)
	}
}

// A plan that changed between showing it and applying it applies nothing:
// the new plan is kept, to be reviewed, and the next apply goes with it.
func TestErasureAppliesOnlyThePlanShown(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main", Rows: 1}, fp: "shown", applyFP: "now"}
	f.install(t)
	s := erasureStore(t)
	v, err := NewErasure(s, "main", asha, nil, "", "a@x")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ApplyErasure(s, v.ID, asha, "a@x")
	if !errors.Is(err, ErrErasurePlanChanged) {
		t.Fatalf("err = %v", err)
	}
	if got.State != auth.ErasurePlanned || got.Fingerprint != "now" || got.Plan.Rows != 2 || got.Result != nil {
		t.Fatalf("after the changed plan: %+v", got)
	}
	f.applyFP = "now"
	if got, err = ApplyErasure(s, v.ID, asha, "a@x"); err != nil || got.State != auth.ErasureApplied {
		t.Fatalf("the reviewed plan did not apply: %v %+v", err, got.ErasureRequest)
	}
}

// An apply that fails commits nothing and leaves the request planned.
func TestErasureFailedApplyIsReleased(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main", Rows: 1}, fp: "fp", applyErr: errors.New("clearing public.people: boom")}
	f.install(t)
	s := erasureStore(t)
	v, _ := NewErasure(s, "main", asha, nil, "", "a@x")
	if _, err := ApplyErasure(s, v.ID, asha, "a@x"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	if got, _ := GetErasure(s, v.ID); got.State != auth.ErasurePlanned {
		t.Fatalf("a failed apply left the request %s", got.State)
	}
}

// A plan with a problem is not applied, and the engine is not asked.
func TestErasureBlockedPlanIsNotApplied(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main", Blocked: true, Tables: []ErasureTable{{Schema: "public", Table: "people",
		Problems: []string{"phone is NOT NULL with no default, so it cannot be cleared"}}}}, fp: "fp"}
	f.install(t)
	s := erasureStore(t)
	v, _ := NewErasure(s, "main", asha, nil, "", "a@x")
	if _, err := ApplyErasure(s, v.ID, asha, "a@x"); !errors.Is(err, ErrErasureBlocked) || !strings.Contains(err.Error(), "public.people: phone") {
		t.Fatalf("err = %v", err)
	}
	if len(f.applied) != 0 {
		t.Fatal("a blocked plan reached the engine")
	}
}

// Two applies at once meet at the claim: the second is refused.
func TestErasureClaimIsOnce(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main"}, fp: "fp"}
	f.install(t)
	s := erasureStore(t)
	v, _ := NewErasure(s, "main", asha, nil, "", "a@x")
	if err := s.ClaimErasure(v.ID, "fp", "a@x"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimErasure(v.ID, "fp", "b@x"); !errors.Is(err, auth.ErrErasureMoved) {
		t.Fatalf("claimed twice: %v", err)
	}
	if err := s.ClaimErasure(v.ID+1, "fp", "b@x"); !errors.Is(err, auth.ErrNoErasure) {
		t.Fatalf("claimed a request that is not there: %v", err)
	}
}

// A request left applying by an engine that stopped is settled from the
// branch's own record.
func TestErasureLeftApplyingIsSettled(t *testing.T) {
	for _, on := range []bool{true, false} {
		erasureStuck = 15 * time.Minute
		f := &fakeErasure{plan: ErasurePlan{Branch: "main"}, fp: "fp", onBranch: on}
		f.install(t)
		s := erasureStore(t)
		v, _ := NewErasure(s, "main", asha, nil, "", "a@x")
		if err := s.ClaimErasure(v.ID, "fp", "a@x"); err != nil {
			t.Fatal(err)
		}
		// Still within the time an apply may take: read as it is.
		if got, _ := GetErasure(s, v.ID); got.State != auth.ErasureApplying {
			t.Fatalf("settled too soon: %s", got.State)
		}
		erasureStuck = 0
		t.Cleanup(func() { erasureStuck = 15 * time.Minute })
		got, err := GetErasure(s, v.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := auth.ErasurePlanned
		if on {
			want = auth.ErasureApplied
		}
		if got.State != want {
			t.Errorf("branch record %v: settled as %s, want %s", on, got.State, want)
		}
	}
}

// Making and applying are Enterprise; reading is not.
func TestErasureIsEnterpriseReadingIsFree(t *testing.T) {
	s := erasureStore(t)
	v, err := s.CreateErasure(auth.NewErasureRequest{Branch: "main", Refs: "[]", Events: "{}", Plan: `{"branch":"main"}`, Actor: "a@x"})
	if err != nil {
		t.Fatal(err)
	}
	edition.SetEntitlement(func(edition.Feature) bool { return false })
	t.Cleanup(func() { edition.SetEntitlement(nil) })
	if _, err := NewErasure(s, "main", asha, nil, "", "a@x"); !errors.Is(err, ErrNotLicensed) {
		t.Errorf("made without the licence: %v", err)
	}
	if _, err := ApplyErasure(s, v.ID, asha, "a@x"); !errors.Is(err, ErrNotLicensed) {
		t.Errorf("applied without the licence: %v", err)
	}
	if _, err := GetErasure(s, v.ID); err != nil {
		t.Errorf("reading needs the licence: %v", err)
	}
	if _, err := ListErasures(s); err != nil {
		t.Errorf("listing needs the licence: %v", err)
	}
}

func TestNewErasureRefuses(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main"}, fp: "fp"}
	f.install(t)
	s := erasureStore(t)
	for name, c := range map[string]struct {
		branch string
		values []ErasureValue
		events map[string]string
		note   string
	}{
		"another branch":     {"dev", asha, nil, ""},
		"no values":          {"main", nil, nil, ""},
		"an unknown event":   {"main", asha, map[string]string{"retired": "2025-01-01"}, ""},
		"a date that is not": {"main", asha, map[string]string{"account_closed": "31/03/2025"}, ""},
		"a long note":        {"main", asha, nil, strings.Repeat("x", 501)},
	} {
		if _, err := NewErasure(s, c.branch, c.values, c.events, c.note, "a@x"); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestParseErasureValue(t *testing.T) {
	for in, want := range map[string]ErasureValue{
		"email:Asha@Example.com":  {Category: "email", Value: "Asha@Example.com"},
		" mobile: 98765 43210 ":   {Category: "mobile", Value: "98765 43210"},
		"asha@example.com":        {Value: "asha@example.com"},
		"98765 43210":             {Value: "98765 43210"},
		"Email:asha@example.com":  {Value: "Email:asha@example.com"}, // a category is lower case
		"averyverylongword:value": {Value: "averyverylongword:value"},
	} {
		if got := ParseErasureValue(in); got != want {
			t.Errorf("%q: %+v, want %+v", in, got, want)
		}
	}
}

func TestSameRefs(t *testing.T) {
	a := []ErasureRef{{Categories: []string{"mobile"}, Last4: "3210"}, {Categories: []string{"upi", "email"}, Last4: ".com"}}
	b := []ErasureRef{{Categories: []string{"email", "upi"}, Last4: ".com"}, {Categories: []string{"mobile"}, Last4: "3210"}}
	if !SameRefs(a, b) {
		t.Error("the same values in another order are not the same")
	}
	if SameRefs(a, b[:1]) || SameRefs(a, []ErasureRef{a[0], {Categories: []string{"email"}, Last4: ".org"}}) {
		t.Error("different values read as the same")
	}
}

// An entry says what an erasure does to its rows: clear (the default) or
// delete, the table's; and what a column is cleared to, the column's.
func TestCheckDPDPEntryErasure(t *testing.T) {
	e, err := CheckDPDPEntry(goodEntry())
	if err != nil || e.OnErasure != EraseClear {
		t.Fatalf("the default is not clear: %q %v", e.OnErasure, err)
	}
	d := goodEntry()
	d.OnErasure = " delete "
	if e, err := CheckDPDPEntry(d); err != nil || e.OnErasure != EraseDelete {
		t.Fatalf("delete: %q %v", e.OnErasure, err)
	}
	to := "erased"
	for name, change := range map[string]func(*DPDPEntry){
		"another action":          func(e *DPDPEntry) { e.OnErasure = "shred" },
		"a column deleting":       func(e *DPDPEntry) { e.Column = "email"; e.OnErasure = EraseDelete },
		"a table's clear-to":      func(e *DPDPEntry) { e.ClearTo = &to },
		"a clear-to far too long": func(e *DPDPEntry) { e.Column = "email"; long := strings.Repeat("x", 201); e.ClearTo = &long },
	} {
		x := goodEntry()
		change(&x)
		if _, err := CheckDPDPEntry(x); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	c := goodEntry()
	c.Column, c.ClearTo = "phone", &to
	if e, err := CheckDPDPEntry(c); err != nil || e.ClearTo == nil || *e.ClearTo != "erased" {
		t.Errorf("a column's clear-to: %v %v", e.ClearTo, err)
	}
}

func TestErasureCell(t *testing.T) {
	to := "erased"
	del := &DPDPEntry{OnErasure: EraseDelete}
	if got := erasureCell(nil, nil); got != "clear" {
		t.Errorf("no entry: %q", got)
	}
	if got := erasureCell(del, &DPDPEntry{ClearTo: &to}); got != "delete" {
		t.Errorf("a deleting table: %q", got)
	}
	if got := erasureCell(&DPDPEntry{OnErasure: EraseClear}, &DPDPEntry{ClearTo: &to}); got != "clear to erased" {
		t.Errorf("a column with a placeholder: %q", got)
	}
}

// A plan as the store keeps it reads back the same, and its summary is
// counts, never a value.
func TestErasurePlanRoundTrip(t *testing.T) {
	p := ErasurePlan{Branch: "main", Refs: []ErasureRef{{Categories: []string{"email"}, Last4: ".com"}}, Matched: 1, Rows: 4,
		Tables: []ErasureTable{{Schema: "public", Table: "people", Rows: 1, Action: ErasureActClear},
			{Schema: "public", Table: "orders", Rows: 3, Action: ErasureActKeep}}}
	raw, _ := json.Marshal(p)
	v, err := ViewErasure(auth.ErasureRequest{ID: 1, Refs: `[{"categories":["email"],"last4":".com"}]`, Plan: string(raw), Result: "{}"})
	if err != nil || v.Plan.Rows != 4 || len(v.Refs) != 1 || v.Result != nil {
		t.Fatalf("%v %+v", err, v)
	}
	if s := p.Summary(); s != "main: 1 value(s); 1 row(s) matched, 4 changed in 1 table(s)" {
		t.Errorf("summary = %q", s)
	}
}

// The free side holds no SQL of its own for erasing: what changes rows is in
// enterprise/dpdp, behind the licence.
func TestErasureChangesNothingOnTheFreeSide(t *testing.T) {
	src, err := os.ReadFile("erasure.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"UPDATE ", "DELETE FROM", "VACUUM"} {
		if strings.Contains(string(src), w) {
			t.Errorf("internal/branch/erasure.go runs %q", w)
		}
	}
}

// One apply erases main, then every branch, each matched again there; a
// branch whose plan changed is skipped, and applied on its own afterwards.
func TestErasureAppliesEveryBranch(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main", Rows: 1}, fp: "fp",
		branches:  []BranchInfo{{Name: "dev", State: "running"}, {Name: "qa", State: "exited"}, {Name: "mask", Masked: MaskedOpen}, {Name: "mk", Masked: MaskedMaking}},
		applyFPOn: map[string]string{"qa": "changed"}}
	f.install(t)
	s := erasureStore(t)
	v, err := NewErasure(s, "main", asha, nil, "", "a@x")
	if err != nil {
		t.Fatal(err)
	}
	states := func(v ErasureView) map[string]string {
		out := map[string]string{}
		for _, b := range v.Branches {
			out[b.Branch] = b.State
		}
		return out
	}
	if got := states(v); got["dev"] != BranchPlanned || got["qa"] != BranchPlanned || got["mask"] != BranchPlanned || got["mk"] != BranchListed {
		t.Fatalf("planned: %v", got)
	}
	// The masked branch is planned from main's rows by key; the others by value only.
	if f.seeds["plan:mask"] == nil || f.seeds["plan:dev"] != nil {
		t.Errorf("seeds: %v", f.seeds)
	}
	got, err := ApplyErasure(s, v.ID, asha, "a@x")
	if err != nil {
		t.Fatal(err)
	}
	st := states(got)
	if got.State != auth.ErasureApplied || st["dev"] != BranchApplied || st["mask"] != BranchApplied || st["qa"] != BranchSkipped || st["mk"] != BranchListed {
		t.Fatalf("applied: %v", st)
	}
	if strings.Join(f.appliedOn, ",") != "main,dev,qa,mask" {
		t.Errorf("applied in the order %v", f.appliedOn)
	}
	if seed := f.seeds["apply:mask"]; len(seed["public.people"]) != 1 {
		t.Errorf("the masked branch was not applied by main's keys: %v", seed)
	}
	if got.BranchesLeft() != 2 {
		t.Errorf("left = %d, want qa and mk", got.BranchesLeft())
	}
	// qa's new plan is kept; applied on its own with it.
	f.applyFPOn = nil
	if _, err := ApplyErasureBranch(s, v.ID, "dev", asha, "a@x"); !errors.Is(err, ErrErasureState) {
		t.Errorf("applied to dev twice: %v", err)
	}
	if _, err := ApplyErasureBranch(s, v.ID, "nowhere", asha, "a@x"); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("applied to a branch not in the request: %v", err)
	}
	f.applyFPOn = map[string]string{"qa": "changed"}
	got, err = ApplyErasureBranch(s, v.ID, "qa", asha, "a@x")
	if err != nil || states(got)["qa"] != BranchApplied {
		t.Fatalf("qa on its own: %v %v", err, states(got))
	}
}

// Main first, and alone: a branch is never erased by a request main's apply
// did not get through.
func TestErasureBranchesWaitForMain(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main"}, fp: "fp", applyErr: errors.New("boom"),
		branches: []BranchInfo{{Name: "dev"}}}
	f.install(t)
	s := erasureStore(t)
	v, _ := NewErasure(s, "main", asha, nil, "", "a@x")
	if _, err := ApplyErasure(s, v.ID, asha, "a@x"); err == nil {
		t.Fatal("applied")
	}
	if strings.Join(f.appliedOn, ",") != "main" {
		t.Errorf("a branch was reached after main failed: %v", f.appliedOn)
	}
	if _, err := ApplyErasureBranch(s, v.ID, "dev", asha, "a@x"); !errors.Is(err, ErrErasureState) {
		t.Errorf("a branch applied before main: %v", err)
	}
}

// A branch made before its parent's erasure finished keeps the person in its
// origin snapshot, however it was erased; one made after it from main does not.
func TestErasureListsBranchesMadeBefore(t *testing.T) {
	long := time.Now().Add(-30 * 24 * time.Hour)
	f := &fakeErasure{plan: ErasurePlan{Branch: "main", Rows: 1}, fp: "fp",
		branches: []BranchInfo{{Name: "old"}, {Name: "kid"}},
		parents:  map[string]string{"kid": "old"},
		made:     map[string]time.Time{"old": long, "kid": long.Add(time.Hour)}}
	f.install(t)
	s := erasureStore(t)
	v, _ := NewErasure(s, "main", asha, nil, "", "a@x")
	if len(v.MadeBefore) != 0 {
		t.Fatalf("a planned request lists branches: %+v", v.MadeBefore)
	}
	got, err := ApplyErasure(s, v.ID, asha, "a@x")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, m := range got.MadeBefore {
		names = append(names, m.Branch+":"+m.Parent)
	}
	if strings.Join(names, ",") != "kid:old,old:main" {
		t.Fatalf("made before: %v", got.MadeBefore)
	}
	// A branch made from main after it finished holds none of the person, and
	// is not listed, nor taken for one made since the plan.
	f.branches = append(f.branches, BranchInfo{Name: "fresh"})
	f.made["fresh"] = time.Now().Add(time.Hour)
	again, _ := GetErasure(s, v.ID)
	for _, m := range again.MadeBefore {
		if m.Branch == "fresh" {
			t.Errorf("a branch made after the erasure is listed: %+v", m)
		}
	}
	// Remade from the request: recorded, and no longer listed once made anew.
	remade := false
	oldReset := resetForErase
	resetForErase = func(name, parent string) error {
		remade = name == "old" && parent == "main"
		f.made["old"] = time.Now().Add(2 * time.Hour) // made anew
		return nil
	}
	t.Cleanup(func() { resetForErase = oldReset })
	after, err := RemakeErasureBranch(s, v.ID, "old", "dpo@x")
	if err != nil || !remade {
		t.Fatalf("remake: %v %v", err, remade)
	}
	for _, m := range after.MadeBefore {
		if m.Branch == "old" {
			t.Errorf("old is still listed after it was remade: %+v", m)
		}
	}
	for _, b := range after.Branches {
		if b.Branch == "old" && (b.Done != "remade" || b.DoneBy != "dpo@x") {
			t.Errorf("the remake was not recorded: %+v", b)
		}
	}
	if _, err := RemakeErasureBranch(s, v.ID, "fresh", "dpo@x"); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("remade a branch the request does not list: %v", err)
	}
}

func TestBranchMaxAge(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "off": 0, "0": 0, "90d": 90 * 24 * time.Hour, "2w": 14 * 24 * time.Hour,
		"720h": 720 * time.Hour, "soon": 0, "-3d": 0} {
		if got := parseAge(in); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}

// A copy waits for its parent's erasure; the erasing lock is not a branch's.
func TestErasingLockIsNoBranchsLock(t *testing.T) {
	if err := checkName(erasingLock("main")); err == nil {
		t.Error("the erasing lock's name is a branch name, and could be one's lock")
	}
	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = withErasingLock("main", func() error { close(held); <-release; return nil })
	}()
	<-held
	got := make(chan error, 1)
	go func() {
		unlock, err := lockBranch(erasingLock("main"), "copied")
		if err == nil {
			unlock()
		}
		got <- err
	}()
	select {
	case <-got:
		t.Fatal("a copy did not wait for the erasure")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-got; err != nil {
		t.Fatal(err)
	}
}

// A parent whose erasure changed nothing never held the person: the branches
// made from it before then are not listed on its account.
func TestErasureListsNothingFromAParentThatChangedNothing(t *testing.T) {
	long := time.Now().Add(-30 * 24 * time.Hour)
	f := &fakeErasure{plan: ErasurePlan{Branch: "main"}, fp: "fp",
		branches: []BranchInfo{{Name: "old"}, {Name: "kid"}},
		parents:  map[string]string{"kid": "old"},
		made:     map[string]time.Time{"old": long, "kid": long.Add(time.Hour)}}
	f.install(t)
	s := erasureStore(t)
	v, _ := NewErasure(s, "main", asha, nil, "", "a@x")
	got, err := ApplyErasure(s, v.ID, asha, "a@x")
	if err != nil {
		t.Fatal(err)
	}
	// main changed nothing; old (a branch) changed a row, so kid, made from
	// it before then, still holds the person; old itself does not.
	names := []string{}
	for _, m := range got.MadeBefore {
		names = append(names, m.Branch)
	}
	if strings.Join(names, ",") != "kid" {
		t.Fatalf("made before: %+v", got.MadeBefore)
	}
}
