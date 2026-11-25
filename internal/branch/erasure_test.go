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
		Plan: func(string, []ErasureValue, map[string]string, string) (ErasurePlan, string, error) {
			return f.plan, f.fp, nil
		},
		Apply: func(_ string, a ErasureApply) (ErasurePlan, string, ErasureResult, error) {
			f.applied = append(f.applied, a)
			if f.applyFP != "" && f.applyFP != a.Fingerprint {
				p := f.plan
				p.Rows++
				return p, f.applyFP, ErasureResult{}, ErrErasurePlanChanged
			}
			if f.applyErr != nil {
				return f.plan, a.Fingerprint, ErasureResult{}, f.applyErr
			}
			return f.plan, a.Fingerprint, ErasureResult{Rows: f.plan.Rows, Verified: true,
				Rewrites: []ErasureRewrite{{Schema: "public", Table: "people", State: RewritePending}}}, nil
		},
		Settle: func(_ string, _ ErasurePlan, r ErasureResult, only []string) ErasureResult {
			f.settled++
			for i := range r.Rewrites {
				r.Rewrites[i].State = RewriteDone
			}
			now := time.Now()
			r.Vacuumed = &now
			return r
		},
		AppliedOn: func(string, string) (bool, error) { return f.onBranch, nil },
	})
	t.Cleanup(func() { erasure = old; edition.SetEntitlement(nil) })
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
	if _, err := ReplanErasure(s, v.ID, asha, "admin@x"); !errors.Is(err, ErrErasureState) {
		t.Errorf("planned again once applied: %v", err)
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
