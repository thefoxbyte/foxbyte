// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// A request applied on main, as the fake engine applies one.
func appliedRequest(t *testing.T) (*fakeErasure, *auth.Store, ErasureView) {
	t.Helper()
	f := &fakeErasure{plan: ErasurePlan{Branch: "main", Rows: 1, Matched: 1, Refs: []ErasureRef{{Categories: []string{"email"}, Last4: ".com"}}}, fp: "fp1"}
	f.install(t)
	s := erasureStore(t)
	v, err := NewErasure(s, "main", asha, nil, "DPO-7", "admin@x")
	if err != nil {
		t.Fatal(err)
	}
	if v, err = ApplyErasure(s, v.ID, asha, "admin@x"); err != nil || v.State != auth.ErasureApplied {
		t.Fatalf("apply: %v %+v", err, v)
	}
	dir := t.TempDir()
	oldPath := reapplyingPath
	reapplyingPath = func() string { return filepath.Join(dir, "erasure-reapplying.json") }
	t.Cleanup(func() { reapplyingPath = oldPath })
	return f, s, v
}

func TestRestorePastAnErasureIsRefusedSayingHow(t *testing.T) {
	_, s, v := appliedRequest(t)
	before, after := v.Result.Applied.Add(-time.Hour), time.Now().Add(time.Hour)

	_, err := guardRestoreWith(s, "restore", "main", before, "an hour before", AfterErasure{})
	if !errors.Is(err, ErrErasureRestore) || !strings.Contains(err.Error(), "--after-erasure reapply") ||
		!strings.Contains(err.Error(), "#1") || !strings.Contains(err.Error(), "Nothing was restored") {
		t.Fatalf("a copy from before the erasure: %v", err)
	}
	if g, err := guardRestoreWith(s, "restore", "main", after, "now", AfterErasure{}); g != nil || err != nil {
		t.Fatalf("a copy from after it undoes nothing: %v %v", g, err)
	}
	// A time not known is before every erasure.
	if _, err := guardRestoreWith(s, "pg rollback", "main", time.Time{}, "before the upgrade", AfterErasure{}); !errors.Is(err, ErrErasureRestore) {
		t.Fatalf("a copy of no known time: %v", err)
	}
	// The decision needs a reason, recorded on each request.
	if _, err := guardRestoreWith(s, "restore", "main", before, "x", AfterErasure{Reapply: true, Actor: "admin@x"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("no reason: %v", err)
	}
	g, err := guardRestoreWith(s, "restore", "main", before, "x", AfterErasure{Reapply: true, Reason: "incident 9", Actor: "admin@x"})
	if err != nil || g == nil || g.requests() != "#1" {
		t.Fatalf("with the decision: %v %+v", err, g)
	}
}

func TestRestorePastAnErasureNeedsEnterpriseToReapply(t *testing.T) {
	_, s, v := appliedRequest(t)
	edition.SetEntitlement(func(edition.Feature) bool { return false }) // the subscription ended
	_, err := guardRestoreWith(s, "restore", "main", v.Result.Applied.Add(-time.Minute), "x",
		AfterErasure{Reapply: true, Reason: "incident 9", Actor: "admin@x"})
	if !errors.Is(err, ErrErasureRestore) || !strings.Contains(err.Error(), "needs FoxByte Enterprise") || !strings.Contains(err.Error(), "Nothing was restored") {
		t.Fatalf("without Enterprise the restore is refused, saying why: %v", err)
	}
}

func TestRestoredBranchIsClosedUntilTheErasureIsAppliedAgain(t *testing.T) {
	_, s, v := appliedRequest(t)
	var got []ErasureReapply
	var on []string
	erasure.Reapply = func(target string, a ErasureReapply) (ErasureResult, error) {
		got, on = append(got, a), append(on, target)
		// Closed while it runs: no way in reaches it.
		if err := checkBranchOpen(target); !errors.Is(err, ErrBranchClosed) {
			t.Errorf("the copy was open during the re-apply: %v", err)
		}
		return ErasureResult{Rows: 1, Applied: time.Now(), Tables: a.Done,
			Rewrites: []ErasureRewrite{{Schema: "public", Table: "people", State: RewritePending}}}, nil
	}
	g, err := guardRestoreWith(s, "branch-before", "main", v.Result.Applied.Add(-time.Minute), "just before entry 40",
		AfterErasure{Reapply: true, Reason: "incident 9", Actor: "admin@x"})
	if err != nil || g == nil {
		t.Fatal(err)
	}
	if err := g.open("main-before-40", true); err != nil {
		t.Fatal(err)
	}
	if err := checkBranchOpen("main-before-40"); !errors.Is(err, ErrBranchClosed) || !strings.Contains(err.Error(), "#1") {
		t.Fatalf("not closed: %v", err)
	}
	done, err := g.reapply()
	if err != nil || len(done) != 1 || done[0].Keys != "main" || !done[0].Blackbox {
		t.Fatalf("reapply: %v %+v", err, done)
	}
	if len(got) != 1 || on[0] != "main-before-40" || len(got[0].Done) != 1 || string(got[0].Done[0].Keys[0]) != `["1"]` || got[0].UID != v.UID {
		t.Fatalf("the engine was asked: %v %+v", on, got)
	}
	if done[0].Result.Rewrites[0].State != RewriteDone {
		t.Fatalf("the copy's tables were not rewritten: %+v", done[0].Result.Rewrites)
	}
	if err := checkBranchOpen("main-before-40"); err != nil {
		t.Fatalf("still closed once applied: %v", err)
	}
	// The request shows the restore, who decided, why, and what it did.
	nv, err := GetErasure(s, v.ID)
	if err != nil || len(nv.Restores) != 1 {
		t.Fatalf("restores: %v %+v", err, nv.Restores)
	}
	r := nv.Restores[0]
	if r.State != auth.RestoreDone || r.Door != "branch-before" || r.Target != "main-before-40" || r.By != "admin@x" || r.Reason != "incident 9" {
		t.Fatalf("the restore's record: %+v", r)
	}
	var d ReapplyDone
	if err := json.Unmarshal([]byte(r.Detail), &d); err != nil || d.Result.Rows != 1 {
		t.Fatalf("its detail: %v %s", err, r.Detail)
	}
	// It keeps no value.
	if strings.Contains(r.Detail, "asha") {
		t.Fatalf("the record kept the value: %s", r.Detail)
	}
}

func TestFailedReapplyKeepsTheBranchClosed(t *testing.T) {
	_, s, v := appliedRequest(t)
	erasure.Reapply = func(string, ErasureReapply) (ErasureResult, error) {
		return ErasureResult{}, errors.New("public.people has no primary key in the copy")
	}
	g, _ := guardRestoreWith(s, "backup restore", "main", v.Result.Applied.Add(-time.Minute), "the export",
		AfterErasure{Reapply: true, Reason: "r", Actor: "admin@x"})
	if err := g.open("restored", true); err != nil {
		t.Fatal(err)
	}
	_, err := g.reapply()
	if err == nil || !strings.Contains(err.Error(), "stays closed") || !strings.Contains(err.Error(), "branch delete restored") {
		t.Fatalf("a failed re-apply: %v", err)
	}
	if err := checkBranchOpen("restored"); !errors.Is(err, ErrBranchClosed) || !strings.Contains(err.Error(), "no primary key") {
		t.Fatalf("not closed after the failure: %v", err)
	}
	rs, _ := s.ErasureRestores(v.ID)
	if len(rs) != 1 || rs[0].State != auth.RestoreFailed || !strings.Contains(rs[0].Error, "no primary key") {
		t.Fatalf("the record: %+v", rs)
	}
	// Deleting it removes the mark with it.
	if err := unmarkReapplying("restored"); err != nil || checkBranchOpen("restored") != nil {
		t.Fatalf("still closed once gone: %v", err)
	}
}

func TestUndoneByReadsTheBranchsOwnRecord(t *testing.T) {
	t1 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(2 * time.Hour)
	main := ErasureResult{Applied: t1, Tables: []ErasureDone{{Schema: "public", Table: "people"}}}
	dev := ErasureResult{Applied: t2, Tables: []ErasureDone{{Schema: "public", Table: "orders"}}}
	v := ErasureView{ErasureRequest: auth.ErasureRequest{ID: 3, State: auth.ErasureApplied, Branch: "main"},
		Result: &main, Branches: []ErasureBranch{{Branch: "dev", State: BranchApplied, Plan: &ErasurePlan{Branch: "dev"}, Result: &dev},
			{Branch: "qa", State: BranchSkipped, Plan: &ErasurePlan{Branch: "qa"}}}}
	views := []ErasureView{v,
		{ErasureRequest: auth.ErasureRequest{ID: 4, State: auth.ErasurePlanned, Branch: "main"}},
		{ErasureRequest: auth.ErasureRequest{ID: 5, State: auth.ErasureWithdrawn, Branch: "main"}}}

	between := t1.Add(time.Hour)
	if u := undoneBy(views, "dev", between); len(u) != 1 || u[0].keys != "dev" || u[0].result.Tables[0].Table != "orders" {
		t.Fatalf("dev, between main's erasure and its own: %+v", u)
	}
	if u := undoneBy(views, "main", between); len(u) != 0 {
		t.Fatalf("main after its erasure: %+v", u)
	}
	// A branch it skipped, or never saw, gets main's record.
	for _, b := range []string{"qa", "gone"} {
		if u := undoneBy(views, b, t1.Add(-time.Hour)); len(u) != 1 || u[0].keys != "main" {
			t.Fatalf("%s: %+v", b, u)
		}
	}
	// One that changed nothing on the branch the copy is of undoes nothing.
	none := ErasureResult{Applied: t2}
	quiet := ErasureView{ErasureRequest: auth.ErasureRequest{ID: 8, State: auth.ErasureApplied, Branch: "main"}, Result: &none}
	if u := undoneBy([]ErasureView{quiet}, "main", t1); len(u) != 0 {
		t.Fatalf("a request that changed nothing on main: %+v", u)
	}
	// Only applied requests are undone, and one applying now is said.
	views = append(views, ErasureView{ErasureRequest: auth.ErasureRequest{ID: 6, State: auth.ErasureApplying, Branch: "main", Claimed: t2}})
	u := undoneBy(views, "main", t1.Add(-time.Hour))
	if len(u) != 2 || u[0].view.ID != 3 || u[1].view.ID != 6 {
		t.Fatalf("applied and applying: %+v", u)
	}
}

func TestParseAfterErasure(t *testing.T) {
	if a, err := ParseAfterErasure("reapply", "  incident 9 ", "op"); err != nil || !a.Reapply || a.Reason != "incident 9" || a.Actor != "op" {
		t.Fatalf("reapply: %+v %v", a, err)
	}
	if a, err := ParseAfterErasure("", "", "op"); err != nil || a.Reapply {
		t.Fatalf("none: %+v %v", a, err)
	}
	if _, err := ParseAfterErasure("ignore", "r", "op"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("anything but reapply is refused: %v", err)
	}
}
