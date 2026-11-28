// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func TestRetentionCutoffKeepsAYearAtLeast(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	cut, raised, ok := retentionCutoff(DPDPKeep{Count: 6, Unit: "months", From: "collection"}, now)
	if !ok || !raised || !cut.Equal(now.AddDate(-1, 0, 0)) {
		t.Fatalf("six months: %v raised %v ok %v", cut, raised, ok)
	}
	cut, raised, ok = retentionCutoff(DPDPKeep{Count: 3, Unit: "years", From: "last-contact"}, now)
	if !ok || raised || !cut.Equal(now.AddDate(-3, 0, 0)) {
		t.Fatalf("three years: %v raised %v", cut, raised)
	}
	if _, _, ok := retentionCutoff(DPDPKeep{Count: 0, Unit: "years", From: "purpose-served"}, now); ok {
		t.Fatal("until the purpose is served has no date")
	}
	if !keepsUnderAYear(DPDPKeep{Count: 90, Unit: "days"}) || keepsUnderAYear(DPDPKeep{Count: 12, Unit: "months"}) || keepsUnderAYear(DPDPKeep{Count: 1, Unit: "years"}) {
		t.Fatal("under a year")
	}
}

func TestNoticeAddress(t *testing.T) {
	for _, ok := range []string{"https://hooks.example/fox", "http://127.0.0.1:9000/n", "http://localhost/n"} {
		if err := checkNotifyURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://hooks.example/fox", "ftp://x/y", "", "hooks.example"} {
		if err := checkNotifyURL(bad); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s accepted: %v", bad, err)
		}
	}
}

// retentionRig is a store, main's inventory with public.people kept two
// years after collection, the fake engine, and a webhook receiver.
type retentionRig struct {
	s      *auth.Store
	f      *fakeErasure
	due    []RetentionRow // what Due finds
	srv    *httptest.Server
	status int
	mu     sync.Mutex
	bodies [][]byte
	sigs   []string
}

func newRetentionRig(t *testing.T) *retentionRig {
	t.Helper()
	r := &retentionRig{status: 200}
	r.f = &fakeErasure{plan: ErasurePlan{Branch: "main", Rows: 1}, fp: "fpR", branches: []BranchInfo{{Name: "dev"}}}
	r.f.install(t)
	r.s = erasureStore(t)
	dir := t.TempDir()
	oldPath, oldInv := retentionSettingsPath, retentionInventory
	retentionSettingsPath = func() string { return filepath.Join(dir, "retention.json") }
	entry := DPDPEntry{Schema: "public", Table: "people", Basis: "consent", Keep: DPDPKeep{Count: 2, Unit: "years", From: "collection", Reason: "purpose"}}
	retentionInventory = func() (DPDPInventory, error) {
		return DPDPInventory{Branch: "main", Tables: []DPDPTable{{Schema: "public", Table: "people", Entry: &entry}}}, nil
	}
	t.Cleanup(func() { retentionSettingsPath, retentionInventory = oldPath, oldInv })
	t.Setenv("FOX_RETENTION_NOTICE", "0s")
	erasure.Due = func(b string, q RetentionQuery) (RetentionDue, error) {
		if q.Column != "created_at" {
			return RetentionDue{}, errors.New("public.people has no column " + q.Column)
		}
		var rows []RetentionRow
		for _, x := range r.due {
			skip := false
			for _, e := range q.Exclude {
				skip = skip || normKey(e) == normKey(x.Key)
			}
			if !skip {
				rows = append(rows, x)
			}
		}
		total := len(rows)
		if q.Limit > 0 && len(rows) > q.Limit {
			rows = rows[:q.Limit]
		}
		return RetentionDue{Schema: q.Schema, Table: q.Table, Column: q.Column, KeyColumns: []string{"id"}, Cutoff: q.Cutoff, Total: total, Rows: rows}, nil
	}
	erasure.PlanRetention = func(b, only string, seed ErasureSeed, actor string) (ErasurePlan, string, ErasureSeed, error) {
		p := ErasurePlan{Branch: b, Rows: len(seed[only])}
		fp := "fpR"
		if b != "main" {
			fp += "@" + b
		}
		return p, fp, seed, nil
	}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies, r.sigs = append(r.bodies, b), append(r.sigs, req.Header.Get(NoticeSignature))
		st := r.status
		r.mu.Unlock()
		w.WriteHeader(st)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func TestRetentionNoticesThenErasesOnlyArmedTables(t *testing.T) {
	r := newRetentionRig(t)
	old := time.Now().AddDate(-3, 0, 0)
	r.due = []RetentionRow{{Key: `["1"]`, Since: old}, {Key: `["2"]`, Since: old.Add(time.Hour)}}

	if _, err := RunRetention(r.s, "admin@x"); !errors.Is(err, ErrRetentionOff) {
		t.Fatalf("a run while off: %v", err)
	}
	secret, err := SetRetentionOn(r.s, r.srv.URL+"/notice", "admin@x")
	if err != nil || len(secret) != 64 {
		t.Fatalf("on: %v %q", err, secret)
	}
	if LoadRetentionSettings().Public().Secret != "" {
		t.Fatal("the secret is shown again")
	}
	if _, err := SetRetentionColumn(r.s, "public.people", "nope", "admin@x"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("a column that is not there: %v", err)
	}
	if _, err := SetRetentionColumn(r.s, "public.people", "created_at", "admin@x"); err != nil {
		t.Fatal(err)
	}
	// Not armed: listed as due, never touched.
	run, err := RunRetention(r.s, "admin@x")
	if err != nil || len(run.Tables) != 0 || len(r.bodies) != 0 {
		t.Fatalf("an unarmed table was acted on: %v %+v", err, run)
	}
	st, err := GetRetentionStatus(r.s)
	if err != nil || len(st.Tables) != 1 || st.Tables[0].Due != 2 || st.Tables[0].Armed || !strings.Contains(st.Tables[0].Why, "not armed") {
		t.Fatalf("status: %v %+v", err, st.Tables)
	}
	if _, err := ArmRetention(r.s, "public.people", "admin@x", ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("armed with no reason: %v", err)
	}
	if _, err := ArmRetention(r.s, "public.people", "admin@x", "the DPO's policy of 1 Dec"); err != nil {
		t.Fatal(err)
	}

	// First run: noticed, signed, nothing erased.
	run, err = RunRetention(r.s, "retention scheduler")
	if err != nil || len(run.Tables) != 1 || run.Tables[0].Noticed != 2 || run.Tables[0].Erased != 0 {
		t.Fatalf("first run: %v %+v", err, run)
	}
	if len(r.bodies) != 1 {
		t.Fatalf("notices posted: %d", len(r.bodies))
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(r.bodies[0])
	if r.sigs[0] != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("the signature does not verify: %s", r.sigs[0])
	}
	var body RetentionNoticeBody
	if err := json.Unmarshal(r.bodies[0], &body); err != nil || body.Table != "public.people" || len(body.Rows) != 2 || body.Rule != "DPDP Rules, 2025, Rule 8(2)" {
		t.Fatalf("the notice: %v %+v", err, body)
	}
	if strings.Contains(string(r.bodies[0]), "asha") {
		t.Fatal("a notice carried a value")
	}
	if len(r.f.applied) != 0 {
		t.Fatal("erased before its notice's time")
	}

	// Second run: row 2's date moved (the person came back); row 1 is erased.
	r.due = r.due[:1]
	run, err = RunRetention(r.s, "retention scheduler")
	if err != nil || run.Tables[0].Erased != 1 || run.Tables[0].Renewed != 1 || run.Tables[0].Request == 0 {
		t.Fatalf("second run: %v %+v", err, run)
	}
	if len(r.f.applied) != 2 || r.f.applied[0].Only != "public.people" || !r.f.applied[0].Retention ||
		strings.Join(r.f.applied[0].Seed["public.people"], ",") != `["1"]` || len(r.f.applied[0].Values) != 0 {
		t.Fatalf("the engine was asked: %+v", r.f.applied)
	}
	if r.f.appliedOn[1] != "dev" || r.f.applied[1].UID != r.f.applied[0].UID {
		t.Fatalf("every branch, under the request's own id: %v %+v", r.f.appliedOn, r.f.applied)
	}
	v, err := GetErasure(r.s, run.Tables[0].Request)
	if err != nil || v.State != auth.ErasureApplied || !strings.Contains(v.Note, "retention of public.people") || len(v.Refs) != 0 ||
		len(v.Branches) != 1 || v.Branches[0].State != BranchApplied {
		t.Fatalf("the request: %v %+v", err, v)
	}
	ns, _ := r.s.RetentionNotices("public", "people", false, 10)
	states := map[string]string{}
	for _, n := range ns {
		states[n.Key] = n.State
	}
	if states[`["1"]`] != auth.NoticeErased || states[`["2"]`] != auth.NoticeRenewed {
		t.Fatalf("notices: %+v", ns)
	}
	if set := LoadRetentionSettings(); set.LastRun == nil || !strings.Contains(set.LastSummary, "1 erased") {
		t.Fatalf("the last run: %+v", set)
	}
	// A cleared row keeps its date: it is not noticed or erased again.
	bodies := len(r.bodies)
	if run, err = RunRetention(r.s, "retention scheduler"); err != nil || run.Tables[0].Due != 0 || run.Tables[0].Noticed != 0 || len(r.bodies) != bodies {
		t.Fatalf("the erased row came back: %v %+v", err, run)
	}

	// Disarmed: nothing more.
	if err := DisarmRetention(r.s, "public.people", "admin@x"); err != nil {
		t.Fatal(err)
	}
	r.due = []RetentionRow{{Key: `["3"]`, Since: old}}
	if run, _ = RunRetention(r.s, "retention scheduler"); len(run.Tables) != 0 {
		t.Fatalf("a disarmed table: %+v", run)
	}
}

func TestAnUndeliveredNoticeErasesNothing(t *testing.T) {
	r := newRetentionRig(t)
	r.due = []RetentionRow{{Key: `["1"]`, Since: time.Now().AddDate(-3, 0, 0)}}
	if _, err := SetRetentionOn(r.s, r.srv.URL, "admin@x"); err != nil {
		t.Fatal(err)
	}
	_, _ = SetRetentionColumn(r.s, "public.people", "created_at", "admin@x")
	_, _ = ArmRetention(r.s, "public.people", "admin@x", "policy")
	r.status = 503
	for i := 0; i < 2; i++ {
		run, err := RunRetention(r.s, "retention scheduler")
		if err != nil || run.Tables[0].Noticed != 0 || run.Tables[0].Erased != 0 || !strings.Contains(run.Tables[0].Error, "could not be delivered") {
			t.Fatalf("run %d: %v %+v", i, err, run)
		}
	}
	if len(r.f.applied) != 0 {
		t.Fatal("erased with no notice delivered")
	}
	// Delivered at last: noticed, and erased on the run after.
	r.status = 200
	if run, _ := RunRetention(r.s, "retention scheduler"); run.Tables[0].Noticed != 1 {
		t.Fatalf("delivered: %+v", run)
	}
	if run, _ := RunRetention(r.s, "retention scheduler"); run.Tables[0].Erased != 1 {
		t.Fatalf("erased after: %+v", run)
	}
}

func TestTheSchedulerWaitsADayAfterRetentionIsOn(t *testing.T) {
	r := newRetentionRig(t)
	r.due = []RetentionRow{{Key: `["1"]`, Since: time.Now().AddDate(-3, 0, 0)}}
	if _, err := SetRetentionOn(r.s, r.srv.URL, "admin@x"); err != nil {
		t.Fatal(err)
	}
	_, _ = SetRetentionColumn(r.s, "public.people", "created_at", "admin@x")
	_, _ = ArmRetention(r.s, "public.people", "admin@x", "policy")
	retentionIfDue(r.s)
	if len(r.bodies) != 0 {
		t.Fatal("the scheduler ran as soon as retention was on")
	}
	set := LoadRetentionSettings()
	set.Since = time.Now().Add(-25 * time.Hour)
	_ = saveRetentionSettings(set)
	old := retentionPrimaryUp
	retentionPrimaryUp = func() bool { return true }
	t.Cleanup(func() { retentionPrimaryUp = old })
	retentionIfDue(r.s)
	if len(r.bodies) != 1 {
		t.Fatalf("a day on, the scheduler did not run: %d", len(r.bodies))
	}
}
