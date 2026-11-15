// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func requestStore(t *testing.T) (*auth.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "a.db")
	s, err := auth.Open(auth.Config{DBPath: path, WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

// targetRecord stands in for the target's bb.applied_requests.
func targetRecord(t *testing.T, rec map[int64]int, err error) {
	t.Helper()
	old := appliedRequestsOf
	appliedRequestsOf = func(string) (map[int64]int, error) { return rec, err }
	t.Cleanup(func() { appliedRequestsOf = old })
}

func approved(t *testing.T, s *auth.Store, entries string) auth.ChangeRequest {
	t.Helper()
	c, err := s.CreateChangeRequest(auth.CLIUser, "dev", "main", 0, entries)
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.ClaimChangeRequest(c.ID, auth.CLIUser, auth.RequestApproved, "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A request the store never saw finish is looked up in the target's own
// record, and taken as applied when it is there: reconciled, not offered again.
func TestRequestHistoryReconcilesFromTheTargetsRecord(t *testing.T) {
	s, _ := requestStore(t)
	lost := approved(t, s, `[{"id":5},{"id":6}]`) // committed; Finish never ran
	failed := approved(t, s, `[{"id":7}]`)
	if err := s.FinishChangeRequest(failed.ID, 0, "a statement failed"); err != nil {
		t.Fatal(err)
	}
	targetRecord(t, map[int64]int{lost.ID: 2}, nil)

	hist, err := RequestHistory(s, "dev", "main")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[int64]auth.ChangeRequest{}
	for _, c := range hist {
		byID[c.ID] = c
	}
	if c := byID[lost.ID]; c.Status != auth.RequestApproved || c.Applied != 2 {
		t.Errorf("the lost apply reads %+v, want approved with 2 applied", c)
	}
	if c := byID[failed.ID]; c.Status != auth.RequestFailed || c.Applied != 0 {
		t.Errorf("a request the target does not have was marked applied: %+v", c)
	}
	if got, _ := s.ChangeRequest(lost.ID); got.Applied != 2 {
		t.Errorf("the store was not reconciled: %+v", got)
	}
}

// Not knowing is not "not applied".
func TestRequestHistoryRefusesWhenTheTargetCannotBeRead(t *testing.T) {
	s, _ := requestStore(t)
	approved(t, s, `[{"id":5}]`)
	targetRecord(t, nil, errors.New("the target is down"))
	if _, err := RequestHistory(s, "dev", "main"); err == nil || !strings.Contains(err.Error(), "target is down") {
		t.Fatalf("err = %v", err)
	}
}

// Nothing to be unsure of, nothing to ask: the target is not read at all.
func TestRequestHistoryDoesNotReadAKnownHistory(t *testing.T) {
	s, _ := requestStore(t)
	c := approved(t, s, `[{"id":5}]`)
	if err := s.FinishChangeRequest(c.ID, 1, ""); err != nil {
		t.Fatal(err)
	}
	targetRecord(t, nil, errors.New("must not be asked"))
	if _, err := RequestHistory(s, "dev", "main"); err != nil {
		t.Fatal(err)
	}
}

func stubApply(t *testing.T, n int, err error) {
	t.Helper()
	old := applyNow
	applyNow = func(ApplyPlan) (int, error) { return n, err }
	t.Cleanup(func() { applyNow = old })
}

// The apply committed and the store could not note it. The caller hears so,
// and the next read of the history reconciles from the target's record, which
// the same transaction wrote.
func TestFinishFailureIsReconciledNotReapplied(t *testing.T) {
	s, path := requestStore(t)
	c := approved(t, s, `[{"id":5},{"id":6}]`)
	targetRecord(t, map[int64]int{}, nil) // before the apply, the target has none
	stubApply(t, 2, nil)

	// The store refuses to record an outcome, as a full disk or a lock would.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER no_outcome BEFORE UPDATE OF applied ON change_requests
		BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	n, applyErr, recordErr := ApplyClaimed(s, c, "carol@example.com")
	if applyErr != nil || n != 2 || recordErr == nil {
		t.Fatalf("ApplyClaimed = %d, %v, %v; want 2 applied and the record's failure", n, applyErr, recordErr)
	}
	if got, _ := s.ChangeRequest(c.ID); got.Status != auth.RequestApproved || got.Applied != 0 {
		t.Fatalf("setup: %+v", got)
	}

	if _, err := db.Exec(`DROP TRIGGER no_outcome`); err != nil {
		t.Fatal(err)
	}
	targetRecord(t, map[int64]int{c.ID: 2}, nil) // what the apply's transaction wrote
	hist, err := RequestHistory(s, "dev", "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Applied != 2 {
		t.Fatalf("history after reconciling: %+v", hist)
	}
}

// A request the target already holds is not run again; the store takes the
// target's count.
func TestAlreadyAppliedIsReconciled(t *testing.T) {
	s, _ := requestStore(t)
	c := approved(t, s, `[{"id":5},{"id":6},{"id":7}]`)
	targetRecord(t, map[int64]int{}, nil)
	stubApply(t, 3, fmt.Errorf("applying: %w", ErrAlreadyApplied))
	n, applyErr, recordErr := ApplyClaimed(s, c, "carol@example.com")
	if !errors.Is(applyErr, ErrAlreadyApplied) || recordErr != nil || n != 3 {
		t.Fatalf("ApplyClaimed = %d, %v, %v", n, applyErr, recordErr)
	}
	got, _ := s.ChangeRequest(c.ID)
	if got.Status != auth.RequestApproved || got.Applied != 3 {
		t.Errorf("not reconciled: %+v", got)
	}
}

func TestRequestKeyIgnoresOrder(t *testing.T) {
	a := RequestKey([]RequestEntry{{ID: 9}, {ID: 2}, {ID: 30}})
	b := RequestKey([]RequestEntry{{ID: 30}, {ID: 9}, {ID: 2}})
	if a != b || a != "2,9,30" {
		t.Errorf("%q vs %q", a, b)
	}
}

// What was left out, and whether data goes, is the first thing a reviewer reads.
func TestFormatRequestSaysWhatWasLeftOut(t *testing.T) {
	c := auth.ChangeRequest{ID: 3, Source: "agent-x", Target: "main", OmittedCount: 2,
		Omitted: `[{"id":11,"actor":"agent-x","kind":"agent","command":"DELETE","object":"public.orders","reason":"r"}]`}
	out := FormatRequest(c, nil)
	for _, want := range []string{"schema changes only", "2 data change(s)", "entry 11: DELETE public.orders, by agent-x (agent)", "and 1 more", "--include-data"} {
		if !strings.Contains(out, want) {
			t.Errorf("the request does not say %q:\n%s", want, out)
		}
	}
	c.IncludeData, c.OmittedCount, c.Omitted = true, 0, ""
	if out := FormatRequest(c, nil); !strings.Contains(out, "INCLUDES DATA CHANGES") {
		t.Errorf("a request carrying data does not say so:\n%s", out)
	}
}
