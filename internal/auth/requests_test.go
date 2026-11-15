// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestChangeRequestLifecycle(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("asker@example.com", "password123")
	if err != nil {
		t.Fatal(err)
	}
	approver, err := s.CreateUser("approver@example.com", "password123")
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.CreateChangeRequest(u.ID, "dev", "main", 12, `[{"id":13}]`)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == 0 || c.Status != RequestOpen || c.Source != "dev" || c.Target != "main" {
		t.Fatalf("unexpected request: %+v", c)
	}
	if c.CreatedBy != "asker@example.com" || c.ForkAfterID != 12 {
		t.Errorf("who asked, or where they forked, is wrong: %+v", c)
	}

	// Open requests are listable by state and by target.
	open, err := s.ChangeRequests(RequestOpen, "main")
	if err != nil || len(open) != 1 {
		t.Fatalf("listing open requests for main gave %d, %v", len(open), err)
	}
	if none, _ := s.ChangeRequests(RequestOpen, "other"); len(none) != 0 {
		t.Errorf("a request for main was listed under another target")
	}

	// A decision is made once: a second one must not apply the statements again.
	got, err := s.ClaimChangeRequest(c.ID, approver.ID, RequestApproved, "looks right")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != RequestApproved || got.DecidedBy != "approver@example.com" || got.Note != "looks right" {
		t.Errorf("the decision was not recorded: %+v", got)
	}
	if _, err := s.ClaimChangeRequest(c.ID, approver.ID, RequestApproved, ""); !errors.Is(err, ErrRequestDecided) {
		t.Errorf("approving twice gave %v, want ErrRequestDecided", err)
	}
	if _, err := s.ClaimChangeRequest(c.ID, approver.ID, RequestRejected, ""); !errors.Is(err, ErrRequestDecided) {
		t.Errorf("rejecting an approved request gave %v, want ErrRequestDecided", err)
	}

	// Applying records how much went in; a failure records why.
	if err := s.FinishChangeRequest(c.ID, 3, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ChangeRequest(c.ID); got.Applied != 3 || got.Status != RequestApproved {
		t.Errorf("after applying: %+v", got)
	}
	if err := s.FinishChangeRequest(c.ID, 0, "the target went away"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ChangeRequest(c.ID); got.Status != RequestFailed || got.Note == "" {
		t.Errorf("a failure should be recorded: %+v", got)
	}
}

func TestChangeRequestUnknownID(t *testing.T) {
	s := testStore(t)
	if _, err := s.ChangeRequest(999); !errors.Is(err, ErrNoSuchRequest) {
		t.Errorf("an unknown id gave %v, want ErrNoSuchRequest", err)
	}
	if _, err := s.ClaimChangeRequest(999, 1, RequestApproved, ""); !errors.Is(err, ErrNoSuchRequest) {
		t.Errorf("deciding an unknown id gave %v, want ErrNoSuchRequest", err)
	}
}

// The CLI has no account: whoever has a shell on the machine is the operator, and
// the record says so rather than naming a deleted user.
func TestChangeRequestFromTheCLI(t *testing.T) {
	s := testStore(t)
	c, err := s.CreateChangeRequest(CLIUser, "dev", "main", 0, "[]")
	if err != nil {
		t.Fatal(err)
	}
	if c.CreatedBy != "the local CLI" {
		t.Errorf("created_by = %q, want the local CLI", c.CreatedBy)
	}
	got, err := s.ClaimChangeRequest(c.ID, CLIUser, RequestRejected, "not now")
	if err != nil {
		t.Fatal(err)
	}
	if got.DecidedBy != "the local CLI" {
		t.Errorf("decided_by = %q, want the local CLI", got.DecidedBy)
	}
}

// A deleted branch must not leave open requests pointing at nothing.
func TestForgetBranchRequests(t *testing.T) {
	s := testStore(t)
	if _, err := s.CreateChangeRequest(CLIUser, "gone", "main", 0, "[]"); err != nil {
		t.Fatal(err)
	}
	decided, err := s.CreateChangeRequest(CLIUser, "gone", "main", 0, "[]")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimChangeRequest(decided.ID, CLIUser, RequestApproved, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetBranchRequests("gone"); err != nil {
		t.Fatal(err)
	}
	left, err := s.ChangeRequests("", "")
	if err != nil {
		t.Fatal(err)
	}
	// The decided one is history and stays; the open one is gone.
	if len(left) != 1 || left[0].ID != decided.ID {
		t.Errorf("after forgetting the branch: %+v", left)
	}
}

// Deleting a branch forgets its owner and any request still waiting on it, in one
// place, so the CLI and the API cannot disagree about what deletion means.
func TestForgetBranchAlsoForgetsRequests(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("owner@example.com", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBranchOwner("doomed", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateChangeRequest(u.ID, "doomed", "main", 0, "[]"); err != nil {
		t.Fatal(err)
	}
	if err := s.ForgetBranch("doomed"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.BranchOwner("doomed"); ok {
		t.Error("the owner outlived the branch")
	}
	left, err := s.ChangeRequests(RequestOpen, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("an open request outlived its branch: %+v", left)
	}
}

// Two open requests for exactly the same changes are two chances to apply
// them. The second ask gets the first request back.
func TestADuplicateOpenRequestReturnsTheExistingOne(t *testing.T) {
	s := testStore(t)
	n := NewChangeRequest{Source: "dev", Target: "main", ForkAfterID: 4, Entries: `[{"id":5},{"id":6}]`,
		EntryKey: "5,6", Omitted: `[{"id":7}]`, OmittedCount: 1}
	first, existing, err := s.OpenChangeRequest(CLIUser, n)
	if err != nil || existing {
		t.Fatalf("first: %v, existing=%v", err, existing)
	}
	if first.IncludeData || first.OmittedCount != 1 || first.Omitted != `[{"id":7}]` {
		t.Errorf("what was left out is not kept: %+v", first)
	}
	second, existing, err := s.OpenChangeRequest(CLIUser, n)
	if err != nil || !existing || second.ID != first.ID {
		t.Fatalf("second: #%d, existing=%v, %v; want #%d back", second.ID, existing, err, first.ID)
	}
	// A different set of entries, another target, or a source with a decided
	// request is a new request.
	other := n
	other.EntryKey = "5,6,8"
	if c, existing, _ := s.OpenChangeRequest(CLIUser, other); existing || c.ID == first.ID {
		t.Error("a request for more entries was merged into a smaller one")
	}
	elsewhere := n
	elsewhere.Target = "staging"
	if _, existing, _ := s.OpenChangeRequest(CLIUser, elsewhere); existing {
		t.Error("a request to another target was merged")
	}
	if _, err := s.ClaimChangeRequest(first.ID, CLIUser, RequestRejected, ""); err != nil {
		t.Fatal(err)
	}
	if again, existing, _ := s.OpenChangeRequest(CLIUser, n); existing || again.ID == first.ID {
		t.Error("a decided request was handed back as if still open")
	}
	all, _ := s.ChangeRequests("", "")
	if len(all) != 4 {
		t.Errorf("%d requests, want 4", len(all))
	}
}

// A request made with data included says so wherever it is read.
func TestIncludeDataIsRecorded(t *testing.T) {
	s := testStore(t)
	c, _, err := s.OpenChangeRequest(CLIUser, NewChangeRequest{Source: "dev", Target: "main", Entries: `[{"id":1}]`,
		EntryKey: "1", IncludeData: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ChangeRequest(c.ID)
	if err != nil || !got.IncludeData {
		t.Fatalf("include_data lost: %+v, %v", got, err)
	}
	// One made the old way reads as schema only, with nothing listed.
	old, err := s.CreateChangeRequest(CLIUser, "dev", "main", 0, `[{"id":2}]`)
	if err != nil || old.IncludeData || old.OmittedCount != 0 {
		t.Fatalf("%+v, %v", old, err)
	}
}

// When applying committed and noting so did not, the target's own record is
// what the store is reconciled from: the request reads as applied, and the
// next request from the same source does not offer its entries again.
func TestReconcileMarksAnUnrecordedApplyAsApplied(t *testing.T) {
	s := testStore(t)
	c, _ := s.CreateChangeRequest(CLIUser, "dev", "main", 0, `[{"id":1},{"id":2}]`)
	if _, err := s.ClaimChangeRequest(c.ID, CLIUser, RequestApproved, "ok"); err != nil {
		t.Fatal(err)
	}
	// Finish never ran: approved, nothing applied.
	if err := s.ReconcileChangeRequest(c.ID, 2); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ChangeRequest(c.ID)
	if got.Status != RequestApproved || got.Applied != 2 || !strings.Contains(got.Note, reconciledNote) {
		t.Fatalf("not reconciled: %+v", got)
	}
	// A count already recorded is never overwritten.
	if err := s.ReconcileChangeRequest(c.ID, 9); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ChangeRequest(c.ID); got.Applied != 2 {
		t.Errorf("a recorded count was overwritten: %d", got.Applied)
	}

	// A request whose commit was not confirmed is recorded as failed; the
	// target's record turns it into applied.
	f, _ := s.CreateChangeRequest(CLIUser, "dev", "main", 0, `[{"id":3}]`)
	if _, err := s.ClaimChangeRequest(f.ID, CLIUser, RequestApproved, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishChangeRequest(f.ID, 0, "the commit was not confirmed"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileChangeRequest(f.ID, 1); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ChangeRequest(f.ID); got.Status != RequestApproved || got.Applied != 1 {
		t.Errorf("a failed-but-applied request was not reconciled: %+v", got)
	}

	// An open or rejected request is never marked applied.
	o, _ := s.CreateChangeRequest(CLIUser, "dev", "main", 0, `[{"id":4}]`)
	if err := s.ReconcileChangeRequest(o.ID, 1); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ChangeRequest(o.ID); got.Status != RequestOpen || got.Applied != 0 {
		t.Errorf("an open request was marked applied: %+v", got)
	}
	hist, err := s.RequestsFrom("dev", "main", RequestApproved, RequestFailed)
	if err != nil || len(hist) != 2 {
		t.Errorf("history = %d, %v; want the two applied requests", len(hist), err)
	}
}
