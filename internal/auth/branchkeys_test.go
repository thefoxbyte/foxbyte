// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"strings"
	"testing"
)

// A branch's scoped keys go with it, each one written to the security log, and
// nothing else is touched: not account keys, not another branch's key.
func TestRevokeBranchKeysLogsEachKey(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("a@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	k1, _, _ := s.CreateScopedAPIKey(u.ID, "agent one", "agent-one")
	k2, _, _ := s.CreateScopedAPIKey(u.ID, "agent one again", "agent-one")
	other, _, _ := s.CreateScopedAPIKey(u.ID, "agent two", "agent-two")
	plain, _, _ := s.CreateAPIKey(u.ID, "laptop")

	n, err := s.RevokeBranchKeys("agent-one", "engine", "its branch was deleted")
	if err != nil || n != 2 {
		t.Fatalf("RevokeBranchKeys = %d, %v; want 2, nil", n, err)
	}
	for _, k := range []string{k1, k2} {
		if _, _, ok := s.VerifyKey(k); ok {
			t.Error("a key scoped to the deleted branch still works")
		}
	}
	for _, k := range []string{other, plain} {
		if _, _, ok := s.VerifyKey(k); !ok {
			t.Error("revoking one branch's keys touched a key it does not scope")
		}
	}
	evs, err := s.SecurityEventsOfKind(EvKeyRevoked)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("%d revocations logged, want 2: %+v", len(evs), evs)
	}
	for _, e := range evs {
		if !strings.Contains(e.Subject, "agent-one") || e.Detail != "its branch was deleted" || e.Actor != "engine" {
			t.Errorf("logged revocation = %+v", e)
		}
	}
	// Nothing left: nothing revoked, nothing logged.
	if n, err := s.RevokeBranchKeys("agent-one", "engine", "again"); err != nil || n != 0 {
		t.Errorf("second RevokeBranchKeys = %d, %v", n, err)
	}
	if n, _ := s.RevokeBranchKeys("", "engine", "empty"); n != 0 {
		t.Error("an empty branch name revoked something")
	}
	if evs, _ := s.SecurityEventsOfKind(EvKeyRevoked); len(evs) != 2 {
		t.Errorf("%d revocations logged after the no-ops, want 2", len(evs))
	}
}

// Forgetting a branch takes its scoped keys with its owner.
func TestForgetBranchRevokesItsKeys(t *testing.T) {
	s := testStore(t)
	u, _ := s.CreateUser("a@x.com", "password1")
	_ = s.SetBranchOwner("agent-one", u.ID)
	k, _, _ := s.CreateScopedAPIKey(u.ID, "agent one", "agent-one")
	if err := s.ForgetBranch("agent-one"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.VerifyKey(k); ok {
		t.Error("the key outlived the forgotten branch")
	}
}

func TestOwnedBranchCount(t *testing.T) {
	s := testStore(t)
	a, _ := s.CreateUser("a@x.com", "password1")
	b, _ := s.CreateUser("b@x.com", "password1")
	for _, n := range []string{"one", "two", "three"} {
		_ = s.SetBranchOwner(n, a.ID)
	}
	_ = s.SetBranchOwner("four", b.ID)
	// A name made again by someone else is theirs now.
	_ = s.SetBranchOwner("three", b.ID)
	if n, err := s.OwnedBranchCount(a.ID); err != nil || n != 2 {
		t.Errorf("a owns %d (%v), want 2", n, err)
	}
	if n, _ := s.OwnedBranchCount(b.ID); n != 2 {
		t.Errorf("b owns %d, want 2", n)
	}
	_ = s.ForgetBranch("four")
	if n, _ := s.OwnedBranchCount(b.ID); n != 1 {
		t.Errorf("b owns %d after a delete, want 1", n)
	}
}
