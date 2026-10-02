// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestEmailsAreBareAndFitARoleName(t *testing.T) {
	s := testStore(t)
	for _, bad := range []string{"not-an-email", "Bob <bob@x.com>", "a@b.com, c@d.com",
		strings.Repeat("a", 60) + "@x.com"} {
		if _, err := s.CreateUser(bad, "password1"); !errors.Is(err, ErrBadEmail) {
			t.Errorf("CreateUser(%q) = %v, want ErrBadEmail", bad, err)
		}
	}
	if u, err := s.CreateUser("  Mixed.Case@Example.com ", "password1"); err != nil || u.Email != "mixed.case@example.com" {
		t.Errorf("a normal address: %+v, %v", u, err)
	}
}

func TestChangePasswordEndsOtherSessions(t *testing.T) {
	s := testStore(t)
	u, _ := s.CreateUser("a@x.com", "password1")
	mine, _ := s.createSession(u.ID)
	other, _ := s.createSession(u.ID)
	if err := s.ChangePassword(u.ID, "wrong", "password2", mine); err == nil {
		t.Fatal("changed with the wrong current password")
	}
	if err := s.ChangePassword(u.ID, "password1", "short", mine); err == nil {
		t.Fatal("accepted a short password")
	}
	if err := s.ChangePassword(u.ID, "password1", "password2", mine); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.userBySession(mine); !ok {
		t.Error("the session that changed the password was signed out")
	}
	if _, ok := s.userBySession(other); ok {
		t.Error("another session survived the password change")
	}
	if _, err := s.Login("a@x.com", "password2"); err != nil {
		t.Errorf("new password: %v", err)
	}
	if _, err := s.Login("a@x.com", "password1"); err == nil {
		t.Error("old password still works")
	}
	// A reset is what someone locked out is told to run (`fox user passwd`), so
	// the promise is both halves: the new password works, the old one does not,
	// and nothing that was signed in stays signed in.
	if err := s.ResetPassword("a@x.com", "password3"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.userBySession(mine); ok {
		t.Error("an admin reset left a session signed in")
	}
	if _, err := s.Login("a@x.com", "password3"); err != nil {
		t.Errorf("the password a reset set does not work: %v", err)
	}
	if _, err := s.Login("a@x.com", "password2"); err == nil {
		t.Error("the password from before the reset still works")
	}
	if err := s.ResetPassword("nobody@x.com", "password4"); err == nil {
		t.Error("resetting an account that does not exist should say so")
	}
}

func TestDeleteAccount(t *testing.T) {
	s := testStore(t)
	a, _ := s.CreateUser("a@x.com", "password1")
	b, _ := s.CreateUser("b@x.com", "password1")
	key, _, _ := s.CreateAPIKey(b.ID, "ci")
	tok, _ := s.createSession(b.ID)
	_ = s.SetBranchOwner("b-dev", b.ID)
	_, _ = s.CreatePipeline(b.ID, "p", "{}")
	if err := s.DeleteAccount(b.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.VerifyKey(key); ok {
		t.Error("the deleted account's key still works")
	}
	if _, ok := s.userBySession(tok); ok {
		t.Error("the deleted account's session still works")
	}
	if _, ok := s.BranchOwner("b-dev"); ok {
		t.Error("the deleted account still owns a branch")
	}
	if ps, _ := s.ListPipelines(b.ID); len(ps) != 0 {
		t.Error("the deleted account's pipelines remain")
	}
	list, _ := s.ListAccounts()
	if len(list) != 1 || list[0].ID != a.ID {
		t.Errorf("accounts after delete: %+v", list)
	}
	if err := s.DeleteAccount(b.ID); err == nil {
		t.Error("deleting a missing account succeeded")
	}
}

func TestBranchOwners(t *testing.T) {
	s := testStore(t)
	a, _ := s.CreateUser("a@x.com", "password1")
	b, _ := s.CreateUser("b@x.com", "password1")
	_ = s.SetBranchOwner("dev", a.ID)
	if o, ok := s.BranchOwner("dev"); !ok || o != a.ID {
		t.Errorf("owner = %d, %v", o, ok)
	}
	_ = s.SetBranchOwner("dev", b.ID) // the name was used again
	if o, _ := s.BranchOwner("dev"); o != b.ID {
		t.Error("a re-made branch kept its old owner")
	}
	_ = s.ForgetBranch("dev")
	if _, ok := s.BranchOwner("dev"); ok {
		t.Error("ForgetBranch left the owner")
	}
}

// Revoking a key that is not there must say so. It used to answer "revoked" for
// any id, so a typo left the key working while the person believed the door was
// shut (checklist G3).
func TestRevokeUnknownKeyIsRefused(t *testing.T) {
	s := testStore(t)
	// CreateUser, not Register: the first account needs the setup token, which is
	// not what this test is about.
	u, err := s.CreateUser("owner@example.com", "password123")
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := s.CreateAPIKey(u.ID, "real")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeKey(u.ID, "no-such-id"); !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("revoking an unknown id gave %v, want ErrNoSuchKey", err)
	}
	// Another account's key is the same answer, so nothing is learned about it.
	other, err := s.CreateUser("other@example.com", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeKey(other.ID, info.ID); !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("revoking someone else's key gave %v, want ErrNoSuchKey", err)
	}
	// The real one still works, and only once.
	if err := s.RevokeKey(u.ID, info.ID); err != nil {
		t.Errorf("revoking a real key failed: %v", err)
	}
	if err := s.RevokeKey(u.ID, info.ID); !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("revoking it twice gave %v, want ErrNoSuchKey", err)
	}
}
