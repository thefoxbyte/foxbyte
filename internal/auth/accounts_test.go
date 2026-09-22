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
	if err := s.ResetPassword("a@x.com", "password3"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.userBySession(mine); ok {
		t.Error("an admin reset left a session signed in")
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
