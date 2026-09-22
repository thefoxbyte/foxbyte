// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func storeWith(t *testing.T) (*auth.Store, auth.User, auth.User, auth.User) {
	t.Helper()
	s, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x", SignupOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	admin, _ := s.CreateUser("admin@x.com", "password1")
	alice, _ := s.CreateUser("alice@x.com", "password1")
	bob, _ := s.CreateUser("bob@x.com", "password1")
	return s, admin, alice, bob
}

func TestLevels(t *testing.T) {
	s, admin, alice, bob := storeWith(t)
	c := NewWith(s, func(e string) bool { return e == "admin@x.com" })
	if err := c.Own(alice, "alice-dev"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		who    auth.User
		branch string
		want   Level
	}{
		{admin, "alice-dev", Manage}, // an admin reaches everything
		{admin, "nobodys", Manage},
		{alice, "alice-dev", Manage}, // the owner
		{bob, "alice-dev", None},     // someone else's branch is not there
		{alice, "main", Use},         // main is shared
		{bob, "", Use},               // "" is main
		{alice, "nobodys", None},     // no owner: an admin's
		{auth.User{}, "main", Use},   // (no account id cannot own anything)
		{auth.User{}, "alice-dev", None},
	} {
		if got := c.Level(tc.who, tc.branch); got != tc.want {
			t.Errorf("%s on %q: %v, want %v", tc.who.Email, tc.branch, got, tc.want)
		}
	}
	// A deleted branch's owner is forgotten, so a new branch of that name is
	// not handed to the old owner.
	c.Forget("alice-dev")
	if c.Level(alice, "alice-dev") != None {
		t.Error("the owner of a deleted branch still reaches a branch of the same name")
	}
	// A deleted account's branches go to the admins.
	_ = c.Own(bob, "bob-dev")
	if err := s.DeleteAccount(bob.ID); err != nil {
		t.Fatal(err)
	}
	if c.Level(bob, "bob-dev") != None {
		t.Error("a deleted account still owns its branch")
	}
}

func TestAdminIsCachedBriefly(t *testing.T) {
	s, _, alice, _ := storeWith(t)
	calls, admin := 0, true
	c := NewWith(s, func(string) bool { calls++; return admin })
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.Admin(alice)
	c.Admin(alice)
	if calls != 1 {
		t.Errorf("asked %d times inside the TTL, want 1", calls)
	}
	admin = false
	now = now.Add(adminTTL)
	if c.Admin(alice) || calls != 2 {
		t.Errorf("a revoked admin was still an admin after the TTL (calls %d)", calls)
	}
}
