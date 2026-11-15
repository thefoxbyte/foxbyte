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

// A grant or revoke the security log records reaches the cache within a
// second, wherever it was made, instead of when the old answer expires.
func TestARecordedRevokeBitesWithinASecond(t *testing.T) {
	s, _, alice, _ := storeWith(t)
	calls, admin := 0, true
	c := NewWith(s, func(string) bool { calls++; return admin })
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	if !c.Admin(alice) {
		t.Fatal("not an admin to begin with")
	}

	// Revoked elsewhere (the CLI, another process), and recorded as such.
	admin = false
	s.Audit(auth.EvAdminRevoked, "root@x.com", alice.Email, "", "branch main")

	now = now.Add(epochEvery / 2) // the log is not asked again this soon
	if !c.Admin(alice) || calls != 1 {
		t.Fatalf("asked inside epochEvery (calls %d)", calls)
	}
	now = now.Add(epochEvery) // well inside adminTTL
	if c.Admin(alice) {
		t.Error("a recorded revoke had not bitten after a second")
	}
	if calls != 2 {
		t.Errorf("calls %d, want 2", calls)
	}
}

// Anything else the log records leaves the remembered answers alone.
func TestOtherEventsKeepTheCache(t *testing.T) {
	s, _, alice, _ := storeWith(t)
	calls := 0
	c := NewWith(s, func(string) bool { calls++; return true })
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	c.Admin(alice)
	s.Audit(auth.EvLoginFailed, "", alice.Email, "203.0.113.1", "")
	now = now.Add(2 * epochEvery)
	c.Admin(alice)
	if calls != 1 {
		t.Errorf("an unrelated event emptied the cache (calls %d)", calls)
	}
}

// Who may change main. The test store is a new install, so it records
// "granted": only the admin and an account granted write may. In "all", every
// account may. Off main, using a branch is enough.
func TestMayWriteMain(t *testing.T) {
	s, admin, alice, bob := storeWith(t)
	c := NewWith(s, func(e string) bool { return e == "admin@x.com" })
	if err := c.Own(alice, "alice-dev"); err != nil {
		t.Fatal(err)
	}
	if mode, _ := s.MainWriteMode(); mode != auth.MainWriteGranted {
		t.Fatalf("a new store's mode is %q", mode)
	}
	check := func(when string, want map[string]bool) {
		t.Helper()
		for _, u := range []auth.User{admin, alice, bob} {
			if got := c.MayWriteMain(u); got != want[u.Email] {
				t.Errorf("%s: %s may write main = %v, want %v", when, u.Email, got, want[u.Email])
			}
		}
	}
	check("granted, nobody granted", map[string]bool{"admin@x.com": true})
	if err := s.GrantMainWrite(bob.ID, admin.Email); err != nil {
		t.Fatal(err)
	}
	check("bob granted", map[string]bool{"admin@x.com": true, "bob@x.com": true})
	if !c.MayWrite(alice, "alice-dev") || c.MayWrite(bob, "alice-dev") {
		t.Error("off main, writing a branch is using it")
	}
	if c.MayWrite(alice, "") || !c.MayWrite(bob, "main") {
		t.Error("MayWrite on main is not MayWriteMain")
	}
	if err := s.SetMainWriteMode(auth.MainWriteAll); err != nil {
		t.Fatal(err)
	}
	check("all", map[string]bool{"admin@x.com": true, "alice@x.com": true, "bob@x.com": true})
	if c.MayWriteMain(auth.User{}) {
		t.Error("no account at all may write main")
	}
	// Reading main stays Use for everybody, in either mode.
	_ = s.SetMainWriteMode(auth.MainWriteGranted)
	if c.Level(alice, "main") != Use {
		t.Error("a read-only account lost Use on main")
	}
}
