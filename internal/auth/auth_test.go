// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// testStore opens a Store in a temp dir and closes it when the test ends.
//
// The close is not optional on Windows: t.TempDir's cleanup deletes the
// directory, and Windows refuses to unlink a file that is still open, so a
// leaked handle fails the test in cleanup rather than in the test body.
func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Config{DBPath: filepath.Join(t.TempDir(), "t.db"), WebOrigin: "http://x", SignupOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("closing the store: %v", err)
		}
	})
	return s
}

func TestPasswordLogin(t *testing.T) {
	s := testStore(t)
	if _, err := s.CreateUser("A@x.com", "password1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login("a@x.com", "password1"); err != nil { // case-insensitive
		t.Errorf("login should succeed: %v", err)
	}
	if _, err := s.Login("a@x.com", "wrong"); err == nil {
		t.Error("wrong password should fail")
	}
	if _, err := s.CreateUser("a@x.com", "password1"); err == nil {
		t.Error("duplicate email should fail")
	}
}

func TestAPIKeys(t *testing.T) {
	s := testStore(t)
	u, _ := s.CreateUser("k@x.com", "password1")
	secret, info, err := s.CreateAPIKey(u.ID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	if got, scope, ok := s.VerifyKey(secret); !ok || scope != "" || got.ID != u.ID {
		t.Errorf("verify key failed: ok=%v", ok)
	}
	if _, _, ok := s.VerifyKey("key_wrong"); ok {
		t.Error("bad key should not verify")
	}
	if err := s.RevokeKey(u.ID, info.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.VerifyKey(secret); ok {
		t.Error("revoked key should not verify")
	}
}

// TestVerifyKeyConcurrent reproduces the SQLITE_BUSY regression: many
// simultaneous authenticated requests must all verify, not be rejected as
// invalid because a concurrent last_used write hit a lock.
func TestVerifyKeyConcurrent(t *testing.T) {
	s := testStore(t)
	u, _ := s.CreateUser("c@x.com", "password1")
	secret, _, err := s.CreateAPIKey(u.ID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	const n = 32
	var wg sync.WaitGroup
	var fails int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, ok := s.VerifyKey(secret); !ok {
				atomic.AddInt64(&fails, 1)
			}
		}()
	}
	wg.Wait()
	if fails != 0 {
		t.Errorf("%d/%d concurrent VerifyKey calls were rejected (SQLITE_BUSY regression)", fails, n)
	}
}

func TestSessions(t *testing.T) {
	s := testStore(t)
	u, _ := s.CreateUser("s@x.com", "password1")
	tok, err := s.createSession(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := s.userBySession(tok); !ok || got.ID != u.ID {
		t.Error("session lookup failed")
	}
	s.deleteSession(tok)
	if _, ok := s.userBySession(tok); ok {
		t.Error("deleted session should be invalid")
	}
}

// A scoped key is an agent's credential for one branch. It must round-trip its
// scope, must not authenticate an HTTP request (that would hand an agent the
// control plane), and must be revocable without touching account keys.
func TestScopedKeys(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("a@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := s.CreateAPIKey(u.ID, "account")
	if err != nil {
		t.Fatal(err)
	}
	scoped, info, err := s.CreateScopedAPIKey(u.ID, "agent agent-alice", "agent-alice")
	if err != nil {
		t.Fatal(err)
	}
	if info.Scope != "agent-alice" {
		t.Errorf("KeyInfo.Scope = %q, want agent-alice", info.Scope)
	}

	if got, scope, ok := s.VerifyKey(scoped); !ok || scope != "agent-alice" || got.ID != u.ID {
		t.Errorf("VerifyKey(scoped) = %v/%q/%v, want the owner, agent-alice, true", got.ID, scope, ok)
	}
	if _, scope, ok := s.VerifyKey(plain); !ok || scope != "" {
		t.Errorf("VerifyKey(account key) scope = %q, want empty", scope)
	}

	// The gate that keeps an agent out of the control plane and the Agent API.
	req := httptest.NewRequest("GET", "/api/branches", nil)
	req.Header.Set("Authorization", "Bearer "+scoped)
	if _, ok := s.userFromRequest(req); ok {
		t.Error("a branch-scoped key must not authenticate an HTTP request")
	}
	req = httptest.NewRequest("GET", "/api/branches", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	if _, ok := s.userFromRequest(req); !ok {
		t.Error("an account key must still authenticate an HTTP request")
	}

	// Listings carry the scope, so a person can tell the two kinds apart.
	keys, err := s.listAPIKeys(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for _, k := range keys {
		if k.ID == info.ID && k.Scope == "agent-alice" {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("the scoped key was not listed with its scope: %+v", keys)
	}

	// Deleting the branch revokes its key and leaves account keys alone.
	if err := s.RevokeScopeKeys("agent-alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.VerifyKey(scoped); ok {
		t.Error("the scoped key still works after its branch was revoked")
	}
	if _, _, ok := s.VerifyKey(plain); !ok {
		t.Error("revoking a scope must not touch account keys")
	}
	if err := s.RevokeScopeKeys(""); err != nil {
		t.Errorf("an empty scope should be a no-op, got %v", err)
	}
	if _, _, ok := s.VerifyKey(plain); !ok {
		t.Error("an empty scope deleted unscoped keys — every account key would be lost")
	}
}

// Every existing install already has an api_keys table, and the schema runs
// with CREATE TABLE IF NOT EXISTS, so without a migration the scope column
// would never appear and scoping would silently not exist.
func TestScopeColumnAddedToExistingStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL
);
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL,
  key_hash TEXT NOT NULL, prefix TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER
);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(Config{DBPath: path, WebOrigin: "http://x", SignupOpen: true})
	if err != nil {
		t.Fatalf("opening a pre-scope store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("closing the store: %v", err)
		}
	})

	u, err := store.CreateUser("m@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := store.CreateScopedAPIKey(u.ID, "agent", "agent-x")
	if err != nil {
		t.Fatalf("minting a scoped key on a migrated store: %v", err)
	}
	if _, scope, ok := store.VerifyKey(key); !ok || scope != "agent-x" {
		t.Errorf("scope after migration = %q/%v, want agent-x/true", scope, ok)
	}
}

// On a new install `fox start` launches three servers that all create the store
// at once. Some used to lose with SQLITE_BUSY and exit, leaving the control
// plane and the Agent API down after the first start.
func TestConcurrentFirstOpen(t *testing.T) {
	const rounds, servers = 40, 4
	fails := 0
	for round := 0; round < rounds; round++ {
		path := filepath.Join(t.TempDir(), "fresh.db")
		var wg sync.WaitGroup
		errs := make(chan error, servers)
		for i := 0; i < servers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, err := Open(Config{DBPath: path, WebOrigin: "http://x", SignupOpen: true})
				if err != nil {
					errs <- err
					return
				}
				if err := s.Close(); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if fails++; fails <= 3 {
				t.Errorf("round %d: opening a new store alongside others: %v", round, err)
			}
		}
	}
	if fails > 3 {
		t.Errorf("%d of %d opens failed in total", fails, rounds*servers)
	}
}
