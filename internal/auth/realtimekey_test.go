// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// A realtime key streams one branch and does nothing else.
//
// The claim this kind is sold on is a negative one — it cannot reach the
// control plane and cannot run SQL — and a negative claim is only as good as
// its test. The gateway half of it is asserted in internal/proxy and in the
// integration suite, against a real connection.
func TestRealtimeKey(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("a@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	rtk, info, err := s.CreateRealtimeKey(u.ID, "my app", "app")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("is recognisable as one", func(t *testing.T) {
		if !strings.HasPrefix(rtk, RealtimeKeyPrefix) {
			t.Errorf("key %q does not begin with %q — a key in a log should be identifiable without a lookup", rtk, RealtimeKeyPrefix)
		}
		if info.Kind != KindRealtime {
			t.Errorf("Kind = %q, want %q", info.Kind, KindRealtime)
		}
		if info.Scope != "app" {
			t.Errorf("Scope = %q, want the branch it was minted for", info.Scope)
		}
	})

	t.Run("verifies with its kind", func(t *testing.T) {
		gotU, scope, kind, ok := s.VerifyKeyKind(rtk)
		if !ok {
			t.Fatal("a freshly minted realtime key did not verify")
		}
		if gotU.ID != u.ID || scope != "app" || kind != KindRealtime {
			t.Fatalf("VerifyKeyKind = (%d, %q, %q), want (%d, \"app\", %q)", gotU.ID, scope, kind, u.ID, KindRealtime)
		}
	})

	t.Run("streams its own branch", func(t *testing.T) {
		if _, ok := s.UserForRealtime(bearer(rtk), "app"); !ok {
			t.Error("a realtime key could not reach its own branch's feed")
		}
	})

	t.Run("and no other branch", func(t *testing.T) {
		if _, ok := s.UserForRealtime(bearer(rtk), "other"); ok {
			t.Error("a realtime key reached another branch's feed")
		}
	})

	t.Run("is refused at the control plane", func(t *testing.T) {
		// Authn is what guards /api/. A scoped key has always been refused
		// there; a realtime key is scoped, so it inherits that — asserted
		// because the whole shape depends on it, not because it is new.
		if _, ok := s.userFromRequest(bearer(rtk)); ok {
			t.Error("a realtime key authenticated against the control plane")
		}
	})

	t.Run("needs a branch at mint time", func(t *testing.T) {
		// A realtime key with no scope would be a key to every branch's feed,
		// which is the one thing this kind exists not to be.
		if _, _, err := s.CreateRealtimeKey(u.ID, "n", ""); err == nil {
			t.Error("minted a realtime key with no branch")
		}
		if _, _, err := s.CreateRealtimeKey(u.ID, "n", "   "); err == nil {
			t.Error("whitespace passed as a branch name")
		}
	})

	t.Run("appears in the listing as a realtime key", func(t *testing.T) {
		keys, err := s.ListKeys(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, k := range keys {
			if k.ID == info.ID {
				found = true
				if k.Kind != KindRealtime {
					t.Errorf("listed Kind = %q, want %q", k.Kind, KindRealtime)
				}
			}
		}
		if !found {
			t.Error("the key is not in its owner's listing, so it cannot be revoked from there")
		}
	})

	t.Run("revokes", func(t *testing.T) {
		if err := s.RevokeKey(u.ID, info.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, _, ok := s.VerifyKeyKind(rtk); ok {
			t.Error("a revoked realtime key still verifies")
		}
	})
}

// Every key issued before this kind existed must behave exactly as it did. The
// kind column defaults to empty, and empty is the kind both the control plane
// and the Gateway have always accepted — so an install that migrates loses no
// access. This is the additive half of the change, and the half a migration
// could silently break.
func TestOrdinaryKeysUnchangedByKind(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("b@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	account, _, err := s.CreateAPIKey(u.ID, "ops")
	if err != nil {
		t.Fatal(err)
	}
	scoped, _, err := s.CreateScopedAPIKey(u.ID, "agent", "app")
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, key, wantScope string
	}{
		{"an account key", account, ""},
		{"a branch-scoped key", scoped, "app"},
	} {
		t.Run(c.name+" has the empty kind", func(t *testing.T) {
			_, scope, kind, ok := s.VerifyKeyKind(c.key)
			if !ok {
				t.Fatal("did not verify")
			}
			if kind != "" {
				t.Errorf("kind = %q, want empty — this key predates kinds and must act like it", kind)
			}
			if scope != c.wantScope {
				t.Errorf("scope = %q, want %q", scope, c.wantScope)
			}
		})
	}

	// VerifyKey keeps its old signature and its old answers, so no existing
	// caller had to learn about kinds to stay correct.
	if _, scope, ok := s.VerifyKey(scoped); !ok || scope != "app" {
		t.Errorf("VerifyKey(scoped) = (%q, %v), want (\"app\", true)", scope, ok)
	}
	// An account key still opens the control plane.
	if _, ok := s.userFromRequest(bearer(account)); !ok {
		t.Error("an account key stopped authenticating against the control plane")
	}
	// And a scoped gateway key can still reach the feed of its own branch:
	// removing that would break a subscriber running today.
	if _, ok := s.UserForRealtime(bearer(scoped), "app"); !ok {
		t.Error("a scoped gateway key lost access to its branch's feed")
	}
}

func bearer(key string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	return r
}

// The credential is read from headers only. A key in a query string is written
// to access logs, kept in browser history and sent on in Referer, so accepting
// one there would quietly turn every subscriber's URL into a disclosed secret.
func TestRealtimeKeyNotAcceptedInQuery(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("c@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	rtk, _, err := s.CreateRealtimeKey(u.ID, "app", "app")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"?key=", "?api_key=", "?token=", "?apikey=", "?access_token="} {
		r := httptest.NewRequest("GET", "/realtime/v1/branches/app/stream"+q+rtk, nil)
		if _, ok := s.UserForRealtime(r, "app"); ok {
			t.Errorf("a key in %q authenticated", q)
		}
	}
	// X-API-Key is a header, and is accepted — some clients cannot set
	// Authorization.
	r := httptest.NewRequest("GET", "/realtime/v1/branches/app/stream", nil)
	r.Header.Set("X-API-Key", rtk)
	if _, ok := s.UserForRealtime(r, "app"); !ok {
		t.Error("X-API-Key was not accepted")
	}
}

// An install that predates the kind column must come through the migration with
// every key it had, still working, and must be able to mint realtime keys
// afterwards.
//
// This is the test that matters most in this file. The other failures here are
// a feature not working; a bad migration is an operator locked out of a
// database that was fine before they upgraded. Modelled on the pre-scope store
// test in auth_test.go, including a key written *before* the column existed —
// a fresh store would take the new DDL and never exercise the ALTER TABLE.
func TestKindMigrationKeepsExistingKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// The table as it stood before kinds: scope exists, kind does not.
	if _, err := db.Exec(`
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL
);
CREATE TABLE api_keys (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL,
  key_hash TEXT NOT NULL, prefix TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER,
  scope TEXT NOT NULL DEFAULT ''
);
INSERT INTO users(id,email,pw_hash,created) VALUES(1,'old@x.com','',0);`); err != nil {
		t.Fatal(err)
	}
	// A key issued by the old code: hashed the same way, with no kind column to
	// put anything in.
	const oldSecret = KeyPrefix + "already-issued-before-kinds"
	if _, err := db.Exec(`INSERT INTO api_keys(id,user_id,name,key_hash,prefix,created,scope)
		VALUES('k1',1,'agent',?,?,0,'legacy-branch')`, hashKey(oldSecret), oldSecret[:12]); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(Config{DBPath: path, WebOrigin: "http://x", SignupOpen: true})
	if err != nil {
		t.Fatalf("opening a pre-kind store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("closing the store: %v", err)
		}
	})

	// The key that was already there still opens what it always opened.
	u, scope, kind, ok := store.VerifyKeyKind(oldSecret)
	if !ok {
		t.Fatal("a key issued before the migration stopped working — this would lock an install out")
	}
	if scope != "legacy-branch" {
		t.Errorf("scope = %q, want legacy-branch", scope)
	}
	if kind != "" {
		t.Errorf("kind = %q, want empty: a key from before kinds must act exactly as it did", kind)
	}
	if u.Email != "old@x.com" {
		t.Errorf("owner = %q, want old@x.com", u.Email)
	}
	// And it can still reach the feed of its own branch, as it could before.
	if _, ok := store.UserForRealtime(bearer(oldSecret), "legacy-branch"); !ok {
		t.Error("a pre-migration scoped key lost access to its branch's feed")
	}

	// Realtime keys work on the migrated store.
	rtk, info, err := store.CreateRealtimeKey(1, "app", "app")
	if err != nil {
		t.Fatalf("minting a realtime key on a migrated store: %v", err)
	}
	if _, _, kind, ok := store.VerifyKeyKind(rtk); !ok || kind != KindRealtime {
		t.Errorf("new key on migrated store = (%q, %v), want (%q, true)", kind, ok, KindRealtime)
	}
	// Both keys are listed, each with its own kind.
	keys, err := store.ListKeys(1)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, k := range keys {
		got[k.ID] = k.Kind
	}
	if got["k1"] != "" || got[info.ID] != KindRealtime {
		t.Errorf("listed kinds = %v, want k1 empty and %s realtime", got, info.ID)
	}

	// Re-opening runs migrate again, and every step must be safe to repeat.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(Config{DBPath: path, WebOrigin: "http://x", SignupOpen: true})
	if err != nil {
		t.Fatalf("re-opening a migrated store: %v", err)
	}
	defer func() { _ = again.Close() }()
	if _, _, _, ok := again.VerifyKeyKind(oldSecret); !ok {
		t.Error("the old key stopped working on the second open")
	}
}
