// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// counts is how many sessions and API keys an account has.
func counts(t *testing.T, s *Store, uid int64) (sessions, keys int) {
	t.Helper()
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, uid).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id=?`, uid).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	return sessions, keys
}

// An account made by open sign-up and later joined by a provider sign-in with
// that verified email loses everything the sign-up set up, and the provider's
// user is left with an account only they can enter.
func TestOAuthLinkCleansAnOpenSignup(t *testing.T) {
	tokenIn(t)
	s := testStore(t) // sign-up open
	if _, err := s.CreateUser("admin@x.com", "password1"); err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("owner@x.com", "password1", "")
	if err != nil {
		t.Fatal(err)
	}
	if proven, _ := s.EmailProven(u.ID); proven {
		t.Fatal("an open sign-up counted as a proven email")
	}
	if _, err := s.createSession(u.ID); err != nil {
		t.Fatal(err)
	}
	key, _, err := s.CreateAPIKey(u.ID, "k")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateScopedAPIKey(u.ID, "agent", "b1"); err != nil {
		t.Fatal(err)
	}

	got, err := s.upsertOAuth("google", "g1", "owner@x.com", true, "10.0.0.1")
	if err != nil || got.ID != u.ID {
		t.Fatalf("provider sign-in: %+v, %v; want account %d", got, err, u.ID)
	}
	if _, err := s.Login("owner@x.com", "password1"); err == nil {
		t.Error("the sign-up's password still works after the provider proved the email")
	}
	if ns, nk := counts(t, s, u.ID); ns != 0 || nk != 0 {
		t.Errorf("after the take-over: %d sessions, %d keys; want none", ns, nk)
	}
	if _, _, ok := s.VerifyKey(key); ok {
		t.Error("the sign-up's API key still verifies")
	}
	if proven, _ := s.EmailProven(u.ID); !proven {
		t.Error("the email is still unproven after a verified provider sign-in")
	}
	ev, err := s.LastSecurityEventOfKind(EvAccountClaimed)
	if err != nil || ev == nil || ev.Subject != "owner@x.com" || ev.IP != "10.0.0.1" {
		t.Fatalf("security log: %+v, %v", ev, err)
	}

	// Now proven, a later password and key are the owner's own and survive the
	// next provider sign-in.
	if err := s.ChangePassword(u.ID, "", "password2", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateAPIKey(u.ID, "mine"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.upsertOAuth("github", "h1", "owner@x.com", true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login("owner@x.com", "password2"); err != nil {
		t.Errorf("the owner's own password was wiped by a second provider: %v", err)
	}
	if _, nk := counts(t, s, u.ID); nk != 1 {
		t.Errorf("the owner's own key: %d keys, want 1", nk)
	}
	if evs, _ := s.SecurityEventsOfKind(EvAccountClaimed); len(evs) != 1 {
		t.Errorf("%d take-over events, want 1", len(evs))
	}
}

// An account an admin made, and the first account made with the setup token,
// have proven emails: a provider sign-in joins them and takes nothing away.
func TestOAuthLinkKeepsProvenAccounts(t *testing.T) {
	tokenIn(t)
	s := closedStore(t)
	tok, err := EnsureSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Register("first@x.com", "password1", tok)
	if err != nil {
		t.Fatal(err)
	}
	made, err := s.CreateUser("made@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.SignupOpen = true
	for _, u := range []User{first, made} {
		if proven, _ := s.EmailProven(u.ID); !proven {
			t.Errorf("%s: not proven", u.Email)
		}
		if _, err := s.createSession(u.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.CreateAPIKey(u.ID, "k"); err != nil {
			t.Fatal(err)
		}
		if got, err := s.upsertOAuth("github", "s-"+u.Email, u.Email, true, ""); err != nil || got.ID != u.ID {
			t.Fatalf("%s: provider sign-in: %+v, %v", u.Email, got, err)
		}
		if _, err := s.Login(u.Email, "password1"); err != nil {
			t.Errorf("%s: password wiped: %v", u.Email, err)
		}
		if ns, nk := counts(t, s, u.ID); ns != 1 || nk != 1 {
			t.Errorf("%s: %d sessions, %d keys after linking; want 1 and 1", u.Email, ns, nk)
		}
	}
	if evs, _ := s.SecurityEventsOfKind(EvAccountClaimed); len(evs) != 0 {
		t.Errorf("%d take-over events for proven accounts, want none", len(evs))
	}
}

// A new account made by a provider sign-in has a proven email.
func TestOAuthSignupIsProven(t *testing.T) {
	tokenIn(t)
	s := testStore(t)
	if _, err := s.CreateUser("admin@x.com", "password1"); err != nil {
		t.Fatal(err)
	}
	u, err := s.upsertOAuth("google", "n1", "new@x.com", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if proven, _ := s.EmailProven(u.ID); !proven {
		t.Error("an account made by a verified provider sign-in is unproven")
	}
}

// Accounts that existed before the table did are all proven, so upgrading
// changes nothing for them, and the table appears on an old store.
func TestExistingAccountsAreProvenAfterMigration(t *testing.T) {
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
INSERT INTO users(email, pw_hash, created) VALUES ('old@x.com', '', 1);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(Config{DBPath: path, WebOrigin: "http://x", SignupOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	old, ok := s.UserByEmail("old@x.com")
	if !ok {
		t.Fatal("the old account is gone")
	}
	if proven, err := s.EmailProven(old.ID); err != nil || !proven {
		t.Errorf("an existing account after migration: proven=%v, %v", proven, err)
	}
	if _, _, err := s.CreateAPIKey(old.ID, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.upsertOAuth("github", "o1", "old@x.com", true, ""); err != nil {
		t.Fatal(err)
	}
	if _, nk := counts(t, s, old.ID); nk != 1 {
		t.Errorf("an existing account lost its keys on a provider sign-in: %d keys", nk)
	}
}
