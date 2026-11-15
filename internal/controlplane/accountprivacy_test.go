// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// accountRoutes is the account endpoints behind the auth gate, the way Serve
// mounts them, with the HA and Postgres parts stubbed out.
func accountRoutes(t *testing.T, s *auth.Store) http.Handler {
	t.Helper()
	oldCopy, oldRevoke := isACopy, revokeMainAdmin
	isACopy = func() bool { return false }
	revokeMainAdmin = func(string) error { return nil }
	t.Cleanup(func() { isACopy, revokeMainAdmin = oldCopy, oldRevoke })
	api := http.NewServeMux()
	registerAccounts(api, s)
	s.MountKeys(api)
	root := http.NewServeMux()
	s.MountPublic(root)
	root.Handle("/api/", s.Authn(api))
	return root
}

func call(h http.Handler, method, path, body string, set func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if set != nil {
		set(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func bearer(k string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+k) }
}

func TestAccountExportIsOwnDataWithoutSecrets(t *testing.T) {
	s, _, alice, bob := withACL(t)
	h := accountRoutes(t, s)
	ka, _, _ := s.CreateAPIKey(alice.ID, "alice laptop")
	kb, _, _ := s.CreateAPIKey(bob.ID, "bob laptop")
	_ = acl.Own(bob, "bob-dev")
	s.Audit(auth.EvLoginOK, "alice@x.com", "alice@x.com", "10.0.0.1", "")
	s.Audit(auth.EvLoginOK, "bob@x.com", "bob@x.com", "10.0.0.2", "")
	s.Audit(auth.EvKeyRevoked, "admin@x.com", "alice@x.com", "10.9.9.9", "")
	// A session, so the export has one to describe.
	if w := call(h, "POST", "/auth/login", `{"email":"alice@x.com","password":"password1"}`, nil); w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}

	w := call(h, "GET", "/api/account/export", "", bearer(ka))
	if w.Code != 200 {
		t.Fatalf("export: %d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	var exp auth.AccountExport
	if err := json.Unmarshal(w.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Profile.Email != "alice@x.com" || len(exp.Keys) != 1 || exp.Keys[0].Name != "alice laptop" ||
		len(exp.Branches) != 1 || exp.Branches[0].Name != "alice-dev" || len(exp.Sessions) != 1 {
		t.Errorf("export: %+v", exp)
	}
	for _, e := range exp.Events {
		if e.Kind == auth.EvKeyRevoked && e.IP != "" {
			t.Errorf("the admin's address is in alice's export: %+v", e)
		}
	}
	if len(exp.Events) < 3 { // her sign-in, the key revoke, the login just now
		t.Errorf("events: %+v", exp.Events)
	}
	// Nothing of bob's, and no secret of anyone's.
	for _, bad := range []string{"bob", "10.0.0.2", ka, kb, "$2a$", "key_hash", "pw_hash", "token"} {
		if strings.Contains(body, bad) {
			t.Errorf("the export contains %q", bad)
		}
	}
}

func TestSelfDeleteNeedsReauthentication(t *testing.T) {
	s, _, alice, _ := withACL(t)
	h := accountRoutes(t, s)
	ka, _, _ := s.CreateAPIKey(alice.ID, "t")
	s.Audit(auth.EvLoginOK, "alice@x.com", "alice@x.com", "10.0.0.1", "")

	// A key alone, with no password: refused.
	if w := call(h, "DELETE", "/api/account", "", bearer(ka)); w.Code != 403 {
		t.Fatalf("with a key and no password: %d %s", w.Code, w.Body)
	}
	if w := call(h, "DELETE", "/api/account", `{"password":"wrong-one"}`, bearer(ka)); w.Code != 403 {
		t.Fatalf("with the wrong password: %d %s", w.Code, w.Body)
	}
	if _, ok := s.UserByEmail("alice@x.com"); !ok {
		t.Fatal("a refused deletion deleted the account")
	}
	w := call(h, "DELETE", "/api/account", `{"password":"password1"}`, bearer(ka))
	if w.Code != 200 {
		t.Fatalf("with the password: %d %s", w.Code, w.Body)
	}
	if _, ok := s.UserByEmail("alice@x.com"); ok {
		t.Fatal("the account is still there")
	}
	if _, _, ok := s.VerifyKey(ka); ok {
		t.Error("her key still works")
	}
	evs, _ := s.SecurityEvents(0, 0)
	for _, e := range evs {
		if strings.Contains(e.Actor+e.Subject+e.Detail, "alice@x.com") {
			t.Errorf("event %d still names her: %+v", e.ID, e)
		}
	}
	if _, problems := auth.VerifyEvents(evs); len(problems) > 0 {
		t.Errorf("the log does not verify: %v", problems)
	}
}

func TestSelfDeleteWithARecentSignIn(t *testing.T) {
	s, _, _, _ := withACL(t)
	h := accountRoutes(t, s)
	w := call(h, "POST", "/auth/login", `{"email":"bob@x.com","password":"password1"}`, nil)
	if w.Code != 200 {
		t.Fatalf("login: %d", w.Code)
	}
	cookies := w.Result().Cookies()
	withCookie := func(r *http.Request) {
		for _, c := range cookies {
			r.AddCookie(c)
		}
	}
	if w := call(h, "DELETE", "/api/account", "", withCookie); w.Code != 200 {
		t.Fatalf("just signed in: %d %s", w.Code, w.Body)
	}
	if _, ok := s.UserByEmail("bob@x.com"); ok {
		t.Fatal("still there")
	}
}

func TestSelfDeleteRefusedForTheLastAdmin(t *testing.T) {
	s, admin, alice, _ := withACL(t)
	h := accountRoutes(t, s)
	k, _, _ := s.CreateAPIKey(admin.ID, "t")
	if w := call(h, "DELETE", "/api/account", `{"password":"password1"}`, bearer(k)); w.Code != 409 {
		t.Fatalf("the only admin: %d %s", w.Code, w.Body)
	}
	if _, ok := s.UserByEmail("admin@x.com"); !ok {
		t.Fatal("the only admin was deleted")
	}
	// With a second admin it goes through.
	acl = access.NewWith(s, func(e string) bool { return e == "admin@x.com" || e == alice.Email })
	if w := call(h, "DELETE", "/api/account", `{"password":"password1"}`, bearer(k)); w.Code != 200 {
		t.Fatalf("with another admin: %d %s", w.Code, w.Body)
	}
}

// An admin deleting someone else pseudonymises them too.
func TestAdminDeletePseudonymises(t *testing.T) {
	s, admin, alice, _ := withACL(t)
	h := accountRoutes(t, s)
	k, _, _ := s.CreateAPIKey(admin.ID, "t")
	s.Audit(auth.EvLoginOK, "alice@x.com", "alice@x.com", "10.0.0.1", "")
	w := call(h, "DELETE", "/api/users/"+itoa64(alice.ID), "", bearer(k))
	if w.Code != 200 {
		t.Fatalf("admin delete: %d %s", w.Code, w.Body)
	}
	evs, _ := s.SecurityEvents(0, 0)
	for _, e := range evs {
		if strings.Contains(e.Actor+e.Subject+e.Detail+e.IP, "alice@x.com") || e.IP == "10.0.0.1" {
			t.Errorf("event %d still holds her data: %+v", e.ID, e)
		}
	}
	if _, problems := auth.VerifyEvents(evs); len(problems) > 0 {
		t.Errorf("the log does not verify: %v", problems)
	}
}

func itoa64(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
