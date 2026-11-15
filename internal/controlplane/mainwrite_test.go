// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func TestMainWriteRoutes(t *testing.T) {
	s, admin, alice, bob := withACL(t)
	oldLog := secLog
	secLog = s
	t.Cleanup(func() { secLog = oldLog })
	applied, appliedFor := 0, []string{}
	oldA, oldF, oldL := applyMainWrite, applyMainWriteFor, listMainAdmins
	applyMainWrite = func() error { applied++; return nil }
	applyMainWriteFor = func(e string) error { appliedFor = append(appliedFor, e); return nil }
	listMainAdmins = func() ([]string, error) { return []string{"admin@x.com"}, nil }
	t.Cleanup(func() { applyMainWrite, applyMainWriteFor, listMainAdmins = oldA, oldF, oldL })
	_ = s.SetMainWriteMode(auth.MainWriteAll) // as an upgraded install is

	mux := http.NewServeMux()
	registerMainWrite(mux, s)
	h := s.Authn(mux)
	keyOf := func(u auth.User) string { k, _, _ := s.CreateAPIKey(u.ID, "t"); return k }
	ka, kadm := keyOf(alice), keyOf(admin)
	do := func(key, method, path, body string) (int, map[string]any) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	if code, _ := do(ka, "GET", "/api/access/main-write", ""); code != 403 {
		t.Errorf("a non-admin read it: %d", code)
	}
	if code, _ := do(ka, "PUT", "/api/access/main-write", `{"mode":"granted"}`); code != 403 {
		t.Errorf("a non-admin set it: %d", code)
	}
	code, out := do(kadm, "GET", "/api/access/main-write", "")
	if code != 200 || out["mode"] != "all" {
		t.Fatalf("GET: %d %v", code, out)
	}
	if code, _ := do(kadm, "PUT", "/api/access/main-write", `{"mode":"everyone"}`); code != 400 {
		t.Errorf("an unknown mode: %d", code)
	}
	code, out = do(kadm, "POST", "/api/access/main-write/writers", `{"email":"Bob@x.com"}`)
	if code != 200 || len(appliedFor) != 1 || appliedFor[0] != "bob@x.com" {
		t.Fatalf("grant: %d %v %v", code, out, appliedFor)
	}
	// Switching names who loses write: alice, not the admin and not bob.
	code, out = do(kadm, "PUT", "/api/access/main-write", `{"mode":"granted"}`)
	if code != 200 || applied != 1 {
		t.Fatalf("PUT: %d %v (applied %d)", code, out, applied)
	}
	if lost, _ := out["lost_write"].([]any); len(lost) != 1 || lost[0] != alice.Email {
		t.Errorf("lost_write = %v, want [alice]", out["lost_write"])
	}
	if m, _ := s.MainWriteMode(); m != auth.MainWriteGranted {
		t.Errorf("mode = %q", m)
	}
	if code, _ := do(kadm, "DELETE", "/api/access/main-write/writers/bob@x.com", ""); code != 200 {
		t.Errorf("revoke: %d", code)
	}
	if ok, _ := s.HasMainWriteGrant(bob.ID); ok {
		t.Error("bob kept his grant")
	}
	if code, _ := do(kadm, "DELETE", "/api/access/main-write/writers/nobody@x.com", ""); code != 404 {
		t.Errorf("revoke for no account: %d", code)
	}

	// Each change is in the security log, intent then outcome.
	evs, _ := s.SecurityEvents(0, 0)
	var kinds []string
	for _, e := range evs {
		if strings.HasPrefix(e.Kind, "main-write.") {
			kinds = append(kinds, e.Kind)
		}
	}
	want := []string{auth.EvMainWriteGrantStarted, auth.EvMainWriteGranted, auth.EvMainWriteModeStarted,
		auth.EvMainWriteModeSet, auth.EvMainWriteRevokeStarted, auth.EvMainWriteRevoked}
	if strings.Join(kinds, " ") != strings.Join(want, " ") {
		t.Errorf("logged %v, want %v", kinds, want)
	}
}

// The console names the reason when Postgres refuses a change to main that
// the account may not make, and leaves every other error alone.
func TestConsoleSaysMainIsReadOnly(t *testing.T) {
	s, _, alice, _ := withACL(t)
	oldLog := secLog
	secLog = s
	t.Cleanup(func() { secLog = oldLog })
	denied := func() map[string]any {
		return map[string]any{"error": "ERROR: permission denied for table orders (SQLSTATE 42501)"}
	}
	out := withMainWriteHint(queryAs{Branch: "main", Actor: alice.Email}, denied())
	if h, _ := out["hint"].(string); !strings.Contains(h, "main is read-only for your account") ||
		!strings.Contains(h, "access write grant alice@x.com") {
		t.Errorf("hint = %q", h)
	}
	for _, as := range []queryAs{{Branch: "alice-dev", Actor: alice.Email}, {Branch: "main"}} {
		if out := withMainWriteHint(as, denied()); out["hint"] != nil {
			t.Errorf("%+v: a hint off main or with no account: %v", as, out["hint"])
		}
	}
	if out := withMainWriteHint(queryAs{Branch: "main", Actor: alice.Email},
		map[string]any{"error": "syntax error"}); out["hint"] != nil {
		t.Error("a syntax error was blamed on main being read-only")
	}
	_ = s.GrantMainWrite(alice.ID, "admin@x.com")
	if out := withMainWriteHint(queryAs{Branch: "main", Actor: alice.Email}, denied()); out["hint"] != nil {
		t.Error("a granted account was told main is read-only")
	}
}
