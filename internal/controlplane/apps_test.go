// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// appsServer is the applications routes behind real sign-in, with no engine:
// copying into branches and asking them whether they are ready are counted
// rather than done.
func appsServer(t *testing.T) (*auth.Store, func(key, method, path, body string) (int, map[string]any), map[string]string, *int) {
	t.Helper()
	s, admin, alice, _ := withACL(t)
	synced := 0
	oldSync, oldReady := syncAll, identityReadiness
	syncAll = func() map[string]string { synced++; return nil }
	identityReadiness = func() (map[string]string, error) { return map[string]string{"main": "checked"}, nil }
	t.Cleanup(func() { syncAll, identityReadiness = oldSync, oldReady })
	mux := http.NewServeMux()
	registerApps(mux, s)
	h := s.Authn(mux)
	keys := map[string]string{}
	for name, u := range map[string]auth.User{"admin": admin, "alice": alice} {
		k, _, _ := s.CreateAPIKey(u.ID, "t")
		keys[name] = k
	}
	return s, func(key, method, path, body string) (int, map[string]any) {
		return serve(t, h, key, method, path, body)
	}, keys, &synced
}

func pubHex(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub)
}

func TestAppsRoutesAreAdminsOnly(t *testing.T) {
	_, call, k, synced := appsServer(t)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/apps", ""},
		{"POST", "/api/apps", `{"name":"shop","account":"alice@x.com"}`},
		{"DELETE", "/api/apps/shop", ""},
		{"POST", "/api/apps/shop/keys", `{"public_key":"` + pubHex(t) + `"}`},
		{"POST", "/api/apps/shop/keys/k1/revoke", ""},
	} {
		if code, _ := call(k["alice"], c.method, c.path, c.body); code != 403 {
			t.Errorf("alice, %s %s: %d, want 403", c.method, c.path, code)
		}
	}
	if *synced != 0 {
		t.Errorf("a refused change was copied to the branches %d times", *synced)
	}
}

func TestAppsRoutes(t *testing.T) {
	s, call, k, synced := appsServer(t)
	key1 := pubHex(t)
	code, out := call(k["admin"], "POST", "/api/apps",
		`{"name":"shop","account":"alice@x.com","max_life_seconds":120,"on_invalid":"refuse","public_key":"`+key1+`","kid":"k1"}`)
	app, _ := out["app"].(map[string]any)
	if code != 200 || app["account"] != "alice@x.com" || app["max_life_seconds"] != float64(120) || app["on_invalid"] != "refuse" ||
		len(app["keys"].([]any)) != 1 {
		t.Fatalf("register: %d %v", code, out)
	}
	if *synced != 1 {
		t.Errorf("registering copied to the branches %d times, want once", *synced)
	}
	if code, _ := call(k["admin"], "POST", "/api/apps", `{"name":"shop","account":"alice@x.com"}`); code != 409 {
		t.Errorf("a second registration under one name: %d, want 409", code)
	}
	// A key that is not one is refused before anything is written.
	if code, _ := call(k["admin"], "POST", "/api/apps", `{"name":"other","account":"alice@x.com","public_key":"nonsense"}`); code != 400 {
		t.Errorf("a registration with a bad key: %d, want 400", code)
	}
	if _, err := s.App("other"); err == nil {
		t.Error("a registration with a bad key was kept")
	}

	code, out = call(k["admin"], "POST", "/api/apps/shop/keys", `{"public_key":"`+pubHex(t)+`"}`)
	if code != 200 || out["key"].(map[string]any)["kid"] == "" || len(out["app"].(map[string]any)["keys"].([]any)) != 2 {
		t.Fatalf("add a key: %d %v", code, out)
	}
	if code, _ := call(k["admin"], "POST", "/api/apps/shop/keys", `{"public_key":"`+key1+`"}`); code != 400 {
		t.Errorf("the same key twice: %d, want 400", code)
	}
	if code, _ := call(k["admin"], "POST", "/api/apps/nope/keys", `{"public_key":"`+pubHex(t)+`"}`); code != 404 {
		t.Errorf("a key for no application: %d, want 404", code)
	}

	code, out = call(k["admin"], "POST", "/api/apps/shop/keys/k1/revoke", `{"compromised_since":"2026-10-22T09:00:00Z"}`)
	if code != 200 {
		t.Fatalf("revoke: %d %v", code, out)
	}
	a, _ := s.App("shop")
	for _, key := range a.Keys {
		switch {
		case key.Kid == "k1" && (key.Active() || key.CompromisedSince == nil || *key.CompromisedSince != 1792659600):
			t.Errorf("k1 after revoking it: %+v", key)
		case key.Kid != "k1" && !key.Active():
			t.Errorf("revoking k1 revoked %s too", key.Kid)
		}
	}
	if code, _ := call(k["admin"], "POST", "/api/apps/shop/keys/k1/revoke", `{"compromised_since":"yesterday"}`); code != 400 {
		t.Errorf("an unreadable time: %d, want 400", code)
	}
	if code, _ := call(k["admin"], "POST", "/api/apps/shop/keys/nope/revoke", ""); code != 404 {
		t.Errorf("revoking a key that is not there: %d, want 404", code)
	}

	code, out = call(k["admin"], "GET", "/api/apps", "")
	if code != 200 || len(out["apps"].([]any)) != 1 || out["install_id"] == "" || out["readiness"].(map[string]any)["main"] != "checked" {
		t.Fatalf("list: %d %v", code, out)
	}

	if code, _ := call(k["admin"], "DELETE", "/api/apps/shop", ""); code != 200 {
		t.Fatalf("remove: %d", code)
	}
	if code, _ := call(k["admin"], "DELETE", "/api/apps/shop", ""); code != 404 {
		t.Errorf("remove twice: %d, want 404", code)
	}
	if *synced != 4 {
		t.Errorf("four changes made, copied %d times", *synced)
	}
}
