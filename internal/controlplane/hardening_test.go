// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"testing"
)

// Admins only, and a branch name that is not one is refused before anything
// is read.
func TestHardeningRoute(t *testing.T) {
	s, admin, alice, _ := withACL(t)
	mux := http.NewServeMux()
	registerHardening(mux)
	h := s.Authn(mux)
	ka, _, _ := s.CreateAPIKey(admin.ID, "t")
	kb, _, _ := s.CreateAPIKey(alice.ID, "t")
	if code, _ := serve(t, h, kb, "GET", "/api/hardening", ""); code != 403 {
		t.Errorf("a user who is not an admin: %d", code)
	}
	if code, _ := serve(t, h, ka, "GET", "/api/hardening?branch=..%2Fx", ""); code != 400 {
		t.Errorf("a name that is not a branch's: %d", code)
	}
}
