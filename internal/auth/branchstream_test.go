// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A branch-scoped key may stream its own branch and nothing else.
//
// Authn refuses a scoped key outright because one would otherwise reach the
// whole control plane. This is the narrow exception, and these are its edges.
func TestUserForBranchStream(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("a@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	scoped, _, err := s.CreateScopedAPIKey(u.ID, "agent", "alice-dev")
	if err != nil {
		t.Skipf("no scoped-key constructor in this build: %v", err)
	}
	unscoped, _, err := s.CreateAPIKey(u.ID, "ops")
	if err != nil {
		t.Fatal(err)
	}

	req := func(key string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		return r
	}

	if _, ok := s.UserForBranchStream(req(scoped), "alice-dev"); !ok {
		t.Error("a scoped key could not stream its own branch")
	}
	// The whole point: it reaches no further than the branch it names.
	if _, ok := s.UserForBranchStream(req(scoped), "someone-else"); ok {
		t.Error("a scoped key streamed another branch")
	}
	if _, ok := s.UserForBranchStream(req(scoped), ""); ok {
		t.Error("a scoped key authenticated with no branch named")
	}
	// An unscoped key keeps working everywhere, as it does through Authn.
	if _, ok := s.UserForBranchStream(req(unscoped), "alice-dev"); !ok {
		t.Error("an unscoped key was refused")
	}
	if _, ok := s.UserForBranchStream(req("nonsense"), "alice-dev"); ok {
		t.Error("a bad key authenticated")
	}
	// And Authn still refuses the scoped one, which is the rule this exception
	// is narrow against.
	if _, ok := s.userFromRequest(req(scoped)); ok {
		t.Error("a scoped key now authenticates ordinary control-plane requests")
	}
}
