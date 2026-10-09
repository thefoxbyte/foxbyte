//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/enterprise/realtime"
	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The front door's gate, in the order it runs.
//
// These routes sit on the outer mux, so none of the /api/ middleware runs for
// them: the branch-name check, the auth gate and the authorization chain all
// have to be repeated by hand. That is the cost of being reachable with a
// credential /api/ refuses, and the risk is a check quietly missing. So each
// one is asserted here, including the two places where the *order* is what
// carries the security property.
func realtimeDoorHarness(t *testing.T) (*http.ServeMux, *auth.Store, string, string) {
	t.Helper()
	store, err := auth.Open(auth.Config{
		DBPath:    filepath.Join(t.TempDir(), "t.db"),
		WebOrigin: "http://x", SignupOpen: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	secLog = store

	u, err := store.CreateUser("a@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	// The owner of "app", so access.Level gives Manage without consulting the
	// engine for admin status.
	if err := store.SetBranchOwner("app", u.ID); err != nil {
		t.Fatal(err)
	}
	mine, _, err := store.CreateRealtimeKey(u.ID, "app", "app")
	if err != nil {
		t.Fatal(err)
	}
	// A key for a branch this user does not own, to prove the scope check and
	// the 404 answer.
	theirs, _, err := store.CreateRealtimeKey(u.ID, "other", "other")
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mountRealtimeDoor(mux, store, access.NewWith(store, func(string) bool { return false }))
	return mux, store, mine, theirs
}

func get(mux *http.ServeMux, path, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func TestRealtimeDoorGate(t *testing.T) {
	mux, _, mine, theirs := realtimeDoorHarness(t)
	const hello = realtime.APIPrefix + "/branches/app/hello"

	t.Run("no credential is 401", func(t *testing.T) {
		rec := get(mux, hello, "")
		if rec.Code != 401 {
			t.Fatalf("status %d, want 401: %s", rec.Code, rec.Body.String())
		}
		// The refusal has to say what kind of credential to bring, or the
		// developer's next move is to try the console's API key.
		if !strings.Contains(rec.Body.String(), "realtime key") {
			t.Errorf("the 401 does not say what to bring: %s", rec.Body.String())
		}
	})

	t.Run("a key for another branch is not authenticated here", func(t *testing.T) {
		if rec := get(mux, hello, theirs); rec.Code != 401 {
			t.Fatalf("status %d, want 401: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("a made-up key is 401", func(t *testing.T) {
		if rec := get(mux, hello, "rtk_nonsense"); rec.Code != 401 {
			t.Fatalf("status %d, want 401", rec.Code)
		}
	})

	// A name the engine would never accept is refused before anything resolves
	// it, and as 404 rather than 400: a name that cannot exist and a name the
	// caller may not see should look the same from outside.
	t.Run("an invalid branch name is 404 before authentication", func(t *testing.T) {
		for _, bad := range []string{"../main", "a b", strings.Repeat("x", 300), "Robert'); DROP TABLE"} {
			r := httptest.NewRequest("GET", realtime.APIPrefix+"/branches/x/hello", nil)
			r.SetPathValue("name", bad)
			rec := httptest.NewRecorder()
			realtimeGate(nil, nil)(func(http.ResponseWriter, *http.Request, string) {
				t.Errorf("the handler ran for %q", bad)
			})(rec, r)
			if rec.Code != 404 {
				t.Errorf("name %q: status %d, want 404", bad, rec.Code)
			}
		}
	})

	t.Run("a key for a branch the caller cannot reach is 404, not 403", func(t *testing.T) {
		// "other" exists as a scope but this account does not own it and is not
		// an admin, so authorization says None — answered as a missing branch,
		// because confirming the name is itself the leak.
		rec := get(mux, realtime.APIPrefix+"/branches/other/hello", theirs)
		if rec.Code != 404 {
			t.Fatalf("status %d, want 404: %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "permission") || strings.Contains(rec.Body.String(), "forbidden") {
			t.Errorf("the 404 hints that the branch exists: %s", rec.Body.String())
		}
	})

	// The licence is checked after authorization, so an unlicensed install is
	// not itself a way to ask which branches exist. Both halves are asserted:
	// an authorized caller gets 403, an unauthorized one still gets 404.
	t.Run("the licence is checked after authorization", func(t *testing.T) {
		edition.SetEntitlement(nil)
		if rec := get(mux, hello, mine); rec.Code != 403 {
			t.Fatalf("authorized caller, no licence: status %d, want 403: %s", rec.Code, rec.Body.String())
		}
		if rec := get(mux, realtime.APIPrefix+"/branches/other/hello", theirs); rec.Code != 404 {
			t.Fatalf("unauthorized caller, no licence: status %d, want 404 — an unlicensed install must not confirm branch names", rec.Code)
		}
	})
}

// Every route behind the front door goes through the same gate. A route added
// without one shows up here as a 200 where a 401 belongs, rather than as a feed
// anybody can read.
func TestEveryDoorRouteIsGated(t *testing.T) {
	mux, _, _, _ := realtimeDoorHarness(t)
	for _, path := range []string{
		realtime.APIPrefix + "/branches/app/hello",
		realtime.APIPrefix + "/branches/app/tables",
		realtime.APIPrefix + "/branches/app/stream",
	} {
		if rec := get(mux, path, ""); rec.Code != 401 {
			t.Errorf("GET %s without a credential: status %d, want 401", path, rec.Code)
		}
	}
}

// The old route is untouched. A subscriber running today keeps working: this is
// a second door, not a replacement, and that is the whole additive claim.
func TestTheOriginalStreamRouteStillMounts(t *testing.T) {
	store, err := auth.Open(auth.Config{
		DBPath:    filepath.Join(t.TempDir(), "t.db"),
		WebOrigin: "http://x", SignupOpen: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	secLog = store

	mux := http.NewServeMux()
	mountRealtimeStream(mux, store, access.NewWith(store, func(string) bool { return false }))
	// Unauthenticated, so it stops at the first check — which is enough to
	// prove the pattern is still registered and still refusing.
	rec := get(mux, "/api/branches/main/realtime", "")
	if rec.Code != 401 {
		t.Fatalf("GET /api/branches/main/realtime: status %d, want 401 (the route must still exist)", rec.Code)
	}
}
