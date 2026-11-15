// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// An account at its branch limit is refused a new branch, with a message that
// says so; an admin at the same count is not.
func TestCreateIsHeldToTheBranchLimit(t *testing.T) {
	t.Setenv("FOX_DB", filepath.Join(t.TempDir(), "auth.db"))
	t.Setenv("FOX_MAX_BRANCHES_PER_ACCOUNT", "2")
	t.Setenv("FOX_BRANCH_CREATES_PER_MINUTE", "0") // the rate is branch's own test
	s, err := auth.OpenFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	admin, _ := s.CreateUser("admin@x.com", "password1")
	alice, _ := s.CreateUser("alice@x.com", "password1")
	old := acl
	acl = access.NewWith(s, func(e string) bool { return e == "admin@x.com" })
	t.Cleanup(func() { acl = old })
	for i := range 2 {
		_ = s.SetBranchOwner(fmt.Sprintf("alice-%d", i), alice.ID)
		_ = s.SetBranchOwner(fmt.Sprintf("admin-%d", i), admin.ID)
	}
	h := s.Authn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowCreate(w, r) {
			w.WriteHeader(299)
		}
	}))
	post := func(u auth.User) int {
		k, _, _ := s.CreateAPIKey(u.ID, "t")
		req := httptest.NewRequest("POST", "/api/branches", nil)
		req.Header.Set("Authorization", "Bearer "+k)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post(alice); code != http.StatusForbidden {
		t.Errorf("alice at the limit: %d, want 403", code)
	}
	if code := post(admin); code != 299 {
		t.Errorf("admin at the same count: %d, want through", code)
	}
	_ = s.ForgetBranch("alice-0")
	if code := post(alice); code != 299 {
		t.Errorf("alice after a delete: %d, want through", code)
	}
}

func TestCreateRefusalCodes(t *testing.T) {
	for err, want := range map[error]int{
		fmt.Errorf("%w: x", branch.ErrCreateRate):  http.StatusTooManyRequests,
		fmt.Errorf("%w: x", branch.ErrBranchQuota): http.StatusForbidden,
		fmt.Errorf("store down"):                   http.StatusInternalServerError,
	} {
		if got := createRefusalCode(err); got != want {
			t.Errorf("%v: %d, want %d", err, got, want)
		}
	}
}
