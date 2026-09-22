// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tokenIn keeps the setup token in a temp dir for one test.
func tokenIn(t *testing.T) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "setup-token")
	old := setupTokenPath
	setupTokenPath = func() string { return p }
	t.Cleanup(func() { setupTokenPath = old })
}

func closedStore(t *testing.T) *Store {
	t.Helper()
	s := testStore(t)
	s.cfg.SignupOpen = false
	return s
}

func TestSignupClosedUnlessOpen(t *testing.T) {
	for val, want := range map[string]bool{"": false, "closed": false, "open": true, " OPEN ": true, "yes": false} {
		t.Setenv("FOX_SIGNUP", val)
		if got := SignupOpenFromEnv(); got != want {
			t.Errorf("FOX_SIGNUP=%q: open=%v, want %v", val, got, want)
		}
	}
}

func TestFirstAccountNeedsTheSetupToken(t *testing.T) {
	tokenIn(t)
	s := closedStore(t)
	tok, err := EnsureSetupToken()
	if err != nil || tok == "" {
		t.Fatalf("EnsureSetupToken: %q, %v", tok, err)
	}
	if again, _ := EnsureSetupToken(); again != tok {
		t.Error("the token changed between calls; the one printed would stop working")
	}
	for _, bad := range []string{"", "wrong", tok + "x"} {
		if _, err := s.Register("a@x.com", "password1", bad); !errors.Is(err, ErrSetupToken) {
			t.Errorf("token %q: err = %v, want ErrSetupToken", bad, err)
		}
	}
	if s.HasAnyUser() {
		t.Fatal("a refused registration created an account")
	}
	if _, err := s.Register("a@x.com", "password1", tok); err != nil {
		t.Fatalf("right token refused: %v", err)
	}
	if _, err := EnsureSetupTokenExisting(); err == nil {
		t.Error("the setup token outlived the first account")
	}
	// Sign-up is closed, so a second account cannot register at all, token or not.
	if _, err := s.Register("b@x.com", "password1", tok); !errors.Is(err, ErrSignupClosed) {
		t.Errorf("second account with sign-up closed: err = %v, want ErrSignupClosed", err)
	}
	// Open sign-up lets later accounts in without a token.
	s.cfg.SignupOpen = true
	if _, err := s.Register("b@x.com", "password1", ""); err != nil {
		t.Errorf("second account with sign-up open: %v", err)
	}
}

// EnsureSetupTokenExisting reads the token without creating one.
func EnsureSetupTokenExisting() (string, error) {
	b, err := os.ReadFile(SetupTokenPath())
	return strings.TrimSpace(string(b)), err
}

// Two sign-ups at the same moment on an empty store used to both see "no
// accounts" and both become the admin.
func TestOnlyOneFirstAccount(t *testing.T) {
	tokenIn(t)
	s := testStore(t)
	var firsts atomic.Int32
	s.OnFirstUser = func(User) { firsts.Add(1) }
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = s.CreateUser(string(rune('a'+i))+"@x.com", "password1")
		}(i)
	}
	wg.Wait()
	if n := firsts.Load(); n != 1 {
		t.Errorf("%d accounts were treated as the first; want exactly 1", n)
	}
}

func TestOAuthRules(t *testing.T) {
	tokenIn(t)
	s := closedStore(t)
	// No account yet: a provider sign-in cannot make the first one.
	if _, err := s.upsertOAuth("github", "1", "a@x.com", true); !errors.Is(err, errOAuthNoAccount) {
		t.Errorf("first account over OAuth: err = %v, want errOAuthNoAccount", err)
	}
	a, _ := s.CreateUser("a@x.com", "password1")
	// An unverified email must not join the account that has it.
	if _, err := s.upsertOAuth("github", "2", "a@x.com", false); !errors.Is(err, errOAuthUnverified) {
		t.Errorf("unverified email: err = %v, want errOAuthUnverified", err)
	}
	// A verified one joins it.
	u, err := s.upsertOAuth("github", "3", "A@x.com", true)
	if err != nil || u.ID != a.ID {
		t.Fatalf("verified email: %+v, %v; want account %d", u, err, a.ID)
	}
	// And that identity signs in to it from now on.
	if u, err := s.upsertOAuth("github", "3", "", false); err != nil || u.ID != a.ID {
		t.Errorf("known identity: %+v, %v", u, err)
	}
	// Sign-up closed: a new email gets no account.
	if _, err := s.upsertOAuth("google", "9", "new@x.com", true); !errors.Is(err, errOAuthNoAccount) {
		t.Errorf("new email with sign-up closed: err = %v, want errOAuthNoAccount", err)
	}
	s.cfg.SignupOpen = true
	if _, err := s.upsertOAuth("google", "9", "new@x.com", true); err != nil {
		t.Errorf("new email with sign-up open: %v", err)
	}
}

func TestThrottle(t *testing.T) {
	now := time.Unix(1000, 0)
	th := newThrottle(3, time.Minute)
	th.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if held, _ := th.blocked("ip:1"); held {
			t.Fatalf("held after %d failures", i)
		}
		th.fail("ip:1")
	}
	if held, wait := th.blocked("ip:1"); !held || wait != time.Minute {
		t.Errorf("after 3 failures: held=%v wait=%v", held, wait)
	}
	if held, _ := th.blocked("ip:2"); held {
		t.Error("another address was held")
	}
	now = now.Add(time.Minute)
	if held, _ := th.blocked("ip:1"); held {
		t.Error("still held after the window")
	}
}

func TestLoginIsThrottled(t *testing.T) {
	s := testStore(t)
	if _, err := s.CreateUser("a@x.com", "password1"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.MountPublic(mux)
	try := func(pw string) int {
		r := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(`{"email":"a@x.com","password":"`+pw+`"}`))
		r.RemoteAddr = "203.0.113.7:5555"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < loginMaxFails; i++ {
		if c := try("wrong"); c != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d, want 401", i+1, c)
		}
	}
	if c := try("password1"); c != http.StatusTooManyRequests {
		t.Errorf("after %d failures, even the right password got %d; want 429", loginMaxFails, c)
	}
}

func TestAuthBodyIsCapped(t *testing.T) {
	s := testStore(t)
	mux := http.NewServeMux()
	s.MountPublic(mux)
	big := `{"email":"a@x.com","password":"` + strings.Repeat("p", maxAuthBody) + `"}`
	r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(big))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("oversized body: %d, want 401 (read nothing, matched nothing)", w.Code)
	}
}

func TestStateCookieIsSecure(t *testing.T) {
	s := testStore(t)
	s.cfg.PublicURL = "https://localhost:8080"
	c := s.stateCookie("v", 600)
	if !c.Secure || c.SameSite != http.SameSiteLaxMode || !c.HttpOnly {
		t.Errorf("state cookie: %+v", c)
	}
}

func TestPipelineTargets(t *testing.T) {
	s := testStore(t)
	u, _ := s.CreateUser("a@x.com", "password1")
	p1, _ := s.CreatePipeline(u.ID, "one", "{}")
	p2, _ := s.CreatePipeline(u.ID, "two", "{}")
	if err := s.ClaimPipelineTarget(p1.ID, "sales"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimPipelineTarget(p1.ID, "sales"); err != nil {
		t.Errorf("a pipeline could not re-claim its own branch: %v", err)
	}
	if err := s.ClaimPipelineTarget(p2.ID, "sales"); err == nil {
		t.Error("a second pipeline took over the first one's branch")
	}
	if !s.PipelineOwnsTarget(p1.ID, "sales") || s.PipelineOwnsTarget(p2.ID, "sales") {
		t.Error("ownership reads back wrong")
	}
}
