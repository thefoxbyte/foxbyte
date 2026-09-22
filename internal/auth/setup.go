// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/subtle"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// The first account on an install is its admin: it may override the
// destructive-change guardrail and grant that to others. Letting whoever
// reaches the sign-up page first claim it was a race a stranger could win on
// any install whose port is reachable. So the first account made over HTTP
// needs a setup token: a random secret written to the state directory, which
// only someone who can read that directory — the person who ran `fox start` —
// can see. `fox user create` runs on the machine itself and needs none.

// ErrSetupToken is returned when the first account is attempted without the
// setup token, or with the wrong one.
var ErrSetupToken = errors.New("the first account needs the setup token that `fox start` printed")

// ErrSignupClosed is returned when someone tries to create an account while
// sign-up is closed.
var ErrSignupClosed = errors.New("signups are closed")

// SetupTokenPath is where the first-run setup token is kept.
func SetupTokenPath() string { return setupTokenPath() }

// setupTokenPath is a variable so tests can keep the token in a temp dir.
var setupTokenPath = func() string { return brand.StatePath("setup-token") }

// EnsureSetupToken returns the install's setup token, creating it (mode 0600)
// when there is none. Call it only while the install has no account.
func EnsureSetupToken() (string, error) {
	p := SetupTokenPath()
	if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
		return strings.TrimSpace(string(b)), nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	tok, err := newToken(18)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// checkSetupToken compares a presented token with the stored one in constant
// time. No stored token means none can match.
func checkSetupToken(presented string) bool {
	b, err := os.ReadFile(SetupTokenPath())
	want := strings.TrimSpace(string(b))
	presented = strings.TrimSpace(presented)
	if err != nil || want == "" || presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(presented)) == 1
}

// removeSetupToken deletes the token once the first account exists: it has
// done its job, and must not open a second door later.
func removeSetupToken() { _ = os.Remove(SetupTokenPath()) }

// SignupOpenFromEnv reads FOX_SIGNUP. Sign-up is closed unless it is set to
// "open": the first account is made with the setup token, and every other
// account by an admin with `fox user create`.
func SignupOpenFromEnv() bool {
	return strings.EqualFold(strings.TrimSpace(brand.Getenv("SIGNUP")), "open")
}

// ---- login throttling ----

// loginMaxFails failed logins for one address or one email inside loginWindow
// hold further attempts for it until the window has passed.
const (
	loginMaxFails = 10
	loginWindow   = 15 * time.Minute
)

// throttle slows down password guessing. After maxFails failures for one
// client address or one email inside window, further attempts for it are
// refused until the window has passed since the first of them. A success
// clears the email's count. It is per process and in memory: a restart
// forgets it, which is acceptable for a brake, not a lock-out.
type throttle struct {
	mu       sync.Mutex
	fails    map[string]*failWindow
	maxFails int
	window   time.Duration
	now      func() time.Time
}

type failWindow struct {
	first time.Time
	n     int
}

func newThrottle(maxFails int, window time.Duration) *throttle {
	return &throttle{fails: map[string]*failWindow{}, maxFails: maxFails, window: window, now: time.Now}
}

// blocked reports whether any of keys has used up its failures, and for how
// much longer.
func (t *throttle) blocked(keys ...string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, k := range keys {
		f, ok := t.fails[k]
		if !ok {
			continue
		}
		if now.Sub(f.first) >= t.window {
			delete(t.fails, k)
			continue
		}
		if f.n >= t.maxFails {
			return true, t.window - now.Sub(f.first)
		}
	}
	return false, 0
}

func (t *throttle) fail(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, k := range keys {
		f, ok := t.fails[k]
		if !ok || now.Sub(f.first) >= t.window {
			f = &failWindow{first: now}
			t.fails[k] = f
		}
		f.n++
	}
	// Bound the map: an attacker rotating addresses must not grow it forever.
	if len(t.fails) > 10000 {
		for k, f := range t.fails {
			if now.Sub(f.first) >= t.window {
				delete(t.fails, k)
			}
		}
	}
}

func (t *throttle) clear(key string) {
	t.mu.Lock()
	delete(t.fails, key)
	t.mu.Unlock()
}
