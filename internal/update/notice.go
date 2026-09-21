// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EnvNoCheck turns off the check `fox start` makes for a newer release.
const EnvNoCheck = "FOX_NO_UPDATE_CHECK"

// EnvCheckInterval is how long a newer release found by a start-time check is
// remembered (default 6h; 0 means check on every start).
const EnvCheckInterval = "FOX_UPDATE_CHECK_INTERVAL"

// CheckInterval reads EnvCheckInterval.
func CheckInterval(getenv func(string) string) time.Duration {
	v := strings.TrimSpace(getenv(EnvCheckInterval))
	if v == "" {
		return 6 * time.Hour
	}
	if d, err := time.ParseDuration(v); err == nil && d >= 0 {
		return d
	}
	return 6 * time.Hour
}

// noticeCache is a newer release found by a start-time check, so the notice
// keeps printing on later starts without asking GitHub again.
type noticeCache struct {
	CheckedAt time.Time `json:"checked_at"`
	Repo      string    `json:"repo"`
	Current   string    `json:"current"`
	Notice    string    `json:"notice"`
}

// cachedNotice returns the remembered notice for this repo and installed
// version, if it was found within the interval.
//
// Only a found release counts. "Up to date" is never an answer to reuse: a
// release published a minute later would stay invisible for the whole interval
// (with the 6h default, a release went unannounced for hours while
// `fox update --check` saw it). Files written before this rule may still hold
// an empty notice; they are ignored rather than trusted.
func (c *Client) cachedNotice(current string, within time.Duration) (string, bool) {
	if c.NoticePath == "" || within <= 0 {
		return "", false
	}
	b, err := os.ReadFile(c.NoticePath)
	if err != nil {
		return "", false
	}
	var n noticeCache
	if json.Unmarshal(b, &n) != nil || n.Repo != c.Repo || n.Current != current || n.Notice == "" {
		return "", false
	}
	age := time.Since(n.CheckedAt)
	if age > within || age < -time.Minute { // stale, or a clock that moved backwards
		return "", false
	}
	return n.Notice, true
}

func (c *Client) rememberNotice(current, notice string) {
	if c.NoticePath == "" {
		return
	}
	b, err := json.Marshal(noticeCache{CheckedAt: time.Now(), Repo: c.Repo, Current: current, Notice: notice})
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(c.NoticePath), 0o755)
	tmp := c.NoticePath + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, c.NoticePath)
	}
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ShouldCheck reports whether `fox start` should look for a newer release: not
// when turned off, and not for development builds.
func ShouldCheck(getenv func(string) string, current string) bool {
	if truthy(getenv(EnvNoCheck)) {
		return false
	}
	v, err := ParseVersion(current)
	return err == nil && !v.IsDev()
}

// CheckTimeout is how long `fox start` waits for the check
// (FOX_UPDATE_CHECK_TIMEOUT, default 1.5s).
func CheckTimeout(getenv func(string) string) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(getenv("FOX_UPDATE_CHECK_TIMEOUT"))); err == nil && d > 0 {
		return d
	}
	return 1500 * time.Millisecond
}

// Notice is the one line `fox start` prints when a newer release is available.
func Notice(current string, o *Offer) string {
	return fmt.Sprintf("FoxByte %s is available (you have %s). Run `fox update` to get the new capabilities.", o.Release.Tag, current)
}

// BackgroundCheck starts looking for a newer release and returns a function
// that yields the notice — or "" when there is none, the check failed (offline,
// rate limited) or it didn't finish within the timeout. It never blocks longer
// than the timeout, counted from when the check started.
//
// A newer release, once found, is remembered for CheckInterval, so the notice
// keeps printing without asking GitHub again. "Up to date" and failed checks
// are not remembered, so a new release shows on the very next start. That costs
// one request per start for the releases list (see Available) — conditional on
// the previous ETag, so an unchanged list is a 304 that GitHub does not count
// against the rate limit.
func BackgroundCheck(c *Client, current string, t Target, timeout time.Duration) func() string {
	cur, err := ParseVersion(current)
	if err != nil {
		return func() string { return "" }
	}
	if s, ok := c.cachedNotice(current, CheckInterval(os.Getenv)); ok {
		return func() string { return s } // checked recently: no network at all
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	ch := make(chan string, 1)
	go func() {
		o, err := c.Available(ctx, cur, t)
		if err != nil {
			ch <- "" // offline or rate limited: silent, and not remembered
			return
		}
		s := ""
		if o != nil {
			s = Notice(current, o)
			c.rememberNotice(current, s)
		}
		ch <- s
	}()
	return func() string {
		defer cancel()
		select {
		case s := <-ch:
			return s
		case <-ctx.Done():
			select {
			case s := <-ch:
				return s
			default:
				return ""
			}
		}
	}
}

// IsTerminal reports whether f is an interactive terminal.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
