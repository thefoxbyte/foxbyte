// SPDX-License-Identifier: AGPL-3.0-or-later

package errhint

import (
	"errors"
	"strings"
	"testing"
)

// Every failure listed here is one a user meets on a normal machine, so each
// must produce a hint that names a command.
func TestForKnownFailures(t *testing.T) {
	cases := []struct {
		msg  string
		says string // a fragment the hint must contain
	}{
		{"Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?", "fox start"},
		{"no FoxByte VM yet — run `fox setup` once to create it", "fox setup"},
		{"Lima is required on macOS. Install it with `brew install lima`", "brew install lima"},
		{"listen tcp 127.0.0.1:8080: bind: address already in use", "fox stop"},
		{`pq: password authentication failed for user "dbadmin"`, "apikey create"},
		{"dial tcp 127.0.0.1:6432: connect: connection refused", "fox check"},
		{"ERROR:  canceling statement due to statement timeout", "fox connect"},
		{"docker did not finish within 10m0s and was stopped (set FOX_EXEC_TIMEOUT to change that)", "fox check"},
		{"ERROR: cannot insert multiple commands into a prepared statement", "do run scripts"},
		{"write /var/lib/postgresql/data: no space left on device", "backup prune"},
		{"guardrail: TRUNCATE is blocked by policy", "fox policy list"},
		{`docker: Error response from daemon: unknown: failed to resolve reference "quay.io/minio/minio@sha256:14cea": unexpected status from HEAD request: 401 Unauthorized`, "FOX_MINIO_IMAGE"},
	}
	for _, c := range cases {
		got := ForText(c.msg)
		if got == "" {
			t.Errorf("no hint for %q", c.msg)
			continue
		}
		if !strings.Contains(got, c.says) {
			t.Errorf("hint for %q was %q, wanted it to mention %q", c.msg, got, c.says)
		}
	}
}

// An error nobody has written a hint for must pass through untouched, rather
// than being dressed up in a guess.
func TestNoHintForTheUnknown(t *testing.T) {
	for _, msg := range []string{"", "   ", "some error nobody predicted"} {
		if got := ForText(msg); got != "" {
			t.Errorf("ForText(%q) = %q, want no hint", msg, got)
		}
	}
	if got := For(nil); got != "" {
		t.Errorf("For(nil) = %q, want no hint", got)
	}
}

// Wrap keeps the original message: a hint explains an error, it never hides it.
func TestWrapKeepsTheOriginal(t *testing.T) {
	err := errors.New("Cannot connect to the Docker daemon")
	got := Wrap(err)
	if !strings.Contains(got.Error(), "Cannot connect to the Docker daemon") {
		t.Errorf("Wrap dropped the original: %q", got)
	}
	if !strings.Contains(got.Error(), "fox start") {
		t.Errorf("Wrap added no hint: %q", got)
	}
	plain := errors.New("nothing matches this")
	if Wrap(plain) != plain {
		t.Error("Wrap changed an error it has no hint for")
	}
}

// The hints name the CLI from brand.json, never a hard-coded "fox".
func TestHintsAreNotHardCodedToAName(t *testing.T) {
	for _, h := range hints {
		if strings.Contains(h.says, "fox ") {
			t.Errorf("hint %q hard-codes the command name; use %%s", h.says)
		}
	}
}
