// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Without a key the server must not start, and must say how to make one: MCP
// clients are configured by hand, so the error is the documentation.
func TestAuthenticateWithoutAKey(t *testing.T) {
	for _, key := range []string{"", "   "} {
		if _, err := authenticate(key); !errors.Is(err, ErrNoKey) {
			t.Fatalf("key %q: expected ErrNoKey, got %v", key, err)
		}
	}
	for _, want := range []string{"fox apikey create", "FOX_API_KEY"} {
		if !strings.Contains(KeyHelp, want) {
			t.Errorf("the help should mention %q", want)
		}
	}
}

// A branch-scoped key (an agent's) reaches its own branch and nothing else.
func TestApplyScope(t *testing.T) {
	t.Cleanup(func() { me = identity{} })

	// An account key changes nothing at all: every tool, every argument.
	me = identity{Actor: "you@example.com"}
	for _, tool := range []string{"run_sql", "list_branches", "blackbox_diff", "branch_before_change"} {
		in := json.RawMessage(`{"branch":"main"}`)
		out, err := applyScope(tool, in)
		if err != nil {
			t.Fatalf("account key, %s: %v", tool, err)
		}
		if string(out) != string(in) {
			t.Errorf("account key, %s: arguments rewritten to %s", tool, out)
		}
	}

	me = identity{Actor: "agent@example.com", Scope: "agent-alice"}

	// Tools that reach past one branch are refused outright.
	for tool := range scopedKeyRefuses {
		if _, err := applyScope(tool, json.RawMessage(`{}`)); err == nil {
			t.Errorf("scoped key: %s should be refused", tool)
		} else if !strings.Contains(err.Error(), "agent-alice") {
			t.Errorf("scoped key: %s refusal should name the branch: %v", tool, err)
		}
	}

	// Another branch is refused rather than quietly redirected.
	if _, err := applyScope("run_sql", json.RawMessage(`{"branch":"main","sql":"SELECT 1"}`)); err == nil {
		t.Error("scoped key: naming main should be refused")
	}

	// Its own branch passes, and so does an absent or empty one -- pinned to the
	// key's branch, so a tool's default of "main" can't be what it gets.
	for _, in := range []string{`{"branch":"agent-alice","sql":"SELECT 1"}`, `{"sql":"SELECT 1"}`, `{"branch":"","sql":"SELECT 1"}`, ``} {
		out, err := applyScope("run_sql", json.RawMessage(in))
		if err != nil {
			t.Fatalf("scoped key, %q: %v", in, err)
		}
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("scoped key, %q: %v", in, err)
		}
		if m["branch"] != "agent-alice" {
			t.Errorf("scoped key, %q: branch is %v, want agent-alice", in, m["branch"])
		}
	}

	// Arguments that aren't an object are rejected, not silently replaced.
	if _, err := applyScope("run_sql", json.RawMessage(`"not an object"`)); err == nil {
		t.Error("scoped key: non-object arguments should be refused")
	}
}
