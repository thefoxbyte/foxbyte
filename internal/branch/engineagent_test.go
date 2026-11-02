// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import "testing"

// The agent's name travels as a setting only where nothing better says it:
// on a branch whose Blackbox predates agent roles, and then not on an agent's
// own branch, which carries it as a database default. Where the role could not
// be had it is a claim. With a role of its own, nothing.
func TestEngineSessionOptions(t *testing.T) {
	for _, c := range []struct {
		mode   engineLoginMode
		branch string
		want   string
	}{
		{loginOwn, "main", ""},
		{loginOwn, "agent-a", ""},
		{loginLegacy, "main", "-c bb.actor=alice@example.com -c bb.actor_kind=agent"},
		{loginLegacy, "agent-a", ""},
		{loginClaimed, "main", "-c bb.claimed_actor=alice@example.com -c bb.actor_kind=agent"},
	} {
		if got := engineSessionOptions(engineLogin{mode: c.mode}, c.branch, "alice@example.com"); got != c.want {
			t.Errorf("mode %d on %s: %q, want %q", c.mode, c.branch, got, c.want)
		}
	}
}
