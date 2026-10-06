// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"errors"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// A branch that is replicating from a source must survive the reaper: its apply
// worker is a background worker, so it has no client connections and looks idle.
// The same is true of a branch with a live change feed, whose subscriber holds a
// replication slot rather than a session. Every probe fails safe: an
// unreachable branch is not proof that it is unused.
func TestCanSuspend(t *testing.T) {
	cases := []struct {
		name        string
		conns       int
		connsErr    error
		replicating bool
		replErr     error
		streaming   bool
		streamErr   error
		want        bool
	}{
		{name: "idle and standalone", want: true},
		{name: "still in use", conns: 1},
		{name: "continuous import", replicating: true},
		{name: "connection probe failed", connsErr: errors.New("no such container")},
		{name: "replication probe failed", replErr: errors.New("psql: connection refused")},
		// A change feed has no client connections of its own either: the
		// subscriber holds a replication slot, not a session. Suspending the
		// branch would stop the feed under it.
		{name: "a live change feed", streaming: true},
		{name: "realtime probe failed", streamErr: errors.New("psql: connection refused")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			probeConnections = func(string) (int, error) { return c.conns, c.connsErr }
			probeReplication = func(n string) (branch.Replication, error) {
				return branch.Replication{Branch: n, Replicating: c.replicating}, c.replErr
			}
			probeRealtime = func(string) (bool, error) { return c.streaming, c.streamErr }
			t.Cleanup(func() {
				probeConnections = branch.ActiveConnections
				probeReplication = branch.ReplicationStatus
				probeRealtime = branch.RealtimeActive
			})
			if got := canSuspend("b"); got != c.want {
				t.Fatalf("canSuspend = %v, want %v", got, c.want)
			}
		})
	}
}
