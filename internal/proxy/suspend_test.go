// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"errors"
	"testing"

	"github.com/foxbyte/foxbyte/internal/branch"
)

// A branch that is replicating from a source must survive the reaper: its apply
// worker is a background worker, so it has no client connections and looks idle.
func TestCanSuspend(t *testing.T) {
	cases := []struct {
		name        string
		conns       int
		connsErr    error
		replicating bool
		replErr     error
		want        bool
	}{
		{name: "idle and standalone", want: true},
		{name: "still in use", conns: 1},
		{name: "continuous import", replicating: true},
		{name: "connection probe failed", connsErr: errors.New("no such container")},
		{name: "replication probe failed", replErr: errors.New("psql: connection refused")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			probeConnections = func(string) (int, error) { return c.conns, c.connsErr }
			probeReplication = func(n string) (branch.Replication, error) {
				return branch.Replication{Branch: n, Replicating: c.replicating}, c.replErr
			}
			t.Cleanup(func() {
				probeConnections = branch.ActiveConnections
				probeReplication = branch.ReplicationStatus
			})
			if got := canSuspend("b"); got != c.want {
				t.Fatalf("canSuspend = %v, want %v", got, c.want)
			}
		})
	}
}
