// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"errors"
	"testing"
	"time"

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

// A suspended branch's idle clock has to be forgotten, or whatever resumes it
// next inherits an idle time measured from the last gateway connection and is
// suspended straight back.
//
// The gateway's own wake path calls touch, so a client reconnecting was never
// affected and this was invisible — it bites every other way in: `fox branch
// resume`, the agent API, and a change-feed subscriber, which is how it was
// found. A subscriber woke a branch, the decoder had a second or two to attach
// before the next pass, and if it did not make it the branch went down again.
func TestSuspendForgetsTheIdleClock(t *testing.T) {
	var suspended []string
	listSuspendable = func() ([]string, error) { return []string{"b"}, nil }
	suspendBranch = func(n string) error { suspended = append(suspended, n); return nil }
	probeConnections = func(string) (int, error) { return 0, nil }
	probeReplication = func(n string) (branch.Replication, error) { return branch.Replication{Branch: n}, nil }
	probeRealtime = func(string) (bool, error) { return false, nil }
	t.Cleanup(func() {
		listSuspendable = branch.SuspendableBranches
		suspendBranch = branch.Suspend
		probeConnections = branch.ActiveConnections
		probeReplication = branch.ReplicationStatus
		probeRealtime = branch.RealtimeActive
		mu.Lock()
		delete(lastActivity, "b")
		mu.Unlock()
	})

	// Idle long past the window, so this pass suspends it.
	touch("b")
	mu.Lock()
	lastActivity["b"] = time.Now().Add(-time.Hour)
	mu.Unlock()
	sweepOnce(time.Minute)
	if len(suspended) != 1 {
		t.Fatalf("suspended %v, want it stopped once", suspended)
	}

	// Something else resumes it. The next pass must treat it as newly seen and
	// give it a full window, not stop it again on the spot.
	sweepOnce(time.Minute)
	if len(suspended) != 1 {
		t.Fatalf("suspended %v: a resumed branch was stopped again immediately", suspended)
	}
	mu.Lock()
	_, seen := lastActivity["b"]
	mu.Unlock()
	if !seen {
		t.Fatal("the second pass did not start a fresh idle clock")
	}
	sweepOnce(time.Minute)
	if len(suspended) != 1 {
		t.Fatalf("suspended %v: the fresh idle clock was not respected", suspended)
	}
}
