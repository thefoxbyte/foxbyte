// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// Enabling realtime (and any other docker exec) on a branch suspended inside
// the state cache's window used to fail: EnsureRunning still said "running",
// exec hit a stopped container, and the error was returned. The next exec
// must forget that memory, wake the branch, and try once.
func TestRetryIfStoppedWakesABranchTheCacheStillCallsRunning(t *testing.T) {
	old := wakeForExec
	t.Cleanup(func() { wakeForExec = old })

	cont := container("dev")
	containers.mu.Lock()
	containers.entries[cont] = cachedFacts{
		facts:   containerFacts{state: "running", ip: "10.0.0.9"},
		expires: time.Now().Add(time.Hour),
	}
	containers.mu.Unlock()
	t.Cleanup(func() {
		containers.mu.Lock()
		delete(containers.entries, cont)
		containers.mu.Unlock()
	})

	var woke string
	wakeForExec = func(name string) (string, error) {
		woke = name
		return "10.0.0.9:5432", nil
	}
	n := 0
	err := retryIfStopped("dev", func() error {
		n++
		if n == 1 {
			return fmt.Errorf("Error response from daemon: container %s is not running", cont)
		}
		return nil
	})
	if err != nil || n != 2 || woke != "dev" {
		t.Fatalf("err=%v calls=%d woke=%q", err, n, woke)
	}
	containers.mu.Lock()
	_, cached := containers.entries[cont]
	containers.mu.Unlock()
	if cached {
		t.Fatal("the stale running entry was kept, so the next caller would skip the wake")
	}
}

func TestRetryIfStoppedLeavesAQueryErrorAlone(t *testing.T) {
	old := wakeForExec
	t.Cleanup(func() { wakeForExec = old })
	woke := false
	wakeForExec = func(string) (string, error) {
		woke = true
		return "", nil
	}
	err := retryIfStopped("dev", func() error { return fmt.Errorf("ERROR: syntax error at or near \"nope\"") })
	if err == nil || woke {
		t.Fatalf("a query error was treated as a stopped container: %v woke=%v", err, woke)
	}
}

// The checkpoint scheduler reads only running branches, but the idle reaper can
// stop one between its list and its read. Inside withoutWaking, a read that
// finds the branch stopped says so and leaves it stopped; another branch, and
// the same branch afterwards, still wake as before.
func TestRetryIfStoppedLeavesABranchAsleepForAnUnattendedJob(t *testing.T) {
	old := wakeForExec
	t.Cleanup(func() { wakeForExec = old })
	var woke []string
	wakeForExec = func(name string) (string, error) {
		woke = append(woke, name)
		return "10.0.0.9:5432", nil
	}
	stoppedOnce := func(name string) func() error {
		n := 0
		return func() error {
			n++
			if n == 1 {
				return fmt.Errorf("Error response from daemon: container %s is not running", container(name))
			}
			return nil
		}
	}

	var err, other error
	calls := 0
	withoutWaking("idle", func() {
		fn := stoppedOnce("idle")
		err = retryIfStopped("idle", func() error { calls++; return fn() })
		other = retryIfStopped("busy", stoppedOnce("busy"))
	})
	if !errors.Is(err, errSuspendedMeanwhile) || calls != 1 {
		t.Fatalf("the unattended read: err=%v calls=%d, want errSuspendedMeanwhile after one call", err, calls)
	}
	if other != nil || len(woke) != 1 || woke[0] != "busy" {
		t.Fatalf("another branch must still wake: err=%v woke=%v", other, woke)
	}
	if wakingHeld("idle") {
		t.Fatal("the mark outlived withoutWaking")
	}
	if err := retryIfStopped("idle", stoppedOnce("idle")); err != nil || len(woke) != 2 || woke[1] != "idle" {
		t.Fatalf("afterwards, a read someone asked for wakes it as before: err=%v woke=%v", err, woke)
	}
}

// Two jobs on one branch do not release each other's mark.
func TestWithoutWakingNests(t *testing.T) {
	withoutWaking("dev", func() {
		withoutWaking("dev", func() {})
		if !wakingHeld("dev") {
			t.Fatal("the inner job released the outer one's mark")
		}
	})
	if wakingHeld("dev") {
		t.Fatal("the mark outlived both jobs")
	}
}
