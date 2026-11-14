// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
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
