//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// Stop must actually terminate the recorded process before clearing the pidfile —
// even one that ignores SIGTERM (it escalates to SIGKILL). Previously it removed
// the pidfile without confirming the process died, so `status` reported "stopped"
// while the old process kept serving and a later `start` couldn't rebind the port.
func TestStopTerminatesProcess(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // runDir() → $HOME/.fox

	// A process that ignores SIGTERM, forcing the SIGKILL escalation path.
	cmd := exec.Command("sh", "-c", "trap '' TERM; sleep 60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if err := os.WriteFile(pidPath("testsvc"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Alive("testsvc") {
		t.Fatal("expected the service to be reported alive")
	}

	Stop("testsvc")

	// The process should be dead: cmd.Wait returns promptly (killed), rather than
	// blocking for the full sleep.
	done := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("Stop did not terminate the process")
	}

	if _, err := os.Stat(pidPath("testsvc")); !os.IsNotExist(err) {
		t.Errorf("Stop did not remove the pidfile")
	}
}
