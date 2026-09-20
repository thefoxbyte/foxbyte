// SPDX-License-Identifier: AGPL-3.0-or-later

// Package daemon runs FoxByte's long-lived servers (gateway, agent API) as
// detached background processes so they don't hold a terminal. Each service is
// the foxbyte binary re-invoked with its subcommand, started in a new session
// (setsid) with a pidfile and a log file under ~/.fox.
package daemon

import (
	"fmt"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func runDir() string {
	d := brand.StateDir()
	_ = os.MkdirAll(d, 0o755)
	return d
}

func pidPath(name string) string { return filepath.Join(runDir(), name+".pid") }

// LogPath is the log file for a service.
func LogPath(name string) string { return filepath.Join(runDir(), name+".log") }

func readPid(name string) int {
	b, err := os.ReadFile(pidPath(name))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

// Alive reports whether the service's recorded process is still running.
func Alive(name string) bool {
	pid := readPid(name)
	return pid > 0 && processAlive(pid)
}

// Start launches a service detached (no-op if already running). args are the
// foxbyte subcommand and flags, e.g. {"gateway","--addr",":6432"}.
func Start(name string, args []string) error {
	if Alive(name) {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(LogPath(name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	configureDetach(cmd) // detach from our session (Unix); no-op on the Windows stub
	if err := cmd.Start(); err != nil {
		return err
	}
	return os.WriteFile(pidPath(name), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
}

// Stop terminates a service and clears its pidfile. It waits for a graceful exit
// after SIGTERM and escalates to SIGKILL if the process is still alive, so the
// pidfile is only cleared once the process is actually gone — otherwise `status`
// would report "stopped" while the old process kept serving (and a later `start`
// couldn't rebind the port).
func Stop(name string) {
	pid := readPid(name)
	if pid > 0 {
		terminate(pid) // SIGTERM — ask it to shut down
		for i := 0; i < 30 && processAlive(pid); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if processAlive(pid) {
			kill(pid) // still up after ~3s — force it
		}
	}
	_ = os.Remove(pidPath(name))
}

// Status returns "running (pid N)" or "stopped".
func Status(name string) string {
	if Alive(name) {
		return fmt.Sprintf("running (pid %d)", readPid(name))
	}
	return "stopped"
}
