//go:build !darwin && !windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/foxbyte/foxbyte/internal/update"
)

// localEngine updates a Linux install, where `fox` is the engine itself.
type localEngine struct{}

func newEngineHost() engineHost { return localEngine{} }

func (localEngine) where() string { return "this machine" }

func (localEngine) prepare() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("unsupported host OS %q", runtime.GOOS)
	}
	return nil
}

// stage: the download already is on this machine.
func (localEngine) stage(local string) (string, error) { return local, nil }

func (localEngine) installed() (string, error) { return hostExecutable() }

func (localEngine) command(bin string, args []string) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), update.EnvNoCheck+"=1")
	return cmd
}

func (e localEngine) run(bin string, args ...string) error {
	cmd := e.command(bin, args)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func (e localEngine) output(bin string, args ...string) (string, error) {
	cmd := e.command(bin, args)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return string(out), err
}

func platformUpdateHooks(engineHost) updateHooks {
	return updateHooks{
		target: func() update.Target {
			return update.Target{GOOS: "linux", HostArch: runtime.GOARCH, GuestArch: runtime.GOARCH}
		},
		checkServers: checkControlPlane,
	}
}
