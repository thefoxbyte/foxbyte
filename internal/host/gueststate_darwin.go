//go:build darwin

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func pushGuestState(name string, data []byte) error {
	return guestStateShell(guestStateWriteScript(name), data)
}

func removeGuestState(name string) error {
	return guestStateShell(guestStateRemoveScript(name), nil)
}

// guestStateShell runs a snippet in the VM as the user the engine runs as —
// `limactl shell` without `-u`, deliberately. The engine's state lives in that
// user's home (the anchor keys and the API pid file are there, and /root/.fox
// does not exist), so the shell that resolves $HOME has to be the same one.
func guestStateShell(script string, in []byte) error {
	if _, err := exec.LookPath("limactl"); err != nil {
		return ErrNoEngine
	}
	vm := instance()
	if !instanceExists(vm) || !instanceRunning(vm) {
		return ErrNoEngine
	}
	cmd := exec.Command("limactl", "shell", vm, "--", "sh", "-c", script)
	if in != nil {
		cmd.Stdin = bytes.NewReader(in)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
