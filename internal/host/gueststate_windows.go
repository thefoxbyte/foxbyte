//go:build windows

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

// guestStateShell runs a snippet in the distro as its default user — not
// `wslRoot`, which the setup steps use because they need privilege. Here the
// user is the point: the engine's state directory is the home of whoever runs
// the forwarded command, so the same shell has to resolve it.
//
// The content goes in over stdin rather than through a /mnt path, so this works
// whether or not the Windows drives are mounted in the distro.
func guestStateShell(script string, in []byte) error {
	if !wslInstalled() {
		return ErrNoEngine
	}
	d := currentDistro()
	if !distroExists(d) {
		return ErrNoEngine
	}
	cmd := exec.Command("wsl.exe", "-d", d, "--", "sh", "-c", script)
	if in != nil {
		cmd.Stdin = bytes.NewReader(in)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, strings.TrimSpace(decodeWSLOutput(out)))
	}
	return nil
}
