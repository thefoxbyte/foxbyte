//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import "os/exec"

// FoxByte's long-lived servers run only inside the Linux guest (WSL2); on the
// Windows host, host.Maybe forwards every engine command, so this package is
// never exercised there. These stubs exist solely so the host binary compiles
// for windows/amd64.

func processAlive(pid int) bool { return false }

func configureDetach(cmd *exec.Cmd) {}

func terminate(pid int) {}

func kill(pid int) {}
