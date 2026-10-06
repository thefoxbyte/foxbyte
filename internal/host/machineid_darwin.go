//go:build darwin

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"os/exec"
	"strings"
)

// rawMachineID is the IOPlatformUUID: Apple's own per-machine identifier, which
// survives an OS reinstall and changes when the logic board does. Read through
// ioreg rather than a library so this needs no cgo and no new dependency.
func rawMachineID() string {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		// "IOPlatformUUID" = "ABCDEF01-2345-..."
		if _, v, ok := strings.Cut(line, "="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}
