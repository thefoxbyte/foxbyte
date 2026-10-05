//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"os/exec"
	"strings"
)

// rawMachineID is MachineGuid, written by Windows at install time and stable
// for the life of that installation. Read with reg.exe rather than a registry
// library: it is in every Windows image, and this package already shells out
// for everything else it needs from the OS.
func rawMachineID() string {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "MachineGuid") {
			continue
		}
		// "    MachineGuid    REG_SZ    abcdef01-2345-..."
		if i := strings.Index(line, "REG_SZ"); i >= 0 {
			return strings.TrimSpace(line[i+len("REG_SZ"):])
		}
	}
	return ""
}
