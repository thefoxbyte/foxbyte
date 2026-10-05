//go:build !darwin && !windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"os"
	"strings"
)

// rawMachineID on Linux is /etc/machine-id, which systemd writes once at
// install and which is explicitly meant for this. Two fallbacks behind it:
// /var/lib/dbus/machine-id for systems that predate it or keep only that one,
// and then the DMI product UUID, which comes from the firmware and survives a
// reinstall.
//
// A container inherits the image's machine-id, so every container from one
// image reports the same fingerprint. That is a reason the lock is soft rather
// than a bug to fix here: no reading of a machine id is meaningful under
// immutable infrastructure, which is also why the hosted plan replaces this
// with an account the server knows about.
func rawMachineID() string {
	for _, p := range []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
		"/sys/class/dmi/id/product_uuid",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(b)); id != "" {
			return id
		}
	}
	return ""
}
