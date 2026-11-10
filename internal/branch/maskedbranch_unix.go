// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package branch

import (
	"errors"
	"syscall"
)

// pidAlive: signal 0 asks without sending anything.
func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
