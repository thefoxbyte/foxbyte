// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package branch

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockAuditStore holds the store for one collector at a time: the control
// plane's, every minute, and `fox audit-log show`'s, which collects first.
// The lock goes with the process, so one that dies holding it frees it.
func lockAuditStore() (func(), error) {
	f, err := os.OpenFile(filepath.Join(AuditStoreDir(), "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
