// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package branch

import "time"

// lockBranchFile: the engine never runs on Windows itself (the launcher hands
// every command to the Linux VM), so there is no other process here to share a
// branch with. This process's own half of the lock still applies.
func lockBranchFile(string, string, time.Time, time.Duration) (func(), error) {
	return func() {}, nil
}
