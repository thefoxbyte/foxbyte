// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package branch

// pidAlive: the engine runs in its Linux distribution, not here, so a making
// seen from Windows is taken as running.
func pidAlive(int) bool { return true }
