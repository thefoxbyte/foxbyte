//go:build !darwin && !windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

// On Linux the host is the engine: the file the caller just wrote is the file
// the engine opens, so there is nothing to copy and nowhere to copy it to.
func pushGuestState(string, []byte) error { return nil }

func removeGuestState(string) error { return nil }
