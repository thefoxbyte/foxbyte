//go:build !enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// enterpriseCmd handles the paid edition's commands. In the Standard build
// there are none, so every command falls through to "unknown command" — the
// commands do not exist here, rather than existing and refusing.
func enterpriseCmd(args []string) bool { return false }

// enterpriseUsage is appended to `fox help` when there is something to say.
func enterpriseUsage() string { return "" }
