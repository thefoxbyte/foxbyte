//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// enterpriseCmd handles the paid edition's commands, returning false when the
// command is not one of them so main falls through to "unknown command".
// Each handler calls requireFeature first: the command exists in this build,
// and whether it runs is a licence question.
func enterpriseCmd(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	// Stage 3 adds `realtime` here.
	default:
		return false
	}
}

// enterpriseUsage is appended to `fox help`.
func enterpriseUsage() string { return "" }
