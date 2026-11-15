//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "github.com/thefoxbyte/foxbyte/internal/brand"

// enterpriseCmd handles the paid edition's commands, returning false when the
// command is not one of them so main falls through to "unknown command".
// Each handler calls requireFeature first: the command exists in this build,
// and whether it runs is a licence question.
func enterpriseCmd(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "subject":
		subjectCmd(args[1:])
		return true
	// `realtime` is dispatched by main and falls through to
	// realtimeEnterpriseCmd, so the paid subcommands sit beside the free ones
	// rather than in a separate top-level command.
	default:
		return false
	}
}

// enterpriseUsage is appended to `fox help`.
func enterpriseUsage() string {
	return realtimeEnterpriseUsage() + "\n" + brand.CLI +
		" subject find <value> [--category c] [--json]  where one person's data appears, for an access or erasure request\n"
}
