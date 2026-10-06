//go:build !enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// In the Standard build the feed's own commands do not exist: enable, disable
// and tables are the feature itself, and none of that code is compiled in. They
// fall through to `fox realtime`'s usage, which lists what this build does have
// — status, setup, teardown and slots, all of which work, because someone who
// goes back to Standard must still be able to see and undo what they turned on.
func realtimeEnterpriseCmd([]string) bool { return false }

func realtimeEnterpriseUsage() string { return "" }
