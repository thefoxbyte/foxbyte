// SPDX-License-Identifier: AGPL-3.0-or-later

// Package version holds the foxbyte build version.
package version

// Version is the current foxbyte version. It is a var (not a const) so
// release builds can stamp it via -ldflags "-X …version.Version=…".
var Version = "0.1.0-dev"
