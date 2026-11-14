//go:build !darwin

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

// SetupVM is for macOS, where `fox setup` makes or reuses a Lima VM; the
// other hosts have none to name (see host_darwin.go).
func SetupVM() (name string, exists, ok bool) { return "", false, false }
