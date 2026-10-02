// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import "github.com/thefoxbyte/foxbyte/internal/edition"

// featureNames is the paid features this engine can currently serve, as plain
// strings for /api/status. Always a list, never null: the console iterates it,
// and an empty list is the honest answer for a Standard build.
func featureNames() []string {
	out := []string{}
	for _, f := range edition.Available() {
		out = append(out, string(f))
	}
	return out
}
