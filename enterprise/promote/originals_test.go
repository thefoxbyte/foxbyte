//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package promote

import "testing"

// A data change recorded with placeholders is told by them; a literal "$1"
// inside a string is still read as one, which is the safe way to be wrong (the
// request is refused rather than run with the wrong text).
func TestPlaceholderIsSeen(t *testing.T) {
	for s, want := range map[string]bool{
		"UPDATE people SET email = $1 WHERE id = $2":      true,
		"DELETE FROM people WHERE id = $10":               true,
		"UPDATE people SET email = 'a@b.in' WHERE id = 1": false,
		"UPDATE people SET price = $$1$$":                 false,
	} {
		if got := placeholder.MatchString(s); got != want {
			t.Errorf("%q: %v, want %v", s, got, want)
		}
	}
}
