// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import "testing"

// destroy removes a branch's origin snapshot; it must never touch any other.
func TestIsOriginSnapshotFor(t *testing.T) {
	for _, c := range []struct {
		snap, branch string
		want         bool
	}{
		{snapFor("main", "qa"), "qa", true},
		{snapFor("itb", "itfrom"), "itfrom", true}, // created --from another branch
		{"-", "qa", false},                         // not a clone
		{"", "qa", false},
		{snapFor("main", "qa2"), "qa", false},               // another branch's snapshot
		{snapFor("main", "qa"), "a", false},                 // suffix of a longer name
		{"otherpool/branches/main@for-qa", "qa", false},     // outside FoxByte's datasets
		{datasetBase + "/main@nightly@for-qa", "qa", false}, // malformed
	} {
		if got := isOriginSnapshotFor(c.snap, c.branch); got != c.want {
			t.Errorf("isOriginSnapshotFor(%q, %q) = %v, want %v", c.snap, c.branch, got, c.want)
		}
	}
}
