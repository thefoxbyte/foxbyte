// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strconv"
	"strings"
	"testing"
)

// Every hop from a supported major to PGMajor must have notes: a bump of
// PGMajor with nothing written about the new release fails here, not in front
// of a user about to move their data.
func TestEveryUpgradeHopHasNotes(t *testing.T) {
	for _, from := range SupportedPGMajors {
		for m := int(majorNum(from)) + 1; m <= int(majorNum(PGMajor)); m++ {
			major := strconv.Itoa(m)
			found := false
			for _, n := range pgNotes {
				if n.Major == major {
					found = true
				}
			}
			if !found {
				t.Errorf("no upgrade notes for PostgreSQL %s (moving %s → %s crosses it): add them to pgNotes from its release notes' Migration section", major, from, PGMajor)
			}
		}
	}
}

func TestNotesAreComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range pgNotes {
		if n.ID == "" || n.Headline == "" || n.Detail == "" || !strings.HasPrefix(n.DocURL, "https://www.postgresql.org/docs/"+n.Major+"/") {
			t.Errorf("note %q is incomplete or points at another release's notes: %+v", n.ID, n)
		}
		if !strings.HasPrefix(n.ID, "pg"+n.Major+"-") {
			t.Errorf("note %q should be named for its release, pg%s-…", n.ID, n.Major)
		}
		if seen[n.ID] {
			t.Errorf("note %q is listed twice", n.ID)
		}
		seen[n.ID] = true
		if n.Probe != "" && !strings.Contains(strings.ToUpper(n.Probe), "SELECT") {
			t.Errorf("note %q has a probe that is not a query", n.ID)
		}
	}
}

func TestNotesBetween(t *testing.T) {
	if got := NotesBetween("16", "18"); len(got) == 0 || got[0].Major != "17" || got[len(got)-1].Major != "18" {
		t.Errorf("16 → 18 should cross 17 then 18, got %d notes starting at %q", len(got), got[0].Major)
	}
	if got := NotesBetween("18", "18"); len(got) != 0 {
		t.Errorf("staying on 18 crosses nothing, got %d notes", len(got))
	}
	for _, n := range NotesBetween("17", "18") {
		if n.Major != "18" {
			t.Errorf("17 → 18 should not include the 17 note %q", n.ID)
		}
	}
}
