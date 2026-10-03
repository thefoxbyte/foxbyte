// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/update"
)

// oldReportedVersion is what every release up to and including v1.0 shipped in
// internal/host/host_update.go: the last whitespace-separated field of
// `fox version`. Those binaries are the ones that run an update TO a newer
// release, so this is the parser the version line has to keep satisfying for
// as long as any of them is installed. It is copied here on purpose rather
// than imported — the point is that it cannot be changed from here.
func oldReportedVersion(out string) (update.Version, error) {
	f := strings.Fields(out)
	if len(f) == 0 {
		return update.Version{}, fmt.Errorf("no version printed")
	}
	return update.ParseVersion(f[len(f)-1])
}

// A Standard release's version line must be readable by that old parser. When
// the editions split added "(standard edition)" it stopped being, the last
// field became "edition)", and every existing install refused to update —
// after downloading a binary that ran perfectly well. The fix shipped in the
// new binary, which is not the one doing the parsing, so it fixed nobody.
func TestStandardVersionLineIsReadableByOlderInstalls(t *testing.T) {
	for _, ver := range []string{"1.0.1", "1.0", "2.11.3", "0.4"} {
		line := versionLineFor(false, ver, "standard edition")
		got, err := oldReportedVersion(line)
		if err != nil {
			t.Fatalf("a v1.0 install cannot read %q: %v\n"+
				"`fox update` would refuse every update to this release.", line, err)
		}
		want, err := update.ParseVersion(ver)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", ver, err)
		}
		if got.Compare(want) != 0 {
			t.Errorf("%q read as %v, want %v", line, got, want)
		}
	}
}

// Enterprise may say more after the version, because no Enterprise build
// predates the parser fix and `fox update` keeps a machine in its own edition.
// What it may not do is become unreadable to the current parser.
func TestEnterpriseVersionLineNamesTheEditionAndStillParses(t *testing.T) {
	line := versionLineFor(true, "1.0.1", "enterprise edition, no licence active")
	if !strings.Contains(line, "enterprise edition") {
		t.Errorf("an Enterprise build must say so: %q", line)
	}
	// The parser shipped from v1.0 onwards: the first field that parses.
	var got update.Version
	var found bool
	for _, f := range strings.Fields(line) {
		if v, err := update.ParseVersion(f); err == nil {
			got, found = v, true
			break
		}
	}
	if !found {
		t.Fatalf("no version field in %q", line)
	}
	want, _ := update.ParseVersion("1.0.1")
	if got.Compare(want) != 0 {
		t.Errorf("%q read as %v, want %v", line, got, want)
	}
}

// And the Standard line carries nothing after the version at all — the
// property the test above depends on, asserted directly so a future addition
// fails here with the reason rather than somewhere obscure.
func TestStandardVersionLineHasNothingAfterTheVersion(t *testing.T) {
	line := versionLineFor(false, "1.0.1", "standard edition")
	if fields := strings.Fields(line); len(fields) != 2 || fields[1] != "1.0.1" {
		t.Errorf("Standard's version line must be %q and nothing more, got %q\n"+
			"Anything after the version breaks `fox update` for every install older than v1.0.1.",
			"fox 1.0.1", line)
	}
}
