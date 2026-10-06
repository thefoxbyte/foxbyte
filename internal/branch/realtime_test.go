// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// realtimeMarkerIn points the marker at a directory of this test's own, so these
// never depend on what the machine running them has opted into — and never
// write to it either.
//
// Setting HOME is not enough: brand.StateDir resolves once per process and
// caches, so the first test to ask wins for the whole binary. The first version
// of this file did that and passed or failed by test order.
func realtimeMarkerIn(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := realtimeMarker
	realtimeMarker = func() string { return filepath.Join(dir, "realtime") }
	t.Cleanup(func() { realtimeMarker = old })
	return dir
}

func realtimeOff(t *testing.T) { t.Helper(); realtimeMarkerIn(t) }

func realtimeOnFor(t *testing.T) {
	t.Helper()
	realtimeMarkerIn(t)
	if err := SetRealtimeOn(true); err != nil {
		t.Fatal(err)
	}
}

// The promise this whole change rests on: with the feed off, every database
// starts exactly as it did before realtime existed.
//
// These are the arguments as of the change that introduced the feed, written
// out rather than computed, so a later edit that "tidies" them has to change
// this list too and say why. An upgrade that silently restarted every primary
// with different settings is the failure being prevented.
func TestWithTheFeedOffTheArgumentsAreUnchanged(t *testing.T) {
	realtimeOff(t)

	wantPrimary := []string{
		"postgres",
		"-c", "wal_level=replica",
		"-c", "archive_mode=on",
		"-c", "archive_command=wal-g wal-push %p",
		"-c", "archive_timeout=60",
		"-c", "listen_addresses=*",
	}
	if got := postgresArgs(true); !reflect.DeepEqual(got, wantPrimary) {
		t.Errorf("primary args changed\n got: %q\nwant: %q", got, wantPrimary)
	}
	// And a branch gets no command line at all, so the image's own default runs.
	if got := postgresArgs(false); got != nil {
		t.Errorf("a branch was given a command line with the feed off: %q", got)
	}
}

// With it on, a primary keeps all five and gains the WAL budget; wal_level is
// named once, with the new value.
func TestWithTheFeedOnThePrimaryGainsOnlyWhatItNeeds(t *testing.T) {
	realtimeOnFor(t)
	got := postgresArgs(true)

	if n := strings.Count(strings.Join(got, " "), "wal_level="); n != 1 {
		t.Errorf("wal_level appears %d times, want exactly 1: %q", n, got)
	}
	for _, want := range []string{"wal_level=logical", "max_slot_wal_keep_size=" + WALKeepSize()} {
		if !containsArg(got, want) {
			t.Errorf("primary is missing %q: %q", want, got)
		}
	}
	// Everything it had before is still there.
	for _, want := range []string{"archive_mode=on", "archive_command=wal-g wal-push %p",
		"archive_timeout=60", "listen_addresses=*"} {
		if !containsArg(got, want) {
			t.Errorf("the feed dropped %q from the primary: %q", want, got)
		}
	}
}

// A branch gets a command line for the first time, and `postgres` has to lead
// it or docker takes the first flag for the command.
func TestWithTheFeedOnABranchIsGivenACommandLine(t *testing.T) {
	realtimeOnFor(t)
	got := postgresArgs(false)
	if len(got) == 0 || got[0] != "postgres" {
		t.Fatalf("a branch's command line must start with postgres: %q", got)
	}
	for _, want := range []string{"wal_level=logical", "max_slot_wal_keep_size=" + WALKeepSize(), "listen_addresses=*"} {
		if !containsArg(got, want) {
			t.Errorf("branch is missing %q: %q", want, got)
		}
	}
	// A branch does not archive: that is the primary's job, and wal-g is not
	// configured on a clone.
	if containsArg(got, "archive_mode=on") {
		t.Errorf("a branch was given the primary's archiving: %q", got)
	}
}

// Opting in is a file, and opting out removes it. Neither restarts anything —
// the command that calls these says what it is about to do first.
func TestRealtimeOptInIsRecorded(t *testing.T) {
	realtimeMarkerIn(t)
	if RealtimeOn() {
		t.Fatal("a fresh install has the feed on")
	}
	if err := SetRealtimeOn(true); err != nil || !RealtimeOn() {
		t.Fatalf("opting in: %v", err)
	}
	if err := SetRealtimeOn(false); err != nil || RealtimeOn() {
		t.Fatalf("opting out: %v", err)
	}
	// Opting out twice is not an error: the end state is what was asked for.
	if err := SetRealtimeOn(false); err != nil {
		t.Errorf("opting out when already out: %v", err)
	}
}

// Slot names are built, not taken: a branch or subscription name goes into a
// Postgres identifier with a length limit and a narrow alphabet.
func TestSlotNamesAreSafe(t *testing.T) {
	for _, c := range []struct{ branchName, sub string }{
		{"main", "orders"},
		{"feature/ABC-123", "my sub"},
		{strings.Repeat("x", 90), strings.Repeat("y", 90)},
		{"a'; DROP TABLE t; --", "b"},
	} {
		got := SlotName(c.branchName, c.sub)
		if !strings.HasPrefix(got, SlotPrefix) {
			t.Errorf("SlotName(%q,%q) = %q, missing the prefix", c.branchName, c.sub, got)
		}
		if len(got) > 63 {
			t.Errorf("SlotName(%q,%q) is %d bytes; Postgres allows 63", c.branchName, c.sub, len(got))
		}
		for _, r := range got {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
				t.Errorf("SlotName(%q,%q) = %q contains %q", c.branchName, c.sub, got, r)
				break
			}
		}
	}
}

// The budget is tunable, because the right number depends on how much the
// database writes and how long a subscriber may reasonably be away.
func TestWALKeepSizeIsTunable(t *testing.T) {
	if got := WALKeepSize(); got != "1GB" {
		t.Errorf("default = %q, want 1GB", got)
	}
	t.Setenv(brand.EnvName("REALTIME_WAL_KEEP"), "4GB")
	if got := WALKeepSize(); got != "4GB" {
		t.Errorf("overridden = %q, want 4GB", got)
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// A standby is a primary in waiting. Started without the feed's settings it
// would come up after a failover unable to decode, and realtime would stop
// working at the worst possible moment and for no visible reason.
func TestTheStandbyGetsWhatThePrimaryGets(t *testing.T) {
	for _, on := range []bool{false, true} {
		func() {
			realtimeMarkerIn(t)
			if on {
				if err := SetRealtimeOn(true); err != nil {
					t.Fatal(err)
				}
			}
			standby := standbyRunArgs("/tmp/x")
			want := postgresArgs(true)
			// The standby's run args end with the postgres command line.
			if len(standby) < len(want) {
				t.Fatalf("standby args are shorter than the primary's command line: %q", standby)
			}
			got := standby[len(standby)-len(want):]
			if !reflect.DeepEqual(got, want) {
				t.Errorf("realtime=%v: standby\n got: %q\nwant: %q", on, got, want)
			}
		}()
	}
}
