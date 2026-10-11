// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Where the backups go, as `fox check` reports it.
//
// The default sends the write-ahead log archive and every base backup to the
// object store beside main, on the same disk — fine for a laptop, and wrong
// for anything holding data somebody would miss. This line is the only place
// the product says so unprompted, so what it says matters.
func TestBackupTargetLine(t *testing.T) {
	t.Run("the local store warns, and says what it costs", func(t *testing.T) {
		got := backupTargetLine(branch.Target{Kind: "local"}, nil)
		if got.state != stateWarn {
			t.Fatalf("state %d, want a warning", got.state)
		}
		// The consequence, not just the fact. "backups are local" is a
		// configuration note; "one disk failure takes the database and every
		// backup of it" is a reason to act.
		for _, want := range []string{"same disk", "every backup of it"} {
			if !strings.Contains(got.detail, want) {
				t.Errorf("detail %q does not mention %q", got.detail, want)
			}
		}
		// And the way out, which needs no new code.
		if !strings.Contains(got.fix, "backup target set") {
			t.Errorf("fix %q does not name the command", got.fix)
		}
	})

	t.Run("a remote target is fine, and is described", func(t *testing.T) {
		got := backupTargetLine(branch.Target{
			Kind: "s3", Bucket: "acme-fox-backups", Endpoint: "https://s3.eu-west-1.amazonaws.com",
			Region: "eu-west-1", AccessKey: "AKIA…",
		}, nil)
		if got.state != 0 {
			t.Fatalf("state %d, want ok: %s", got.state, got.detail)
		}
		if !strings.Contains(got.detail, "acme-fox-backups") {
			t.Errorf("detail %q does not name the bucket", got.detail)
		}
	})

	// A target file that cannot be read is not "assume local": backups would
	// go somewhere the owner did not choose, which is the one outcome this
	// check exists to prevent.
	t.Run("an unreadable target fails rather than guessing", func(t *testing.T) {
		got := backupTargetLine(branch.Target{}, errTargetForTest{})
		if got.state != stateFail {
			t.Fatalf("state %d, want a failure", got.state)
		}
		if !strings.Contains(got.detail, "backup-target.json") {
			t.Errorf("detail %q does not say which file", got.detail)
		}
	})
}

type errTargetForTest struct{}

func (errTargetForTest) Error() string {
	return "/home/a/.fox/backup-target.json: unexpected end of JSON input"
}
