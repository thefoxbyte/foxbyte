// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A restore check that main's restart interrupted is not a restore that failed.
//
// Seen on 2026-10-23: the scheduled check ran while integration §11c restarted
// main for a new backup target, the probe row's docker exec failed with exit
// status 128, and that was written down as the last check, so `fox check`
// reported "restore proven" as FAIL for the next hour. The backups were fine.
func TestRestoreCheckPrimaryGoingAway(t *testing.T) {
	up := primaryState{ID: "c0ffee", Status: "running", StartedAt: "2026-10-23T10:00:00.1Z", Ready: true}
	probeErr := errors.New("writing the probe row: exit status 128")

	t.Run("the primary down or not accepting connections explains the failure", func(t *testing.T) {
		for _, after := range []primaryState{
			{Status: "absent"},
			{ID: up.ID, Status: "restarting", StartedAt: up.StartedAt},
			{ID: up.ID, Status: "exited", StartedAt: up.StartedAt},
			{ID: up.ID, Status: "running", StartedAt: up.StartedAt, Ready: false},
		} {
			err := onPrimary("main", probeErr, up, after)
			if !errors.Is(err, ErrPrimaryUnavailable) {
				t.Errorf("primary %+v: got %v, want ErrPrimaryUnavailable", after, err)
			}
		}
	})

	t.Run("so does a restart that finished before anyone looked again", func(t *testing.T) {
		// docker restart: the same container, started again.
		restarted := up
		restarted.StartedAt = "2026-10-23T10:00:03.7Z"
		// fox start: the container removed and created again.
		recreated := up
		recreated.ID = "deadbeef"
		for _, after := range []primaryState{restarted, recreated} {
			if err := onPrimary("main", probeErr, up, after); !errors.Is(err, ErrPrimaryUnavailable) {
				t.Errorf("primary %+v: got %v, want ErrPrimaryUnavailable", after, err)
			}
		}
	})

	t.Run("with the same primary up throughout, a failure is a failed check", func(t *testing.T) {
		// A probe row that cannot be written, or WAL that does not reach the
		// archive, with main fine: exactly what the check exists to catch.
		err := onPrimary("main", probeErr, up, up)
		if err != probeErr {
			t.Fatalf("got %v, want the error unchanged", err)
		}
		if errors.Is(err, ErrPrimaryUnavailable) || !recordable(err) {
			t.Error("a genuine failure must be recorded")
		}
	})

	t.Run("no failure is no failure", func(t *testing.T) {
		if err := onPrimary("main", nil, up, primaryState{Status: "absent"}); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("the message says what happened and that nothing was recorded", func(t *testing.T) {
		after := up
		after.Status, after.Ready = "restarting", false
		msg := onPrimary("main", probeErr, up, after).Error()
		for _, want := range []string{"main was not available", "exit status 128", "it is now restarting", "nothing was recorded"} {
			if !strings.Contains(msg, want) {
				t.Errorf("message %q does not contain %q", msg, want)
			}
		}
		if !errors.Is(onPrimary("main", probeErr, up, after), probeErr) {
			t.Error("the step's own error should still be reachable with errors.Is")
		}
	})
}

// What is written down, and when the scheduler looks again.
func TestRestoreCheckRecording(t *testing.T) {
	os.Remove(restoreCheckPath())
	t.Cleanup(func() { os.Remove(restoreCheckPath()) })
	if err := os.MkdirAll(filepath.Dir(restoreCheckPath()), 0o755); err != nil {
		t.Fatal(err)
	}

	good := RestoreCheck{At: "2026-10-23T09:00:00Z", Token: "probe-1", BaseBackup: "base_1"}
	if _, err := conclude(good, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if last, ok := LastRestoreCheck(); !ok || !last.OK || last.Token != "probe-1" {
		t.Fatalf("a passing check was not recorded: %+v %v", last, ok)
	}

	t.Run("a check the primary's absence stopped leaves the last result alone", func(t *testing.T) {
		skipped := RestoreCheck{At: "2026-10-23T10:00:00Z", Token: "probe-2"}
		err := &primaryUnavailableError{"main", errors.New("it was still restarting after 1m30s")}
		c, got := conclude(skipped, time.Now(), err)
		if got != error(err) || c.OK || c.Err == "" {
			t.Errorf("the caller should still see the failure: %+v %v", c, got)
		}
		if last, _ := LastRestoreCheck(); last.Token != "probe-1" || !last.OK {
			t.Errorf("the last check was overwritten: %+v", last)
		}
		if d := nextLook(err); d != retryAfterUnavailable || d >= time.Hour {
			t.Errorf("next look in %s, want %s", d, retryAfterUnavailable)
		}
	})

	t.Run("a genuine failure is recorded and reported as before", func(t *testing.T) {
		failed := RestoreCheck{At: "2026-10-23T11:00:00Z", Token: "probe-3"}
		err := errors.New("restoring: restore did not complete in time")
		if _, got := conclude(failed, time.Now(), err); got != err {
			t.Fatalf("got %v", got)
		}
		last, _ := LastRestoreCheck()
		if last.Token != "probe-3" || last.OK || last.Err != err.Error() {
			t.Errorf("the failure was not recorded as it is: %+v", last)
		}
		if d := nextLook(err); d != time.Hour {
			t.Errorf("next look in %s, want the hourly look", d)
		}
		if d := nextLook(nil); d != time.Hour {
			t.Errorf("after a pass, next look in %s, want the hourly look", d)
		}
	})
}
