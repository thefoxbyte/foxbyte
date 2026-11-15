// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package branch

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The lock reaches other processes through flock. Another process is played
// here by a second open of the lock file, which the kernel treats the same:
// flock locks belong to the open file, not the process.
func TestTheLockFileExcludesOtherProcesses(t *testing.T) {
	shortLockWait(t, 100*time.Millisecond)
	if err := os.MkdirAll(lockDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(lockPath("x"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte("4242 deleted\n"), 0)

	_, err = lockBranch("x", "woken")
	if !errors.Is(err, ErrBranchBusy) || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("lockBranch while another holds the file: %v, want ErrBranchBusy naming the delete", err)
	}
	// The in-process half was given back when the file lock timed out.
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	unlock, err := lockBranch("x", "woken")
	if err != nil {
		t.Fatalf("after the other let go: %v", err)
	}
	unlock()
}

// A holder that dies frees the branch: the kernel drops a closed file's lock.
func TestAClosedHolderFreesTheBranch(t *testing.T) {
	if err := os.MkdirAll(lockDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(lockPath("y"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	f.Close()
	shortLockWait(t, 100*time.Millisecond)
	unlock, err := lockBranch("y", "woken")
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
