// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package branch

import (
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// lockBranchFile is the other processes' half of lockBranch: an exclusive
// flock on the branch's lock file, polled rather than blocked on so that a
// wait can end at the deadline. Polling starts fast, because most holders
// finish quickly, and slows to a few times a second for one that does not.
func lockBranchFile(name, op string, deadline time.Time, wait time.Duration) (func(), error) {
	if err := os.MkdirAll(lockDir(), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath(name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	pause := 5 * time.Millisecond
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			note, _ := io.ReadAll(io.LimitReader(f, 256))
			f.Close()
			return nil, busyErr(name, readHolder(string(note)), wait)
		}
		time.Sleep(pause)
		if pause < 200*time.Millisecond {
			pause *= 2
		}
	}
	// Who has it, for a waiter's message. Best-effort: the lock is the flock,
	// not these words.
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(lockHolderNote(op)), 0)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}
