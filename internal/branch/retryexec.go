// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// wakeForExec starts a branch whose container another process has stopped.
// EnsureRunning trusts a two-second memory of "running"; docker exec does
// not. A variable so a test can stand in for Docker.
var wakeForExec = EnsureRunning

// containerStopped reports a docker exec that reached a container the state
// cache still thought was running. The message is docker's own.
func containerStopped(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "is not running") || strings.Contains(s, "no such container")
}

// retryIfStopped runs fn, and when the container has been stopped out from
// under the state cache, forgets that cache, wakes the branch, and tries
// once more. A SQL error is returned as it is: waking would not change it.
//
// This is the same shape as the gateway's dial: the first attempt uses the
// address it already has, and a failure means that memory was wrong.
func retryIfStopped(name string, fn func() error) error {
	err := fn()
	if !containerStopped(err) {
		return err
	}
	if wakingHeld(name) {
		return fmt.Errorf("%w (%v)", errSuspendedMeanwhile, err)
	}
	ForgetBackends()
	if _, werr := wakeForExec(name); werr != nil {
		return err
	}
	return fn()
}

// errSuspendedMeanwhile is what an unattended job gets when the branch it was
// reading was suspended under it: not an error worth logging, and not a reason
// to start the branch again.
var errSuspendedMeanwhile = errors.New("the branch was suspended meanwhile, and is left suspended")

// noWake holds the branches an unattended job (the checkpoint scheduler) is
// reading. The scheduler takes only running branches, but the idle reaper can
// stop one between the list and the read; retryIfStopped would then start it
// again, so the scheduler kept waking the branches scale-to-zero had just put
// to sleep (seen 23 Nov 2026: pg-itidle2 stopped at 11:00:21 by the reaper,
// started at 11:00:23 by a checkpoint). A count, not a flag, so two jobs on one
// branch do not release each other.
var noWake = struct {
	sync.Mutex
	held map[string]int
}{held: map[string]int{}}

// withoutWaking runs fn with name marked: inside it, a read that finds the
// branch stopped returns errSuspendedMeanwhile rather than starting it. A read
// someone asked for, on that branch at that moment, does not wake it either;
// it can be asked again.
func withoutWaking(name string, fn func()) {
	noWake.Lock()
	noWake.held[name]++
	noWake.Unlock()
	defer func() {
		noWake.Lock()
		if noWake.held[name]--; noWake.held[name] <= 0 {
			delete(noWake.held, name)
		}
		noWake.Unlock()
	}()
	fn()
}

func wakingHeld(name string) bool {
	noWake.Lock()
	defer noWake.Unlock()
	return noWake.held[name] > 0
}
