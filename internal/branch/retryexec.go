// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
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
	ForgetBackends()
	if _, werr := wakeForExec(name); werr != nil {
		return err
	}
	return fn()
}
