// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// One branch, one change at a time.
//
// The gateway, the control plane, the Agent API, MCP and the CLI are separate
// processes, and each of them may start, stop, make or remove the same branch.
// Nothing used to order them. A wake could start a container in the moment
// between a delete removing the old one and destroying its data; two wakes
// could both run startContainer, whose first step removes whatever container
// is there; the idle reaper could stop a branch a client was half way through
// connecting to.
//
// So every operation that changes what a branch is, or whether it runs, holds
// that branch's lock while it does: a wake or recreate, a suspend, a create, a
// delete, a reset and a restore. The lock is two layers:
//
//   - a per-name slot in this process, so goroutines here queue in order and a
//     wait can give up on time;
//   - an exclusive flock(2) on a small file in the state directory
//     (locks/branch-<name>.lock), so other processes queue too. The kernel
//     drops it when its holder exits, so a crashed command cannot leave a
//     branch locked.
//
// A wait is bounded (FOX_BRANCH_LOCK_TIMEOUT, two minutes by default) and ends
// in ErrBranchBusy naming what holds the branch, never in a hang. The lock is
// not re-entrant: code that holds it calls the *Locked forms of the operations
// below, never the public ones for the same name.
//
// The files are never removed. Removing a lock file another process has open
// would let a third process lock a new file of the same name, and two holders
// would each believe they had the branch.

// ErrBranchBusy: another operation held the branch for longer than a caller
// waits. Retrying later is the remedy.
var ErrBranchBusy = errors.New("branch is busy")

// EnvBranchLockTimeout tunes how long an operation waits for a branch another
// one is changing (a duration such as "5m").
const EnvBranchLockTimeout = "BRANCH_LOCK_TIMEOUT"

const defaultBranchLockWait = 2 * time.Minute

// branchLockWait is how long lockBranch waits. A variable so a test need not
// wait minutes to see a timeout.
var branchLockWait = func() time.Duration {
	if v := strings.TrimSpace(brand.Getenv(EnvBranchLockTimeout)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultBranchLockWait
}

// branchSlot is this process's half of a branch's lock: a one-place channel,
// so a waiter can stop waiting at a deadline, and what the holder is doing,
// for the message a waiter that gives up prints.
type branchSlot struct {
	ch chan struct{}
	mu sync.Mutex
	op string
}

var branchSlots sync.Map // name -> *branchSlot

func slotFor(name string) *branchSlot {
	s, _ := branchSlots.LoadOrStore(name, &branchSlot{ch: make(chan struct{}, 1)})
	return s.(*branchSlot)
}

// lockDir is where the lock files live.
func lockDir() string { return brand.StatePath("locks") }

func lockPath(name string) string { return filepath.Join(lockDir(), "branch-"+name+".lock") }

// lockBranch takes the branch's lock for op ("woken", "deleted", ...) and
// returns what releases it. name must already have passed checkName: it is
// part of a file name.
func lockBranch(name, op string) (func(), error) {
	wait := branchLockWait()
	deadline := time.Now().Add(wait)
	s := slotFor(name)
	timer := time.NewTimer(wait)
	select {
	case s.ch <- struct{}{}:
		timer.Stop()
	case <-timer.C:
		s.mu.Lock()
		holder := s.op
		s.mu.Unlock()
		return nil, busyErr(name, holder, wait)
	}
	release, err := lockBranchFile(name, op, deadline, wait)
	if err != nil {
		<-s.ch
		return nil, err
	}
	s.mu.Lock()
	s.op = op
	s.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.op = ""
			s.mu.Unlock()
			release()
			<-s.ch
		})
	}, nil
}

// busyErr says which branch, what has it if that is known, and how long the
// caller waited.
func busyErr(name, holder string, wait time.Duration) error {
	if holder == "" {
		holder = "changed"
	}
	return fmt.Errorf("%w: %q is being %s by another operation and it did not finish within %s; try again shortly (%s sets the wait)",
		ErrBranchBusy, name, holder, wait, brand.EnvName(EnvBranchLockTimeout))
}

// lockHolderNote is what a holder writes into its lock file, and readHolder
// what a waiter reads back for its message.
func lockHolderNote(op string) string { return fmt.Sprintf("%d %s\n", os.Getpid(), op) }

func readHolder(note string) string {
	_, op, ok := strings.Cut(strings.TrimSpace(note), " ")
	if !ok {
		return ""
	}
	return op
}

// wakeFlight is one wake in progress, for the callers in this process that
// asked for the same branch while it ran. A burst of connections to a
// suspended branch costs one wake, not one queued behind another.
type wakeFlight struct {
	done chan struct{}
	addr string
	err  error
}

var wakes = struct {
	mu sync.Mutex
	m  map[string]*wakeFlight
}{m: map[string]*wakeFlight{}}

// wakeOnce runs fn for name unless a run for name is already under way here,
// in which case it waits for that one's answer.
func wakeOnce(name string, fn func() (string, error)) (string, error) {
	wakes.mu.Lock()
	if fl, ok := wakes.m[name]; ok {
		wakes.mu.Unlock()
		<-fl.done
		return fl.addr, fl.err
	}
	fl := &wakeFlight{done: make(chan struct{})}
	wakes.m[name] = fl
	wakes.mu.Unlock()

	fl.addr, fl.err = fn()

	wakes.mu.Lock()
	delete(wakes.m, name)
	wakes.mu.Unlock()
	close(fl.done)
	return fl.addr, fl.err
}

// When EnsureRunning last routed a caller to each branch, in this process.
//
// The idle reaper runs in the gateway, beside the connections it must not cut.
// A client is routed (EnsureRunning) a moment before Postgres counts it as a
// connection: the dial, TLS and the backend's own startup come in between. A
// sweep whose probes landed in that moment saw no connections and stopped the
// branch under the client. So the reaper's suspend, under the branch's lock,
// first asks whether anyone was routed there within suspendGrace.
var routed = struct {
	mu sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

// suspendGrace is how long after being routed to a branch stays safe from the
// idle reaper. Far longer than a connection takes to start, far shorter than
// any idle window.
const suspendGrace = 30 * time.Second

func noteRouted(name string) {
	routed.mu.Lock()
	routed.at[name] = time.Now()
	routed.mu.Unlock()
}

func routedWithin(name string, d time.Duration) bool {
	routed.mu.Lock()
	defer routed.mu.Unlock()
	t, ok := routed.at[name]
	return ok && time.Since(t) < d
}
