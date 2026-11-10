// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"slices"
	"sync"
	"time"
)

// The dashboard asks what every branch is doing, and the import page which of
// them are replicating, every few seconds per open tab. Each answer was a
// serial walk over the branches, an inspect and a `docker exec psql` apiece, so
// the cost was tabs times branches, and twenty tabs on two branches was p95 1.2s.
//
// One answer now serves everybody for a few seconds. Nothing per-caller belongs
// in a Snapshot: the API filters what it is given by the caller's access after
// it comes out, and must go on doing that.
const (
	// SnapshotTTL is how old a shared answer may be. It bounds how long a change
	// made by another process (the gateway suspending an idle branch, the CLI)
	// is unseen on the dashboard. This process's own changes are seen at once.
	SnapshotTTL = 5 * time.Second
	// SnapshotWait is how long a caller holding the previous answer waits for a
	// new one before showing the previous one instead. With no previous answer
	// it waits for as long as the read takes, as it always did.
	SnapshotWait = 4 * time.Second
)

// Snapshot is one expensive answer shared between callers: at most one read at
// a time, kept for a TTL, and out of date the moment this process changes
// anything (noteStateChange), so the page that made a change shows it.
//
// A failed read is not kept: the next caller tries again.
type Snapshot[T any] struct {
	ttl, wait time.Duration
	read      func() (T, error)

	mu     sync.Mutex
	val    T
	has    bool
	at     time.Time
	gen    uint64
	flight *snapshotFlight[T]
}

type snapshotFlight[T any] struct {
	gen  uint64
	done chan struct{}
	val  T
	err  error
}

// NewSnapshot makes a Snapshot of read.
func NewSnapshot[T any](ttl, wait time.Duration, read func() (T, error)) *Snapshot[T] {
	return &Snapshot[T]{ttl: ttl, wait: wait, read: read}
}

// Get returns the shared answer, reading it first if it has gone out of date.
func (s *Snapshot[T]) Get() (T, error) {
	s.mu.Lock()
	gen := stateGen.Load()
	if s.has && s.gen == gen && stateNow().Sub(s.at) < s.ttl {
		v := s.val
		s.mu.Unlock()
		return v, nil
	}
	// A read begun before a change may have seen the world from before it, so
	// nobody who comes after the change joins it.
	fl := s.flight
	if fl == nil || fl.gen != gen {
		fl = &snapshotFlight[T]{gen: gen, done: make(chan struct{})}
		s.flight = fl
		go s.fetch(fl)
	}
	prev, hasPrev := s.val, s.has
	s.mu.Unlock()

	if !hasPrev {
		<-fl.done
		return fl.val, fl.err
	}
	timer := time.NewTimer(s.wait)
	defer timer.Stop()
	select {
	case <-fl.done:
		return fl.val, fl.err
	case <-timer.C:
		return prev, nil
	}
}

func (s *Snapshot[T]) fetch(fl *snapshotFlight[T]) {
	defer close(fl.done)
	func() {
		// On its own goroutine, where net/http's recovery does not reach: a
		// panic here would take the whole control plane with it.
		defer func() {
			if p := recover(); p != nil {
				fl.err = fmt.Errorf("reading a snapshot: %v", p)
			}
		}()
		fl.val, fl.err = s.read()
	}()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flight == fl {
		s.flight = nil
	}
	if fl.err == nil && fl.gen == stateGen.Load() {
		s.val, s.has, s.at, s.gen = fl.val, true, stateNow(), fl.gen
	}
}

// branchesSnapshot and replicatingSnapshot are the shared answers the console's
// polling reads.
var (
	branchesSnapshot    = NewSnapshot(SnapshotTTL, SnapshotWait, func() ([]BranchInfo, error) { return Branches() })
	replicatingSnapshot = NewSnapshot(SnapshotTTL, SnapshotWait, func() ([]Replication, error) { return Replicating() })
)

// BranchesSnapshot is Branches as of a few seconds ago, for callers polling it.
// For a display only: anything deciding what to do to a branch uses Branches or
// ContainerState. Every caller gets its own slice.
func BranchesSnapshot() ([]BranchInfo, error) {
	bs, err := branchesSnapshot.Get()
	return slices.Clone(bs), err
}

// ReplicatingSnapshot is Replicating as of a few seconds ago, for callers
// polling it. Every caller gets its own slice.
func ReplicatingSnapshot() ([]Replication, error) {
	rs, err := replicatingSnapshot.Get()
	return slices.Clone(rs), err
}

// maxProbeFanOut bounds how many branches are asked about at once, so a large
// install does not start every process together.
const maxProbeFanOut = 8

// forEachBounded runs f(0..n-1) with at most maxProbeFanOut running at a time,
// and returns when all have finished.
func forEachBounded(n int, f func(i int)) {
	sem := make(chan struct{}, maxProbeFanOut)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			f(i)
		}()
	}
	wg.Wait()
}
