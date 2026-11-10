// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSnapshotIsSharedForItsTTL(t *testing.T) {
	_, advance := withFakeDocker(t)
	reads := 0
	s := NewSnapshot(SnapshotTTL, SnapshotWait, func() (int, error) { reads++; return reads, nil })
	for range 10 {
		if v, err := s.Get(); err != nil || v != 1 {
			t.Fatalf("Get = %d, %v", v, err)
		}
	}
	if reads != 1 {
		t.Fatalf("%d reads for 10 callers, want 1", reads)
	}
	advance(SnapshotTTL)
	if v, _ := s.Get(); v != 2 {
		t.Fatalf("Get after the TTL = %d, want a new read", v)
	}
}

// Create, delete and suspend have to show on the very next poll.
func TestSnapshotIsOutOfDateAfterAStateChange(t *testing.T) {
	_, _ = withFakeDocker(t)
	reads := 0
	s := NewSnapshot(SnapshotTTL, SnapshotWait, func() (int, error) { reads++; return reads, nil })
	_, _ = s.Get()
	noteIfChange("docker", []string{"stop", "pg-a"})
	if v, _ := s.Get(); v != 2 {
		t.Fatalf("Get = %d: a change this process made was not seen", v)
	}
}

func TestSnapshotConcurrentCallersShareOneRead(t *testing.T) {
	_, _ = withFakeDocker(t)
	var reads atomic.Int64
	gate := make(chan struct{})
	s := NewSnapshot(SnapshotTTL, SnapshotWait, func() (int, error) { reads.Add(1); <-gate; return 7, nil })
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			if v, err := s.Get(); err != nil || v != 7 {
				t.Errorf("Get = %d, %v", v, err)
			}
		}()
	}
	for reads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	if got := reads.Load(); got != 1 {
		t.Fatalf("%d reads for %d concurrent callers, want 1", got, n)
	}
}

// A read begun before a change is neither joined nor kept. Otherwise the poll
// that follows a suspend could be given the list from before it.
func TestSnapshotDoesNotKeepAReadFromBeforeAChange(t *testing.T) {
	_, _ = withFakeDocker(t)
	var reads atomic.Int64
	gate := make(chan struct{})
	s := NewSnapshot(SnapshotTTL, SnapshotWait, func() (int, error) {
		if reads.Add(1) == 1 {
			<-gate
			return 1, nil // read before the change
		}
		return 2, nil
	})
	first := make(chan int, 1)
	go func() { v, _ := s.Get(); first <- v }()
	for reads.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	noteStateChange()
	if v, _ := s.Get(); v != 2 {
		t.Fatalf("Get after the change = %d, want the read begun after it", v)
	}
	close(gate)
	<-first
	if v, _ := s.Get(); v != 2 {
		t.Fatalf("Get = %d: the older read replaced the newer", v)
	}
}

func TestSnapshotDoesNotKeepAFailure(t *testing.T) {
	_, _ = withFakeDocker(t)
	fail := true
	boom := errors.New("boom")
	s := NewSnapshot(SnapshotTTL, SnapshotWait, func() (int, error) {
		if fail {
			return 0, boom
		}
		return 1, nil
	})
	if _, err := s.Get(); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	fail = false
	if v, err := s.Get(); err != nil || v != 1 {
		t.Fatalf("Get = %d, %v: a failure was kept", v, err)
	}
}

// With an earlier answer to hand, nobody waits on a hung read for longer than
// SnapshotWait: this is what stands between a stuck docker and the dashboard.
func TestSnapshotServesThePreviousAnswerRatherThanHang(t *testing.T) {
	_, _ = withFakeDocker(t)
	var reads atomic.Int64
	gate := make(chan struct{})
	defer close(gate)
	s := NewSnapshot(SnapshotTTL, 20*time.Millisecond, func() (int, error) {
		if reads.Add(1) > 1 {
			<-gate
		}
		return 1, nil
	})
	if v, _ := s.Get(); v != 1 {
		t.Fatal(v)
	}
	noteStateChange() // out of date: the next read will hang
	done := make(chan int, 1)
	go func() { v, _ := s.Get(); done <- v }()
	select {
	case v := <-done:
		if v != 1 {
			t.Fatalf("Get = %d, want the previous answer", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hung on a read that will not finish")
	}
}

func TestSnapshotSurvivesAPanickingRead(t *testing.T) {
	_, _ = withFakeDocker(t)
	s := NewSnapshot(SnapshotTTL, SnapshotWait, func() (int, error) { panic("no") })
	if _, err := s.Get(); err == nil {
		t.Fatal("a panicking read returned no error")
	}
	s.read = func() (int, error) { return 1, nil }
	if v, err := s.Get(); err != nil || v != 1 {
		t.Fatalf("Get = %d, %v: the failed read stayed in flight", v, err)
	}
}

func TestForEachBoundedRunsEachOnce(t *testing.T) {
	var running, peak atomic.Int64
	seen := make([]atomic.Int64, 40)
	forEachBounded(len(seen), func(i int) {
		now := running.Add(1)
		for {
			p := peak.Load()
			if now <= p || peak.CompareAndSwap(p, now) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		running.Add(-1)
		seen[i].Add(1)
	})
	for i := range seen {
		if seen[i].Load() != 1 {
			t.Fatalf("index %d ran %d times", i, seen[i].Load())
		}
	}
	if peak.Load() > maxProbeFanOut {
		t.Fatalf("%d ran at once, the bound is %d", peak.Load(), maxProbeFanOut)
	}
}

// branchesWorld installs the fakes behind Branches: a pool of datasets and a
// count of what is asked about them.
func branchesWorld(t *testing.T, datasets ...string) (*fakeDocker, *atomic.Int64, func(time.Duration)) {
	t.Helper()
	d, advance := withFakeDocker(t)
	var counted atomic.Int64
	oldUsage, oldCount := branchUsages, countConnections
	branchUsages = func() ([]branchUsage, error) {
		var u []branchUsage
		for _, n := range datasets {
			u = append(u, branchUsage{Name: n, Used: "1M", Refer: "2M"})
		}
		return u, nil
	}
	countConnections = func(string, string) (int, error) { counted.Add(1); return 3, nil }
	t.Cleanup(func() { branchUsages, countConnections = oldUsage, oldCount })
	return d, &counted, advance
}

// One inspect however many branches there are, and an answer of the same shape
// the serial walk gave: a stopped branch has no port or count, and one with no
// container is absent.
func TestBranchesUsesOneInspect(t *testing.T) {
	d, counted, _ := branchesWorld(t, "main", "dev", "agent-x", "gone")
	d.set("pg-main", "running", "10.0.0.1")
	d.set("pg-dev", "exited", "")
	d.set("pg-agent-x", "running", "10.0.0.3")

	got, err := Branches()
	if err != nil {
		t.Fatal(err)
	}
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("%d inspects for 4 branches, want 1", n)
	}
	if n := counted.Load(); n != 2 {
		t.Fatalf("%d connection counts, want one per running branch", n)
	}
	want := []BranchInfo{
		{Name: "main", Primary: true, State: "running", Used: "1M", Refer: "2M", Connections: 3, Port: "5432"},
		{Name: "dev", State: "exited", Used: "1M", Refer: "2M"},
		{Name: "agent-x", Agent: true, State: "running", Used: "1M", Refer: "2M", Connections: 3, Port: "5432"},
		{Name: "gone", State: "absent", Used: "1M", Refer: "2M"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Branches =\n%+v\nwant\n%+v", got, want)
	}
}

// Callers filter and sort what they are given. One caller's doing that must
// not show up in another's list.
func TestBranchesSnapshotGivesEachCallerItsOwnSlice(t *testing.T) {
	d, _, _ := branchesWorld(t, "main")
	d.set("pg-main", "running", "10.0.0.1")
	noteStateChange() // the package-level snapshot, between tests
	a, err := BranchesSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	a[0].Name = "changed by a caller"
	b, _ := BranchesSnapshot()
	if b[0].Name != "main" {
		t.Fatalf("the shared list was changed through a caller's copy: %+v", b[0])
	}
}

// The measurement behind the change. 20 tabs on 2 branches for a minute: each
// tab used to poll /api/status and /api/branches every 3s, and each of those
// walked the branches. Now 10s polls of one shared snapshot. Run with -v.
func TestDashboardDockerCalls(t *testing.T) {
	d, counted, step := branchesWorld(t, "main", "dev")
	d.set("pg-main", "running", "10.0.0.1")
	d.set("pg-dev", "running", "10.0.0.2")
	noteStateChange()
	const clients, minute = 20, 60

	polls := 0
	var clock time.Duration
	for clock < minute*time.Second {
		var wg sync.WaitGroup
		wg.Add(clients * 2)
		for range clients * 2 { // status and branches read the same snapshot
			go func() {
				defer wg.Done()
				if _, err := BranchesSnapshot(); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		polls++
		step(10 * time.Second)
		clock += 10 * time.Second
	}
	inspects, conns := d.calls.Load(), counted.Load()
	// Per request before: an inspect and a psql exec per branch, serially.
	legacy := clients * (minute / 3) * 2 * (2 + 2)
	t.Logf("dashboard: %d tabs, 2 branches, 60s: %d docker inspects + %d connection counts over the network, was %d docker processes",
		clients, inspects, conns, legacy)
	if inspects > int64(polls)+1 {
		t.Fatalf("%d inspects over %d polls: not shared", inspects, polls)
	}
}
