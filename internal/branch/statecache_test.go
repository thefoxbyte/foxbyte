// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDocker stands in for inspectContainers: containers it knows answer with
// their state and IP, anything else the way docker says it has no such thing.
type fakeDocker struct {
	mu    sync.Mutex
	state map[string]containerFacts
	calls atomic.Int64
	fail  error // when set, docker is not answering
	gate  chan struct{}
}

func (d *fakeDocker) inspect(_ time.Duration, conts []string) (string, error) {
	d.calls.Add(1)
	if d.gate != nil {
		<-d.gate
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail != nil {
		return "", d.fail
	}
	var lines []string
	var missing error
	for _, c := range conts {
		f, ok := d.state[c]
		if !ok {
			missing = fmt.Errorf("exit status 1: Error: No such object: %s", c)
			continue
		}
		lines = append(lines, fmt.Sprintf("/%s|%s|%s", c, f.state, f.ip))
	}
	return strings.Join(lines, "\n"), missing
}

func (d *fakeDocker) set(cont, state, ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state[cont] = containerFacts{state: state, ip: ip}
}

func (d *fakeDocker) remove(cont string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.state, cont)
}

// withFakeDocker installs a fake docker and a clean memory, and hands back the
// clock so a test can pass the TTL without sleeping.
func withFakeDocker(t *testing.T) (*fakeDocker, func(time.Duration)) {
	t.Helper()
	d := &fakeDocker{state: map[string]containerFacts{}}
	oldInspect, oldNow := inspectContainers, stateNow
	oldExists, oldRecreate, oldResume := branchExists, recreateBranch, resumeBranch
	now := time.Unix(1_000_000, 0)
	var clock sync.Mutex
	inspectContainers = d.inspect
	stateNow = func() time.Time { clock.Lock(); defer clock.Unlock(); return now }
	branchExists = func(string) bool { return true }
	recreateBranch = func(n string) error { t.Fatalf("recreated %q unexpectedly", n); return nil }
	resumeBranch = func(n string) error { t.Fatalf("resumed %q unexpectedly", n); return nil }
	noteStateChange()
	t.Cleanup(func() {
		inspectContainers, stateNow = oldInspect, oldNow
		branchExists, recreateBranch, resumeBranch = oldExists, oldRecreate, oldResume
		noteStateChange()
	})
	return d, func(by time.Duration) { clock.Lock(); defer clock.Unlock(); now = now.Add(by) }
}

func TestParseFacts(t *testing.T) {
	got := parseFacts("/pg-a|running|172.18.0.5\n/pg-b|exited|\n\nnot a line")
	if got["pg-a"] != (containerFacts{"running", "172.18.0.5"}) {
		t.Errorf("pg-a = %+v", got["pg-a"])
	}
	if got["pg-b"] != (containerFacts{"exited", ""}) {
		t.Errorf("pg-b = %+v", got["pg-b"])
	}
	if len(got) != 2 {
		t.Errorf("%d containers parsed, want 2: %v", len(got), got)
	}
}

// Within the TTL a connection costs no docker call at all; past it, one.
func TestARunningBranchIsKeptForTheTTL(t *testing.T) {
	d, advance := withFakeDocker(t)
	d.set("pg-a", "running", "10.0.0.1")
	for range 5 {
		addr, err := EnsureRunning("a")
		if err != nil || addr != "10.0.0.1:5432" {
			t.Fatalf("EnsureRunning = %q, %v", addr, err)
		}
	}
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("%d docker calls for 5 connections, want 1", n)
	}
	advance(stateCacheTTL + time.Millisecond)
	if _, err := EnsureRunning("a"); err != nil {
		t.Fatal(err)
	}
	if n := d.calls.Load(); n != 2 {
		t.Fatalf("%d docker calls after the TTL, want 2", n)
	}
}

// Anything the engine does to a container is seen at once, without waiting for
// the TTL.
func TestAStateChangeInvalidates(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.set("pg-a", "running", "10.0.0.1")
	if _, err := EnsureRunning("a"); err != nil {
		t.Fatal(err)
	}
	d.set("pg-a", "running", "10.0.0.9")
	noteIfChange("docker", []string{"start", "pg-a"})
	addr, err := EnsureRunning("a")
	if err != nil || addr != "10.0.0.9:5432" {
		t.Fatalf("EnsureRunning = %q, %v, want the new address", addr, err)
	}
}

// The commands that change what is running, recognised where commands are run,
// so that none needs remembering at its call site. A tool in a throwaway
// container changes nothing anybody is routed to, and reads certainly do not.
func TestChangesContainers(t *testing.T) {
	yes := [][]string{{"docker", "stop", "x"}, {"docker", "start", "x"}, {"docker", "restart", "x"}, {"docker", "kill", "-s", "KILL", "x"},
		{"docker", "rm", "-f", "-v", "x"}, {"docker", "run", "-d", "--name", "x", "img"}, {"docker", "rename", "x", "y"}}
	no := [][]string{{"docker", "run", "--rm", "img"}, {"docker", "inspect", "x"}, {"docker", "exec", "x", "psql"}, {"docker", "ps"},
		{"docker", "network", "create", "n"}, {"docker"}, {"zfs", "stop"}}
	for _, c := range yes {
		if !changesContainers(c[0], c[1:]) {
			t.Errorf("%v should invalidate", c)
		}
	}
	for _, c := range no {
		if changesContainers(c[0], c[1:]) {
			t.Errorf("%v should not invalidate", c)
		}
	}
}

// A hundred connections arriving together, with nothing remembered, share one
// inspect.
func TestConcurrentCallersShareOneInspect(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.set("pg-a", "running", "10.0.0.1")
	d.gate = make(chan struct{})
	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for range n {
		go func() {
			defer wg.Done()
			if addr, err := EnsureRunning("a"); err != nil || addr != "10.0.0.1:5432" {
				errs <- fmt.Errorf("%q, %v", addr, err)
			}
		}()
	}
	// Every caller queued, or as many as will: then let the inspect finish.
	for d.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(d.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := d.calls.Load(); got != 1 {
		t.Fatalf("%d inspects for %d concurrent connections, want 1", got, n)
	}
}

// An inspect that began before a state change read the world from before it,
// so nobody joins it afterwards and its answer is not kept.
func TestAnInspectFromBeforeAChangeIsNotKept(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.set("pg-a", "running", "10.0.0.1")
	d.gate = make(chan struct{})
	first := make(chan string, 1)
	go func() {
		a, _ := EnsureRunning("a")
		first <- a
	}()
	for d.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	// The change lands while that inspect is out.
	d.set("pg-a", "running", "10.0.0.9")
	noteStateChange()
	close(d.gate)
	<-first
	d.gate = nil
	addr, err := EnsureRunning("a")
	if err != nil || addr != "10.0.0.9:5432" {
		t.Fatalf("EnsureRunning = %q, %v: kept an answer from before the change", addr, err)
	}
}

// Another process stopped the branch: the memory still says running and the
// caller is given the old address, which fails to dial. ForgetBackends sends it
// back through the real path, which wakes the branch.
func TestAForgottenBackendIsWokenThroughTheRealPath(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.set("pg-a", "running", "10.0.0.1")
	if _, err := EnsureRunning("a"); err != nil {
		t.Fatal(err)
	}
	d.set("pg-a", "exited", "") // another process's suspend, unseen here
	addr, err := EnsureRunning("a")
	if err != nil || addr != "10.0.0.1:5432" {
		t.Fatalf("within the TTL: %q, %v, want the remembered address", addr, err)
	}
	woken := 0
	resumeBranch = func(string) error { woken++; d.set("pg-a", "running", "10.0.0.2"); noteStateChange(); return nil }
	ForgetBackends()
	addr, err = EnsureRunning("a")
	if err != nil || addr != "10.0.0.2:5432" || woken != 1 {
		t.Fatalf("after forgetting: %q, %v, woken %d", addr, err, woken)
	}
}

// Nothing but a fresh answer from docker can recreate a container, whose first
// step is `docker rm -f`.
func TestAbsentIsOnlyBelievedFromAFreshAnswer(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.set("pg-a", "running", "10.0.0.1")
	if _, err := EnsureRunning("a"); err != nil {
		t.Fatal(err)
	}
	// Absent never goes into the memory: the only way to the destructive path
	// is an inspect made during this very call.
	d.remove("pg-a")
	ForgetBackends()
	before := d.calls.Load()
	recreated := 0
	recreateBranch = func(string) error { recreated++; d.set("pg-a", "running", "10.0.0.3"); noteStateChange(); return nil }
	if addr, err := EnsureRunning("a"); err != nil || addr != "10.0.0.3:5432" || recreated != 1 {
		t.Fatalf("EnsureRunning = %q, %v, recreated %d", addr, err, recreated)
	}
	if n := d.calls.Load() - before; n < 2 {
		t.Fatalf("recreated on %d docker calls: the decision needs its own", n)
	}
	containers.mu.Lock()
	for cont, e := range containers.entries {
		if !e.facts.serving() {
			t.Errorf("%s remembered as %q", cont, e.facts.state)
		}
	}
	containers.mu.Unlock()
}

// A dockerd that has stopped answering looks like every container vanishing to
// anything that treats an error as "absent", and the next step of that would be
// removing them. It is an error, and nothing is touched.
func TestDockerNotAnsweringIsNeverAbsent(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.fail = errors.New("docker did not finish within 5s and was stopped")
	// withFakeDocker fails the test if either way up is taken.
	_, err := EnsureRunning("a")
	if !errors.Is(err, ErrStateUnknown) {
		t.Fatalf("EnsureRunning = %v, want ErrStateUnknown", err)
	}
	if _, err := BackendAddr("a"); !errors.Is(err, ErrStateUnknown) {
		t.Fatalf("BackendAddr = %v, want ErrStateUnknown", err)
	}
}

// Docker saying there is no such container, by contrast, is an answer.
func TestNoSuchContainerIsAbsent(t *testing.T) {
	d, _ := withFakeDocker(t)
	f, err := probeContainer("pg-gone")
	if err != nil || f.state != "absent" {
		t.Fatalf("probeContainer = %+v, %v", f, err)
	}
	if d.calls.Load() != 1 {
		t.Fatalf("%d calls", d.calls.Load())
	}
}

// A branch that does not exist is still reported as one.
func TestAMissingBranchSaysSo(t *testing.T) {
	_, _ = withFakeDocker(t)
	branchExists = func(string) bool { return false }
	if _, err := EnsureRunning("a"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("EnsureRunning = %v", err)
	}
}

// A failover changes which container "main" is. Read each time, so a promotion
// done by another process needs no invalidation here.
func TestMainFollowsThePrimaryContainer(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.set("pg-main", "running", "10.0.0.1")
	d.set("pg-standby", "running", "10.0.0.2")
	if addr, err := BackendAddr("main"); err != nil || addr != "10.0.0.1:5432" {
		t.Fatalf("BackendAddr = %q, %v", addr, err)
	}
	if err := setPrimary("standby"); err != nil {
		t.Fatal(err)
	}
	defer setPrimary("main")
	if addr, err := BackendAddr("main"); err != nil || addr != "10.0.0.2:5432" {
		t.Fatalf("after failover BackendAddr = %q, %v", addr, err)
	}
}

// The measurement behind the change: docker processes for 100 connections to a
// running branch, before and after. Run with -v to read the numbers.
func TestConnectPathDockerCalls(t *testing.T) {
	d, advance := withFakeDocker(t)
	d.set("pg-a", "running", "10.0.0.1")
	const connections = 100
	for i := range connections {
		if _, err := EnsureRunning("a"); err != nil {
			t.Fatal(err)
		}
		if i%10 == 9 { // ten connections a second
			advance(time.Second)
		}
	}
	got := d.calls.Load()
	legacy := int64(connections * 3) // state in the proxy, state again, then the IP
	t.Logf("connect path: %d connections at 10/s: %d docker calls, was %d", connections, got, legacy)
	if got > connections/10 {
		t.Fatalf("%d docker calls", got)
	}
}
