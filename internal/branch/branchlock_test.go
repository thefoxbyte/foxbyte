// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// shortLockWait makes a lock wait give up quickly, for a test that waits on
// purpose.
func shortLockWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := branchLockWait
	branchLockWait = func() time.Duration { return d }
	t.Cleanup(func() { branchLockWait = old })
}

// stubTeardown stands in for docker and the storage driver in Delete.
func stubTeardown(t *testing.T, fn func(string) error) {
	t.Helper()
	old := teardownBranch
	teardownBranch = fn
	t.Cleanup(func() { teardownBranch = old })
}

// Two wakes that reach the lock at once — as two processes would, with no
// memory in common — start the branch once. The second finds it running.
func TestWakesOfOneBranchAreSerialized(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.set("pg-a", "exited", "")
	var mu sync.Mutex
	inside, most, resumes := 0, 0, 0
	resumeBranch = func(string) error {
		mu.Lock()
		inside++
		resumes++
		if inside > most {
			most = inside
		}
		mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		d.set("pg-a", "running", "10.0.0.1")
		noteStateChange()
		mu.Lock()
		inside--
		mu.Unlock()
		return nil
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Straight to the lock, past this process's single-flight.
			if addr, err := wakeLocked("a"); err != nil || addr != "10.0.0.1:5432" {
				t.Errorf("wakeLocked = %q, %v", addr, err)
			}
		}()
	}
	wg.Wait()
	if resumes != 1 || most != 1 {
		t.Fatalf("%d resumes, at most %d at once; want 1 and 1", resumes, most)
	}
}

// A burst of connections to a suspended branch in one process is one wake.
func TestABurstOfConnectionsIsOneWake(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.set("pg-b", "exited", "")
	var resumes atomic.Int64
	resumeBranch = func(string) error {
		resumes.Add(1)
		time.Sleep(30 * time.Millisecond)
		d.set("pg-b", "running", "10.0.0.2")
		noteStateChange()
		return nil
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := EnsureRunning("b"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := resumes.Load(); n != 1 {
		t.Fatalf("%d resumes for one burst, want 1", n)
	}
}

// A wake that arrives while the branch is being deleted waits, then finds the
// branch gone and says so: it does not start it again on what is left.
func TestAWakeDuringADeleteDoesNotBringItBack(t *testing.T) {
	d, _ := withFakeDocker(t)
	t.Setenv("FOX_DB", filepath.Join(t.TempDir(), "auth.db"))
	d.set("pg-c", "exited", "")
	var exists atomic.Bool
	exists.Store(true)
	branchExists = func(string) bool { return exists.Load() }
	inTeardown, release := make(chan struct{}), make(chan struct{})
	stubTeardown(t, func(string) error {
		d.remove("pg-c") // the container goes first, as removeContainer does
		close(inTeardown)
		<-release
		exists.Store(false)
		return nil
	})
	deleted := make(chan error, 1)
	go func() { deleted <- Delete("c") }()
	<-inTeardown

	woke := make(chan error, 1)
	go func() { _, err := EnsureRunning("c"); woke <- err }()
	select {
	case err := <-woke:
		t.Fatalf("the wake did not wait for the delete: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	err := <-woke
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("wake after delete = %v, want \"does not exist\"", err)
	}
}

// A wait for a branch held too long ends in ErrBranchBusy, naming what holds
// it, and does not hang.
func TestALockWaitEndsInBranchBusy(t *testing.T) {
	d, _ := withFakeDocker(t)
	d.set("pg-d", "exited", "")
	shortLockWait(t, 50*time.Millisecond)
	oldCheck := checkSuspendable
	t.Cleanup(func() { checkSuspendable = oldCheck })
	checkSuspendable = func(string) error { return nil }
	unlock, err := lockBranch("d", "restored")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	start := time.Now()
	for name, op := range map[string]func() error{
		"delete":  func() error { return Delete("d") },
		"wake":    func() error { _, err := EnsureRunning("d"); return err },
		"suspend": func() error { return Suspend("d") },
	} {
		err := op()
		if !errors.Is(err, ErrBranchBusy) || !strings.Contains(err.Error(), "restored") {
			t.Errorf("%s while held: %v, want ErrBranchBusy naming the restore", name, err)
		}
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("three waits of 50ms took %s", time.Since(start))
	}
}

func TestReleasingTheLockLetsTheNextIn(t *testing.T) {
	unlock, err := lockBranch("e", "deleted")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		u, err := lockBranch("e", "woken")
		if err == nil {
			u()
		}
		got <- err
	}()
	time.Sleep(20 * time.Millisecond)
	unlock()
	unlock() // twice is harmless
	if err := <-got; err != nil {
		t.Fatal(err)
	}
}

// The idle reaper's suspend asks again under the lock, and leaves a branch a
// client was just routed to, or one with a connection now.
func TestSuspendIdleRechecksUnderTheLock(t *testing.T) {
	oldCheck, oldStop, oldProbe := checkSuspendable, stopBranch, probeActive
	t.Cleanup(func() { checkSuspendable, stopBranch, probeActive = oldCheck, oldStop, oldProbe })
	checkSuspendable = func(string) error { return nil }
	stops := 0
	stopBranch = func(string) error { stops++; return nil }
	conns, probeErr := 0, error(nil)
	probeActive = func(string) (int, error) { return conns, probeErr }

	noteRouted("f")
	if err := SuspendIdle("f"); !errors.Is(err, ErrBranchInUse) {
		t.Errorf("just routed: %v, want ErrBranchInUse", err)
	}
	routed.mu.Lock()
	routed.at["f"] = time.Now().Add(-2 * suspendGrace)
	routed.mu.Unlock()
	conns = 1
	if err := SuspendIdle("f"); !errors.Is(err, ErrBranchInUse) {
		t.Errorf("a connection open: %v, want ErrBranchInUse", err)
	}
	conns, probeErr = 0, errors.New("docker did not answer")
	if err := SuspendIdle("f"); err == nil {
		t.Error("a failed probe suspended the branch")
	}
	if stops != 0 {
		t.Fatalf("%d stops of a branch in use", stops)
	}
	probeErr = nil
	if err := SuspendIdle("f"); err != nil || stops != 1 {
		t.Errorf("idle: %v, %d stops; want nil, 1", err, stops)
	}
	// Suspend, which a person asks for, does not ask about use.
	noteRouted("f")
	if err := Suspend("f"); err != nil || stops != 2 {
		t.Errorf("Suspend: %v, %d stops; want nil, 2", err, stops)
	}
}

// withKeyStore points the engine at an account store of the test's own and
// returns it with one account.
func withKeyStore(t *testing.T) (*auth.Store, auth.User) {
	t.Helper()
	t.Setenv("FOX_DB", filepath.Join(t.TempDir(), "auth.db"))
	st, err := auth.OpenFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	u, err := st.CreateUser("owner@x.com", "password1")
	if err != nil {
		t.Fatal(err)
	}
	return st, u
}

func keyWorks(st *auth.Store, key string) bool { _, _, ok := st.VerifyKey(key); return ok }

// Every way of deleting a branch ends in Delete — the console's DELETE, `fox
// branch delete`, the Agent API's and MCP's DeleteAgentBranch — and Delete
// revokes the branch's scoped keys and logs it.
func TestEveryDeleteRevokesTheBranchsKeys(t *testing.T) {
	withFakeDocker(t)
	st, u := withKeyStore(t)
	stubTeardown(t, func(string) error { return nil })
	branchExists = func(string) bool { return false }

	plain, _, _ := st.CreateScopedAPIKey(u.ID, "a person's branch", "dev")
	if err := Delete("dev"); err != nil {
		t.Fatal(err)
	}
	if keyWorks(st, plain) {
		t.Error("Delete left the branch's scoped key working")
	}

	_ = st.SetBranchOwner("agent-a1", u.ID)
	agent, _, _ := st.CreateScopedAPIKey(u.ID, "agent agent-a1", "agent-a1")
	if err := DeleteAgentBranch("a1"); err != nil {
		t.Fatal(err)
	}
	if keyWorks(st, agent) {
		t.Error("DeleteAgentBranch left the agent's key working")
	}
	if _, ok := st.BranchOwner("agent-a1"); ok {
		t.Error("the deleted agent branch kept its owner")
	}
	evs, _ := st.SecurityEventsOfKind(auth.EvKeyRevoked)
	if len(evs) != 2 {
		t.Errorf("%d revocations in the security log, want 2: %+v", len(evs), evs)
	}
}

// A delete that cannot get the lock revokes nothing and keeps the owner: the
// branch is still there.
func TestABusyDeleteKeepsTheKeys(t *testing.T) {
	withFakeDocker(t)
	st, u := withKeyStore(t)
	shortLockWait(t, 30*time.Millisecond)
	_ = st.SetBranchOwner("agent-a2", u.ID)
	key, _, _ := st.CreateScopedAPIKey(u.ID, "agent agent-a2", "agent-a2")
	unlock, _ := lockBranch("agent-a2", "woken")
	defer unlock()
	if err := DeleteAgentBranch("a2"); !errors.Is(err, ErrBranchBusy) {
		t.Fatalf("DeleteAgentBranch = %v, want ErrBranchBusy", err)
	}
	if !keyWorks(st, key) {
		t.Error("a delete that never ran revoked the key")
	}
	if _, ok := st.BranchOwner("agent-a2"); !ok {
		t.Error("a delete that never ran dropped the owner")
	}
}

// Making a branch under a name revokes keys left scoped to that name, so a
// missed revocation cannot hand the new branch to the old key; asking to make
// a branch that exists already revokes nothing.
func TestCreatingANameRevokesItsOldKeys(t *testing.T) {
	d, _ := withFakeDocker(t)
	st, u := withKeyStore(t)
	oldBuild := buildBranch
	t.Cleanup(func() { buildBranch = oldBuild })
	built := 0
	buildBranch = func(string, string) error { built++; return nil }

	branchExists = func(n string) bool { return n == "main" }
	stale, _, _ := st.CreateScopedAPIKey(u.ID, "agent agent-old", "agent-old")
	if err := Create("agent-old", ""); err != nil {
		t.Fatal(err)
	}
	if keyWorks(st, stale) || built != 1 {
		t.Errorf("after Create: stale key works=%v, built=%d", keyWorks(st, stale), built)
	}

	branchExists = func(string) bool { return true }
	live, _, _ := st.CreateScopedAPIKey(u.ID, "agent agent-live", "agent-live")
	if err := Create("agent-live", ""); err == nil {
		t.Fatal("made a branch that exists")
	}
	if !keyWorks(st, live) {
		t.Error("a refused create revoked the existing branch's key")
	}

	// A container of the name, with no data, refuses too, and revokes nothing.
	branchExists = func(n string) bool { return n == "main" }
	d.set("pg-agent-live", "exited", "")
	if err := Create("agent-live", ""); !errors.Is(err, ErrBranchExists) {
		t.Fatalf("Create over a container = %v, want ErrBranchExists", err)
	}
	if !keyWorks(st, live) {
		t.Error("a create refused for a container revoked the key")
	}
}

// A reset is the same branch started over: its keys stay.
func TestResetKeepsTheKeys(t *testing.T) {
	withFakeDocker(t)
	st, u := withKeyStore(t)
	var exists atomic.Bool
	exists.Store(true)
	branchExists = func(n string) bool { return n == "main" || exists.Load() }
	stubTeardown(t, func(string) error { exists.Store(false); return nil })
	oldBuild := buildBranch
	t.Cleanup(func() { buildBranch = oldBuild })
	buildBranch = func(string, string) error { exists.Store(true); return nil }

	key, _, _ := st.CreateScopedAPIKey(u.ID, "agent agent-r", "agent-r")
	if err := Reset("agent-r", ""); err != nil {
		t.Fatal(err)
	}
	if !keyWorks(st, key) {
		t.Error("Reset revoked the agent's key")
	}
}
