// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// haWorld is a docker for the failover code: two containers, what each call
// did, in order, and switches for the ways a real one misbehaves.
type haWorld struct {
	mu    sync.Mutex
	calls []string
	state map[string]string // container -> docker state
	rec   map[string]bool   // container -> in recovery

	stopFails    bool  // docker stop errors and the container keeps running
	dockerSilent bool  // inspect does not answer
	promoteErr   error // pg_promote fails
	recoveryErr  error // pg_is_in_recovery cannot be asked

	// what the promotion saw on disk at the moment it ran
	promotingAtPromote, primaryAtPromote string
}

func (w *haWorld) log(s string) {
	w.mu.Lock()
	w.calls = append(w.calls, s)
	w.mu.Unlock()
}

func (w *haWorld) seq() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Join(w.calls, ", ")
}

// install puts the fake in place, with a short fence wait, and a clean state
// directory for the markers.
func (w *haWorld) install(t *testing.T) {
	t.Helper()
	clearHAState(t)
	t.Cleanup(func() { clearHAState(t) })
	saved, wait, poll := haDocker, fenceWait, fencePoll
	t.Cleanup(func() { haDocker, fenceWait, fencePoll = saved, wait, poll })
	fenceWait, fencePoll = 60*time.Millisecond, 5*time.Millisecond

	haDocker.stop = func(c string) error {
		w.log("stop " + c)
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.stopFails {
			return errors.New("docker stop: timed out")
		}
		w.state[c] = "exited"
		return nil
	}
	haDocker.start = func(c string) error {
		w.log("start " + c)
		w.mu.Lock()
		w.state[c] = "running"
		w.mu.Unlock()
		return nil
	}
	haDocker.state = func(c string) (string, error) {
		w.log("inspect " + c)
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.dockerSilent {
			return "", errors.New("docker did not answer within 5s")
		}
		if s, ok := w.state[c]; ok {
			return s, nil
		}
		return "absent", nil
	}
	haDocker.promote = func(c string) error {
		w.log("promote " + c)
		b, _ := os.ReadFile(promotingFile())
		w.promotingAtPromote, w.primaryAtPromote = string(b), PrimaryContainer()
		if w.promoteErr != nil {
			return w.promoteErr
		}
		w.mu.Lock()
		w.rec[c] = false
		w.mu.Unlock()
		return nil
	}
	haDocker.inRecovery = func(c string) (bool, error) {
		w.log("in-recovery? " + c)
		if w.recoveryErr != nil {
			return false, w.recoveryErr
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.rec[c], nil
	}
}

func newHAWorld() *haWorld {
	return &haWorld{
		state: map[string]string{"pg-main": "running", "pg-standby": "running"},
		rec:   map[string]bool{"pg-main": false, "pg-standby": true},
	}
}

func clearHAState(t *testing.T) {
	for _, p := range []string{primaryFile(), promotingFile(), unfencedFile(), joinedPath()} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

// The order is the fix: the old primary is stopped, seen stopped, and only
// then is the standby promoted. The gateway's marker names the standby only
// after the promotion, and the promotion is recorded before it starts.
func TestFailoverFencesBeforePromoting(t *testing.T) {
	w := newHAWorld()
	w.install(t)
	if _, err := promoteFenced("pg-main", failoverAsk{}); err != nil {
		t.Fatal(err)
	}
	want := "inspect pg-main, stop pg-main, inspect pg-main, promote pg-standby"
	if got := w.seq(); got != want {
		t.Errorf("order:\n got %s\nwant %s", got, want)
	}
	if w.primaryAtPromote != "pg-main" {
		t.Errorf("'main' was routed to %s before the promotion finished", w.primaryAtPromote)
	}
	if w.promotingAtPromote != "standby" {
		t.Errorf("the promotion was not recorded before it ran (%q)", w.promotingAtPromote)
	}
	if got := PrimaryContainer(); got != "pg-standby" {
		t.Errorf("after the failover the primary is %s", got)
	}
	if _, err := os.Stat(promotingFile()); !os.IsNotExist(err) {
		t.Error("the in-progress record outlived a finished promotion")
	}
}

// An old primary that is already down (killed, crashed) needs no stop, and is
// still checked before anything is promoted.
func TestFailoverOverADeadPrimary(t *testing.T) {
	w := newHAWorld()
	w.state["pg-main"] = "exited"
	w.install(t)
	if _, err := promoteFenced("pg-main", failoverAsk{}); err != nil {
		t.Fatal(err)
	}
	if got := w.seq(); got != "inspect pg-main, promote pg-standby" {
		t.Errorf("order: %s", got)
	}
}

// A paused container still holds its sessions: it is not stopped.
func TestStoppedState(t *testing.T) {
	for st, want := range map[string]bool{"exited": true, "dead": true, "created": true, "absent": true,
		"running": false, "restarting": false, "paused": false, "removing": false, "": false} {
		if stoppedState(st) != want {
			t.Errorf("stoppedState(%q) = %v", st, !want)
		}
	}
}

// When the stop cannot be confirmed, nothing is promoted and the refusal says
// what --force would risk.
func TestFailoverRefusedWhenStopUnconfirmed(t *testing.T) {
	for name, set := range map[string]func(*haWorld){
		"docker stop fails":    func(w *haWorld) { w.stopFails = true },
		"docker never answers": func(w *haWorld) { w.dockerSilent = true },
	} {
		t.Run(name, func(t *testing.T) {
			w := newHAWorld()
			set(w)
			w.install(t)
			_, err := promoteFenced("pg-main", failoverAsk{})
			if err == nil {
				t.Fatal("promoted over an old primary that may still be running")
			}
			for _, s := range []string{"refusing to promote", "could not be confirmed stopped", "--force", "lost"} {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("the refusal does not say %q:\n%v", s, err)
				}
			}
			if strings.Contains(w.seq(), "promote") {
				t.Errorf("promoted anyway: %s", w.seq())
			}
			if got := PrimaryContainer(); got != "pg-main" {
				t.Errorf("the marker moved to %s", got)
			}
			// The watcher never forces.
			if _, err := promoteFenced("pg-main", failoverAsk{force: true, unattended: true}); err == nil {
				t.Error("an unattended failover forced its way past the fence")
			}
		})
	}
}

// --force promotes over an unconfirmed stop, and it is recorded.
func TestFailoverForcedPastAnUnconfirmedStop(t *testing.T) {
	w := newHAWorld()
	w.stopFails = true
	w.install(t)
	if _, err := promoteFenced("pg-main", failoverAsk{force: true}); err != nil {
		t.Fatal(err)
	}
	if PrimaryContainer() != "pg-standby" {
		t.Error("--force did not promote")
	}
	if b, err := os.ReadFile(unfencedFile()); err != nil || !strings.Contains(string(b), "--force") {
		t.Errorf("the unfenced promotion was not recorded: %q %v", b, err)
	}
}

// A promotion that fails with the standby still a standby puts the old
// primary back. One whose outcome is unknown starts nothing, and leaves the
// record for `fox up` to settle.
func TestFailoverPromotionFails(t *testing.T) {
	w := newHAWorld()
	w.promoteErr = errors.New("psql: connection refused")
	w.install(t)
	_, err := promoteFenced("pg-main", failoverAsk{})
	if err == nil || errors.Is(err, errPromotionUnknown) {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasSuffix(w.seq(), "start pg-main") || PrimaryContainer() != "pg-main" {
		t.Errorf("the old primary was not put back: %s", w.seq())
	}
	if _, err := os.Stat(promotingFile()); !os.IsNotExist(err) {
		t.Error("a promotion known not to have happened left its record")
	}

	w = newHAWorld()
	w.promoteErr = errors.New("timed out")
	w.recoveryErr = errors.New("no answer")
	w.install(t)
	_, err = promoteFenced("pg-main", failoverAsk{})
	if !errors.Is(err, errPromotionUnknown) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(w.seq(), "start pg-main") {
		t.Errorf("started the old primary beside a standby that may be promoted: %s", w.seq())
	}
	if b, _ := os.ReadFile(promotingFile()); string(b) != "standby" {
		t.Errorf("the in-progress record = %q", b)
	}
}

// A standby of a primary on another machine: an unattended promotion needs
// the witness and --accept-unfenced, and one that goes ahead is recorded as
// not fenced.
func TestRemoteFailoverIsRecordedUnfenced(t *testing.T) {
	w := newHAWorld()
	w.install(t)
	// Port 1 on loopback: nothing answers, so the remote primary looks down.
	if err := writeStateAtomic(joinedPath(), []byte(`{"address":"127.0.0.1","port":1,"role":"db_replica"}`)); err != nil {
		t.Fatal(err)
	}
	_, err := promoteFenced("pg-main", failoverAsk{unattended: true, witnessAgreed: true})
	if err == nil || !strings.Contains(err.Error(), "--accept-unfenced") {
		t.Fatalf("an unattended promotion went ahead without --accept-unfenced: %v", err)
	}
	if w.seq() != "" {
		t.Errorf("touched docker before refusing: %s", w.seq())
	}
	unfenced, err := promoteFenced("pg-main", failoverAsk{unattended: true, witnessAgreed: true, acceptUnfenced: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unfenced, "not confirmed") {
		t.Errorf("unfenced = %q", unfenced)
	}
	if b, err := os.ReadFile(unfencedFile()); err != nil || !strings.Contains(string(b), "127.0.0.1:1") {
		t.Errorf("not recorded: %q %v", b, err)
	}
	if PrimaryContainer() != "pg-standby" {
		t.Error("not promoted")
	}
}

// A crash between pg_promote and the marker: the marker still says main, but
// the standby is a primary. `fox up` must not start main beside it.
func TestStartAfterACrashMidFailover(t *testing.T) {
	w := newHAWorld()
	w.state["pg-main"] = "exited"
	w.rec["pg-standby"] = false // it was promoted
	w.install(t)
	if err := writeStateAtomic(promotingFile(), []byte("standby")); err != nil {
		t.Fatal(err)
	}
	if err := settlePromotion(); err != nil {
		t.Fatal(err)
	}
	if PrimaryContainer() != "pg-standby" {
		t.Fatalf("the promoted standby is not recorded as primary (%s)", PrimaryContainer())
	}
	if _, err := os.Stat(promotingFile()); !os.IsNotExist(err) {
		t.Error("the record was not cleared")
	}
	// Never promoted: the marker stands and main is the primary.
	w = newHAWorld()
	w.state["pg-main"] = "exited"
	w.install(t)
	_ = writeStateAtomic(promotingFile(), []byte("standby"))
	if err := settlePromotion(); err != nil {
		t.Fatal(err)
	}
	if PrimaryContainer() != "pg-main" {
		t.Error("a promotion that never happened moved the marker")
	}
	// Cannot tell: refuse to start anything.
	w = newHAWorld()
	w.recoveryErr = errors.New("no answer")
	w.install(t)
	_ = writeStateAtomic(promotingFile(), []byte("standby"))
	if err := settlePromotion(); err == nil || !strings.Contains(err.Error(), "cannot be told") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(promotingFile()); string(b) != "standby" {
		t.Error("the record was dropped without an answer")
	}
}

// With the marker saying the standby is primary, a running old main is
// stopped before the standby serves, and failing that, `fox up` stops.
func TestStartWithTheStandbyPrimary(t *testing.T) {
	w := newHAWorld() // main running: started by hand, or by something else
	w.install(t)
	if err := setPrimary("standby"); err != nil {
		t.Fatal(err)
	}
	if err := stepDownGuard(); err != nil {
		t.Fatal(err)
	}
	if w.state["pg-main"] != "exited" || strings.Contains(w.seq(), "start pg-main") {
		t.Errorf("the old main was not kept down: %s", w.seq())
	}
	w = newHAWorld()
	w.stopFails = true
	w.install(t)
	_ = setPrimary("standby")
	if err := stepDownGuard(); err == nil {
		t.Error("a running old main beside the promoted standby was let through")
	}
}

// The marker is replaced whole: a failure part way leaves the old one, and no
// temporary file behind.
func TestWriteStateAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "primary")
	if err := writeStateAtomic(p, []byte("main")); err != nil {
		t.Fatal(err)
	}
	if err := writeStateAtomic(p, []byte("standby")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "standby" {
		t.Fatalf("got %q", b)
	}
	saved := syncFile
	t.Cleanup(func() { syncFile = saved })
	syncFile = func(*os.File) error { return errors.New("disk full") }
	if err := writeStateAtomic(p, []byte("main")); err == nil {
		t.Fatal("a failed flush was reported as written")
	}
	if b, _ := os.ReadFile(p); string(b) != "standby" {
		t.Errorf("a failed write changed the marker to %q", b)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("left behind: %v", names)
	}
}

// Failover and failback hold both branches' locks.
func TestLockHAHoldsBothBranches(t *testing.T) {
	saved := branchLockWait
	t.Cleanup(func() { branchLockWait = saved })
	branchLockWait = func() time.Duration { return 50 * time.Millisecond }
	unlock, err := lockHA("failed over")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"main", "standby"} {
		if _, err := lockBranch(b, "woken"); !errors.Is(err, ErrBranchBusy) {
			t.Errorf("%s was not held during a failover: %v", b, err)
		}
	}
	unlock()
	u, err := lockBranch("standby", "woken")
	if err != nil {
		t.Fatalf("released, but: %v", err)
	}
	u()
}
