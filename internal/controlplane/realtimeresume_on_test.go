//go:build enterprise

// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"testing"

	"github.com/jackc/pglogrepl"
	"github.com/thefoxbyte/foxbyte/enterprise/realtime"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// What the stream route does with a ?since= before it opens anything.
//
// The cases that do not start a decoder are read here; the one that does is in
// the realtime integration suite, where there is a log to decode. What matters
// at this level is that three of the four answers are not "attach", because
// until this existed they all were.
func TestResumeForAnswers(t *testing.T) {
	oldRun, oldWindow := ensureRunning, readResumeWindow
	t.Cleanup(func() {
		ensureRunning, readResumeWindow = oldRun, oldWindow
		clearHubs()
	})
	ensureRunning = func(string) (string, error) { return "addr", nil }

	t.Run("a position ahead of the branch is refused before anything opens", func(t *testing.T) {
		clearHubs()
		readResumeWindow = func(string, string) (branch.ResumeWindow, error) {
			return branch.ResumeWindow{Confirmed: "0/1000", HaveSlot: true, WALEnd: "0/2000"}, nil
		}
		h, v, err := resumeFor("main", mustLSN(t, "0/9000"))
		if err != nil || v != realtime.ResumeAhead || h != nil {
			t.Fatalf("got (%v, %v, %v), want ResumeAhead and no hub", h, v, err)
		}
		// And nothing was started: a refusal must not leave a decoder holding
		// a slot for a subscriber that never attached.
		if liveHub("main") != nil {
			t.Error("a refused subscribe started a decoder")
		}
	})

	t.Run("a position the slot was read past is told to refetch", func(t *testing.T) {
		clearHubs()
		readResumeWindow = func(string, string) (branch.ResumeWindow, error) {
			return branch.ResumeWindow{Confirmed: "0/5000", HaveSlot: true, WALEnd: "0/9000"}, nil
		}
		_, v, err := resumeFor("main", mustLSN(t, "0/1000"))
		if err != nil || v != realtime.ResumeExpired {
			t.Fatalf("got (%v, %v), want ResumeExpired", v, err)
		}
		if liveHub("main") != nil {
			t.Error("a refetch answer started a decoder")
		}
	})

	t.Run("a stream in progress serves a position nothing has passed", func(t *testing.T) {
		clearHubs()
		hub := realtime.NewHub()
		hub.StartedAt(mustLSN(t, "0/4000"))
		putHub("main", hub)
		// At or above the floor: attach, and to the hub that is already there.
		got, v, err := resumeFor("main", mustLSN(t, "0/4000"))
		if err != nil || v != realtime.ResumeLive || got != hub {
			t.Fatalf("got (%v, %v, %v), want the running hub and ResumeLive", got, v, err)
		}
		// Below it: the changes in between went to whoever was attached, so
		// there is nothing to serve.
		_, v, err = resumeFor("main", mustLSN(t, "0/3000"))
		if err != nil || v != realtime.ResumeExpired {
			t.Fatalf("got (%v, %v), want ResumeExpired", v, err)
		}
	})

	t.Run("a position is checked against the branch even with a stream running", func(t *testing.T) {
		// The hub decides what it can serve, but only the branch knows where
		// its log ends, and a position beyond it is refused on every path
		// rather than depending on whether somebody else happened to be
		// subscribed at the time. One reading per resume is the price.
		clearHubs()
		hub := realtime.NewHub()
		hub.StartedAt(mustLSN(t, "0/4000"))
		putHub("main", hub)
		asked := 0
		readResumeWindow = func(string, string) (branch.ResumeWindow, error) {
			asked++
			return branch.ResumeWindow{Confirmed: "0/3000", HaveSlot: true, WALEnd: "0/6000"}, nil
		}
		// Within the log and at or above the floor: attach.
		got, v, err := resumeFor("main", mustLSN(t, "0/5000"))
		if err != nil || v != realtime.ResumeLive || got != hub {
			t.Fatalf("got (%v, %v, %v), want the running hub and ResumeLive", got, v, err)
		}
		// Beyond the log end: refused, even though the hub would have taken it.
		if _, v, err := resumeFor("main", mustLSN(t, "0/9000")); err != nil || v != realtime.ResumeAhead {
			t.Fatalf("got (%v, %v), want ResumeAhead", v, err)
		}
		if asked != 2 {
			t.Errorf("the branch was read %d time(s), want once per resume", asked)
		}
	})

	t.Run("a subscribe with no position reads the branch but never fails on it", func(t *testing.T) {
		// Where the decoder starts is the floor every later ?since= is measured
		// against, so it is read here too -- best effort, because this request
		// has nothing to get wrong and worked before the check existed.
		clearHubs()
		readResumeWindow = func(string, string) (branch.ResumeWindow, error) {
			return branch.ResumeWindow{}, errors.New("psql: connection refused")
		}
		h, v, err := resumeFor("rtnone", 0)
		if err != nil || v != realtime.ResumeLive || h == nil {
			t.Fatalf("got (%v, %v, %v), want a hub and ResumeLive", h, v, err)
		}
		// Unknown floor, so a resume on this stream is answered with a refetch
		// rather than attached blind.
		if got := realtime.JudgeResume(mustLSN(t, "0/1000"),
			realtime.Window{Live: true, Floor: h.Floor()}); got != realtime.ResumeExpired {
			t.Errorf("a resume against an unknown floor gave %v, want ResumeExpired", got)
		}
		clearHubs()
	})

	t.Run("a branch that cannot be read refuses a resume and allows a fresh subscribe", func(t *testing.T) {
		clearHubs()
		readResumeWindow = func(string, string) (branch.ResumeWindow, error) {
			return branch.ResumeWindow{}, errors.New("psql: connection refused")
		}
		// With a position: refused, rather than handing an unchecked one to
		// the decoder.
		if _, _, err := resumeFor("main", mustLSN(t, "0/1000")); err == nil {
			t.Error("an unreadable branch accepted a ?since= anyway")
		}
		if liveHub("main") != nil {
			t.Error("a refused resume started a decoder")
		}
	})
}

// clearHubs drops every fan-out this test package started, so one case cannot
// decide the next.
func clearHubs() {
	hubs.mu.Lock()
	defer hubs.mu.Unlock()
	for name, cancel := range hubs.cancel {
		cancel()
		delete(hubs.cancel, name)
	}
	hubs.m = map[string]*realtime.Hub{}
}

func putHub(name string, h *realtime.Hub) {
	hubs.mu.Lock()
	defer hubs.mu.Unlock()
	hubs.m[name] = h
}

func mustLSN(t *testing.T, s string) pglogrepl.LSN {
	t.Helper()
	lsn, err := pglogrepl.ParseLSN(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return lsn
}
