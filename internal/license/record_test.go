// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// fakeLog is the security log reduced to what Record uses, so the decision is
// tested without a database.
type fakeLog struct {
	lastKind, lastSubject string
	had                   bool
	readErr               error
	events                [][3]string // kind, subject, detail
}

func (f *fakeLog) Audit(kind, actor, subject, ip, detail string) {
	f.events = append(f.events, [3]string{kind, subject, detail})
	f.lastKind, f.lastSubject, f.had = kind, subject, true
}

func (f *fakeLog) LastLicenseEvent() (string, string, bool, error) {
	if f.readErr != nil {
		return "", "", false, f.readErr
	}
	return f.lastKind, f.lastSubject, f.had, nil
}

func activeStatus(id, customer, bound string) Status {
	return Status{
		State:   Active,
		BoundTo: bound,
		License: License{ID: id, Customer: customer, Edition: "enterprise",
			Features: []string{"anchors"}, NotAfter: time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC)},
	}
}

// The property the whole design rests on: every engine start calls Record, and
// a steady install must record one event ever rather than one per restart.
func TestRecordIsIdempotentAcrossRestarts(t *testing.T) {
	f := &fakeLog{}
	st := activeStatus("FB-1", "Acme Ltd", "machine-a")
	for i := 0; i < 5; i++ {
		Record(f, st)
	}
	if len(f.events) != 1 {
		t.Fatalf("recorded %d events across 5 starts, want 1: %v", len(f.events), f.events)
	}
	if f.events[0][0] != auth.EvLicenseActivated {
		t.Errorf("kind = %q, want %q", f.events[0][0], auth.EvLicenseActivated)
	}
	if f.events[0][1] != "FB-1@machine-a" {
		t.Errorf("subject = %q", f.events[0][1])
	}
	if !strings.Contains(f.events[0][2], "Acme Ltd") || !strings.Contains(f.events[0][2], "anchors") {
		t.Errorf("detail does not say who or what: %q", f.events[0][2])
	}
}

func TestRecordTheWholeLifecycle(t *testing.T) {
	f := &fakeLog{}

	// Activated.
	Record(f, activeStatus("FB-1", "Acme Ltd", "machine-a"))
	// Rebound: same licence, different machine.
	moved := activeStatus("FB-1", "Acme Ltd", "machine-b")
	moved.Rebinds = 1
	Record(f, moved)
	Record(f, moved) // and again: the move is already recorded
	// Lapsed.
	lapsed := moved
	lapsed.State, lapsed.Reason = Lapsed, "the licence expired on 1 October 2027"
	Record(f, lapsed)
	Record(f, lapsed)
	// Removed.
	Record(f, Status{State: Invalid, Reason: "no licence is installed"})
	Record(f, Status{State: Invalid, Reason: "no licence is installed"})

	want := []string{auth.EvLicenseActivated, auth.EvLicenseRebound, auth.EvLicenseLapsed, auth.EvLicenseRemoved}
	if len(f.events) != len(want) {
		t.Fatalf("recorded %d events, want %d: %v", len(f.events), len(want), f.events)
	}
	for i, k := range want {
		if f.events[i][0] != k {
			t.Errorf("event %d kind = %q, want %q", i, f.events[i][0], k)
		}
	}
	if !strings.Contains(f.events[1][2], "machine-a") || !strings.Contains(f.events[1][2], "machine-b") {
		t.Errorf("the rebind does not say where it moved from and to: %q", f.events[1][2])
	}
	if !strings.Contains(f.events[1][2], "move 1") {
		t.Errorf("the rebind does not carry the count: %q", f.events[1][2])
	}
	if f.events[3][1] != noLicenceSubject {
		t.Errorf("removal subject = %q, want %q", f.events[3][1], noLicenceSubject)
	}
}

// A licence renewed after lapsing has to come back, or an install that paid
// again would look dead in the log forever.
func TestRecordAfterALapseActivatesAgain(t *testing.T) {
	f := &fakeLog{}
	st := activeStatus("FB-1", "Acme Ltd", "machine-a")
	Record(f, st)
	lapsed := st
	lapsed.State, lapsed.Reason = Lapsed, "expired"
	Record(f, lapsed)
	renewed := activeStatus("FB-2", "Acme Ltd", "machine-a")
	Record(f, renewed)
	if len(f.events) != 3 || f.events[2][0] != auth.EvLicenseActivated {
		t.Fatalf("events = %v", f.events)
	}
	if f.events[2][1] != "FB-2@machine-a" {
		t.Errorf("subject = %q, want the new licence", f.events[2][1])
	}
}

// Warning unlocks — that is what a warning means — so a licence in grace or
// bound elsewhere is recorded as still unlocking, with the reason in the detail
// where it is read rather than enforced.
func TestRecordAWarningIsStillAnActivation(t *testing.T) {
	f := &fakeLog{}
	st := activeStatus("FB-1", "Acme Ltd", "machine-a")
	st.State = Warning
	st.Reason = "this licence was activated on a different machine"
	Record(f, st)
	if len(f.events) != 1 || f.events[0][0] != auth.EvLicenseActivated {
		t.Fatalf("events = %v", f.events)
	}
	if !strings.Contains(f.events[0][2], "different machine") {
		t.Errorf("detail does not carry the warning: %q", f.events[0][2])
	}
}

// Nothing installed and nothing recorded is the ordinary state of a Standard
// install. It must write nothing at all, on every start, forever.
func TestRecordSaysNothingAboutAnInstallWithNoLicence(t *testing.T) {
	f := &fakeLog{}
	for i := 0; i < 3; i++ {
		Record(f, Status{State: Invalid, Reason: "no licence is installed"})
	}
	if len(f.events) != 0 {
		t.Fatalf("recorded %v, want nothing", f.events)
	}
}

// A forged or edited licence never unlocked anything, so it is a lapse rather
// than an activation — and it is recorded, because an auditor wants to know a
// forgery was presented to this engine.
func TestRecordAForgeryIsRecordedAsLapsed(t *testing.T) {
	f := &fakeLog{}
	st := Status{State: Invalid, Reason: "signed by an unknown key", BoundTo: "machine-a",
		License: License{ID: "FB-9", Customer: "Nobody"}}
	Record(f, st)
	if len(f.events) != 1 || f.events[0][0] != auth.EvLicenseLapsed {
		t.Fatalf("events = %v", f.events)
	}
	if !strings.Contains(f.events[0][2], "unknown key") {
		t.Errorf("detail does not say why: %q", f.events[0][2])
	}
}

// An unreadable log must not be guessed at: treating "cannot read" as "nothing
// recorded" would write a duplicate activation on every start.
func TestRecordWritesNothingWhenTheLogCannotBeRead(t *testing.T) {
	f := &fakeLog{readErr: errors.New("database is locked")}
	Record(f, activeStatus("FB-1", "Acme Ltd", "machine-a"))
	if len(f.events) != 0 {
		t.Fatalf("recorded %v on an unreadable log, want nothing", f.events)
	}
}

func TestRecordToleratesNoLog(t *testing.T) {
	Record(nil, activeStatus("FB-1", "Acme Ltd", "machine-a")) // must not panic
}

func TestSubjectSplitsAtTheLastAt(t *testing.T) {
	if got := subjectLicenseID("FB-1@a@b"); got != "FB-1@a" {
		t.Errorf("id = %q", got)
	}
	if got := subjectMachine("FB-1@a@b"); got != "b" {
		t.Errorf("machine = %q", got)
	}
	if got := subjectLicenseID("FB-1"); got != "FB-1" {
		t.Errorf("id without a machine = %q", got)
	}
}

// EvaluateBound must carry the binding it compared against into the Status: the
// subject of every licence event is built from it, and "bound elsewhere" cannot
// be reported or recorded without saying where.
func TestEvaluateCarriesTheBinding(t *testing.T) {
	pub, priv := testKey(t)
	l := valid(t, priv) // issued for "abc123"
	st := EvaluateBound(l, pub, "moved-to", "moved-to", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if st.BoundTo != "moved-to" {
		t.Errorf("BoundTo = %q, want the binding it compared against", st.BoundTo)
	}
}

// Across the boundary for real: a licence event in an actual store, chained
// onto a log that already has other events, and the chain still verifying
// afterwards. The fake above proves the decision; this proves the write.
func TestRecordAgainstARealSecurityLog(t *testing.T) {
	store, err := auth.Open(auth.Config{
		DBPath:     filepath.Join(t.TempDir(), "accounts.db"),
		WebOrigin:  "http://localhost",
		SignupOpen: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Windows will not delete a file that is still open, so an unclosed store
	// fails the temp-dir cleanup rather than the assertion — which reads as a
	// mysterious failure in a test that otherwise passed.
	t.Cleanup(func() { store.Close() })
	store.Audit(auth.EvLoginOK, "someone@example.com", "", "127.0.0.1", "")

	st := activeStatus("FB-1", "Acme Ltd", "machine-a")
	Record(store, st)
	Record(store, st) // a second start must add nothing

	evs, err := store.RecentSecurityEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if strings.HasPrefix(e.Kind, auth.LicenseKindPrefix) {
			n++
			if e.Subject != "FB-1@machine-a" {
				t.Errorf("subject = %q", e.Subject)
			}
			if e.Actor != "" {
				t.Errorf("actor = %q, want empty: the engine observed this, nobody did it", e.Actor)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d licence events in the log, want 1", n)
	}

	// The log is tamper-evident, and a new kind of event must not be the thing
	// that breaks it. RecentSecurityEvents returns newest first; the chain runs
	// the other way.
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	if bad, why := auth.CheckEventChain(evs); bad != 0 {
		t.Fatalf("the chain broke at event %d: %s", bad, why)
	}
}
