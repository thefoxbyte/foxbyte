// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"strings"
	"testing"
)

// A privileged action leaves its intent in the log before it happens and its
// outcome after, and the chain still verifies.
func TestPrivilegedWritesIntentThenOutcome(t *testing.T) {
	s := testStore(t)
	p, err := s.BeginPrivileged(EvAdminGrantStarted, EvAdminGranted, EvAdminGrantFailed, "ada@example.com", "bob@example.com", "1.2.3.4", "branch main")
	if err != nil {
		t.Fatal(err)
	}
	p.Done(nil, "branch main")
	p.Done(errors.New("twice"), "") // a second call records nothing

	q, err := s.BeginPrivileged(EvAccountDeleteStarted, EvAccountDeleted, EvAccountDeleteFailed, "ada@example.com", "carl@example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	q.Done(errors.New("no such account"), "")

	evs, err := s.SecurityEvents(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Kind)
	}
	want := []string{EvAdminGrantStarted, EvAdminGranted, EvAccountDeleteStarted, EvAccountDeleteFailed}
	if strings.Join(kinds, " ") != strings.Join(want, " ") {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
	if !strings.Contains(evs[3].Detail, "no such account") {
		t.Errorf("the failure does not carry its error: %q", evs[3].Detail)
	}
	if id, why := CheckEventChain(evs); id != 0 {
		t.Errorf("the chain breaks at %d: %s", id, why)
	}
	// Only a granted admin moves the epoch, never the intent.
	if n, _ := s.AdminEpoch(); n != evs[1].ID {
		t.Errorf("AdminEpoch = %d, want the grant's own event %d", n, evs[1].ID)
	}
}

// Fail closed: when the intent cannot be written, the caller is told, and the
// outcome is never written either.
func TestPrivilegedRefusesWhenTheIntentCannotBeWritten(t *testing.T) {
	s := testStore(t)
	if _, err := s.db.Exec(`CREATE TRIGGER refuse_intents BEFORE INSERT ON security_events
		WHEN NEW.kind LIKE '%started' BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	p, err := s.BeginPrivileged(EvChangeApplyStarted, EvChangeApplied, EvChangeApplyFailed, "ada@example.com", "request #1", "", "")
	if !errors.Is(err, ErrSecurityLogUnavailable) || p != nil {
		t.Fatalf("BeginPrivileged = %v, %v; want a refusal", p, err)
	}
	p.Done(nil, "") // nil-safe, and records nothing
	if evs, _ := s.SecurityEvents(0, 0); len(evs) != 0 {
		t.Errorf("events were written: %+v", evs)
	}
	var none *Store
	if _, err := none.BeginPrivileged(EvChangeApplyStarted, EvChangeApplied, EvChangeApplyFailed, "", "", "", ""); !errors.Is(err, ErrSecurityLogUnavailable) {
		t.Errorf("no store at all: %v", err)
	}
}
