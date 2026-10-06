// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import "testing"

// LastLicenseEvent has to find the newest licence event past whatever else the
// log has recorded since — logins and refusals are the bulk of it, and the
// licence recorder compares against this to decide whether to write at all.
func TestLastLicenseEvent(t *testing.T) {
	s := testStore(t)

	if _, _, ok, err := s.LastLicenseEvent(); err != nil || ok {
		t.Fatalf("an empty log reported ok=%v err=%v, want false and no error", ok, err)
	}

	s.Audit(EvLicenseActivated, "", "FB-1@machine-a", "", "Acme Ltd")
	s.Audit(EvLoginOK, "someone@example.com", "", "127.0.0.1", "")
	s.Audit(EvKeyCreated, "someone@example.com", "key 1", "", "")

	kind, subject, ok, err := s.LastLicenseEvent()
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if kind != EvLicenseActivated || subject != "FB-1@machine-a" {
		t.Fatalf("kind=%q subject=%q", kind, subject)
	}

	// The newest one wins, not the first.
	s.Audit(EvLicenseRebound, "", "FB-1@machine-b", "", "moved")
	if kind, subject, _, _ := s.LastLicenseEvent(); kind != EvLicenseRebound || subject != "FB-1@machine-b" {
		t.Fatalf("kind=%q subject=%q, want the newest", kind, subject)
	}
}

// Every licence kind must match the prefix the query filters on, or an event
// would be written and never found again — and the recorder would then write a
// duplicate on every start.
func TestEveryLicenseKindMatchesThePrefix(t *testing.T) {
	for _, k := range []string{EvLicenseActivated, EvLicenseRebound, EvLicenseLapsed, EvLicenseRemoved} {
		if len(k) <= len(LicenseKindPrefix) || k[:len(LicenseKindPrefix)] != LicenseKindPrefix {
			t.Errorf("%q does not start with %q", k, LicenseKindPrefix)
		}
	}
	// And no other kind may, or it would be picked up as a licence event.
	for _, k := range []string{EvLoginOK, EvLoginFailed, EvKeyCreated, EvKeyRevoked, EvAdminGranted,
		EvDenied, EvGatewayRefused, EvChangeRequested, EvChangeDecided, EvRegister, EvAccountDeleted} {
		if len(k) >= len(LicenseKindPrefix) && k[:len(LicenseKindPrefix)] == LicenseKindPrefix {
			t.Errorf("%q starts with %q but is not a licence event", k, LicenseKindPrefix)
		}
	}
}

// A nil store is how the recorder sees an install with no accounts database. It
// must answer "nothing recorded" rather than panic.
func TestLastLicenseEventOnNoStore(t *testing.T) {
	var s *Store
	if _, _, ok, err := s.LastLicenseEvent(); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
