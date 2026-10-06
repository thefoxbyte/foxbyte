// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import "testing"

// A Status nobody evaluated must not read as a working licence. /api/license
// reports what this process is honouring, and before Install has run that is
// nothing — so the zero value is Invalid rather than Active, which is what it
// was when State's constants were first written in the obvious order.
func TestTheZeroStatusUnlocksNothing(t *testing.T) {
	var st Status
	if st.Unlocks() {
		t.Error("the zero Status unlocks features")
	}
	if st.Present() {
		t.Error("the zero Status claims a licence is installed")
	}
	if st.State.Code() != "invalid" {
		t.Errorf("the zero Status reports %q", st.State.Code())
	}
}

// Code is matched on by the API and the console, so it is part of the
// interface: String may be reworded, this may not.
func TestStateCodes(t *testing.T) {
	for st, want := range map[State]string{
		Active: "active", Warning: "warning", Lapsed: "lapsed", Invalid: "invalid",
	} {
		if got := st.Code(); got != want {
			t.Errorf("State(%d).Code() = %q, want %q", st, got, want)
		}
	}
}
