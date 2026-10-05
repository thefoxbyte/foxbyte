// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/host"
)

// Install reads the installed licence and tells internal/edition what it
// unlocks. Everything that asks "may this run" goes through edition.Has, so
// this is the one place a licence becomes an entitlement.
//
// It is safe to call in a Standard build and does nothing useful there:
// edition.Has is false whatever the licence says, because a Standard binary
// does not contain the code the licence would unlock.
//
// Three failures are all treated the same way — no entitlement, no noise:
//
//   - no licence installed, which is the ordinary state of a Standard install
//   - a build with no licence public key, which cannot tell real from forged
//   - a licence that is lapsed or a forgery
//
// None of them is reported here. A refusal is reported at the point someone
// asks for a paid feature, where it can say which feature and what to do about
// it; shouting at start-up about a licence nobody is currently using would be
// noise on every single command.
//
// Returns the status so a caller that wants to say something — `fox check`, the
// status endpoint — can, without reading the licence a second time.
func Install() Status {
	st, err := Current(host.MachineID())
	if err != nil {
		edition.SetEntitlement(nil)
		return Status{State: Invalid, Reason: err.Error()}
	}
	if !st.Unlocks() {
		edition.SetEntitlement(nil)
		return st
	}
	l := st.License
	edition.SetEntitlement(func(f edition.Feature) bool { return l.Has(f) })
	return st
}
