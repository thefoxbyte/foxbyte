// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"sync/atomic"

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
	st := install()
	installed.Store(&st)
	return st
}

// installed is what Install last decided. The control plane records that
// decision in the security log, and must record the one this process is
// actually running under rather than read the licence a second time and risk
// logging a state the process never honoured.
var installed atomic.Pointer[Status]

// Installed is the status Install produced, or a zero Status if it never ran.
func Installed() Status {
	if st := installed.Load(); st != nil {
		return *st
	}
	return Status{}
}

func install() Status {
	st, err := Current(licensedMachine())
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

// licensedMachine is the machine a licence's binding is compared against.
//
// Empty inside the VM, and that is the right answer rather than a concession.
// The machine a licence is bound to is the one a person sits at — `fox license`
// runs there on purpose, and the VM's own id is a different number that changes
// whenever `fox setup` recreates it. Comparing against the guest's would put
// every macOS and Windows install permanently in "this licence was activated on
// a different machine": warning on every command, and recording that sentence
// in the security log as the reason a perfectly good licence was unlocking.
//
// An unreadable machine id is already handled everywhere as "unknown, and
// therefore not a mismatch". This is exactly that case, known in advance.
func licensedMachine() string {
	if host.InGuest() {
		return ""
	}
	return host.MachineID()
}

// SetInstalledForTest makes Installed report st, and returns a function that
// puts back what was there. For tests of packages that read the entitlement
// without being able to activate a real licence — /api/license is the one that
// needs it, since a signed licence needs the private key. Release builds never
// call it, and it does not touch internal/edition: this is what the engine
// *reports*, and what it *permits* still comes only from Install.
func SetInstalledForTest(st Status) (restore func()) {
	old := installed.Load()
	installed.Store(&st)
	return func() { installed.Store(old) }
}
