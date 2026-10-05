// SPDX-License-Identifier: AGPL-3.0-or-later

package license

import (
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/host"
)

// The bug this prevents: on macOS and Windows the engine runs in the VM, whose
// machine id is a different number from the host's — and a licence is bound to
// the host's, because that is where `fox license` runs and where the machine a
// person sits at actually is. Comparing against the guest's would put every
// such install permanently in "this licence was activated on a different
// machine": a warning on every command, and that sentence recorded in the
// security log as the reason a perfectly good licence was unlocking.
//
// Unknown is already handled everywhere as "not a mismatch", and inside the VM
// the host's machine id is exactly that: not readable from here.
func TestTheBindingIsNotComparedInsideTheVM(t *testing.T) {
	t.Setenv(brand.EnvName("IN_GUEST"), "1")
	if got := licensedMachine(); got != "" {
		t.Errorf("licensedMachine() = %q inside the VM, want empty", got)
	}
}

// And on the machine a person sits at, it is compared — otherwise the binding
// would mean nothing anywhere.
func TestTheBindingIsComparedOnTheHost(t *testing.T) {
	t.Setenv(brand.EnvName("IN_GUEST"), "")
	if got, want := licensedMachine(), host.MachineID(); got != want {
		t.Errorf("licensedMachine() = %q on the host, want this machine's id %q", got, want)
	}
}
