// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"errors"
	"fmt"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Giving the engine a file it has to read.
//
// On macOS and Windows the engine runs inside the VM, under a home directory of
// its own — so a file written to ~/.fox on this machine is not the file the
// engine opens. State the engine must act on is therefore *given* to it rather
// than looked up, using the same transport the updater already uses to stage a
// binary in. On Linux the host is the engine, and the copy is nothing.
//
// This exists for the licence. Activating on the host is deliberate: the
// fingerprint that matters is the machine a person sits at, and recreating the
// VM is an ordinary repair step rather than evidence of evasion — which is why
// `license` is in localCommands. But the process that has to honour a licence
// is the engine, on the other side of that boundary. Without this copy a
// customer activates a licence and the engine never hears about it.

// ErrNoEngine means there is nowhere to copy to yet — no VM, or a stopped one.
// It is not a failure of what the caller was doing: the licence is installed on
// this machine either way, and the copy is retried when the stack starts. So
// callers report it and carry on rather than unwinding.
var ErrNoEngine = errors.New("the engine is not running")

// PushState lands data in the engine's state directory as <name>, mode 0600.
func PushState(name string, data []byte) error {
	if err := checkStateName(name); err != nil {
		return err
	}
	return pushGuestState(name, data)
}

// PushStateStartingEngine is PushState for the moment the stack comes up.
//
// It may start the VM, because the command behind it is about to start it
// anyway — and that is what makes `fox start` the second chance this promises
// when a licence is activated with the engine down. Without it the start would
// bring the engine up, *then* hand it the licence, which is one run too late:
// the entitlement is read once, at startup.
//
// prepare() is the updater's, reused rather than reimplemented: "is the VM
// there, and is it running" has one answer per platform and should have one
// implementation.
func PushStateStartingEngine(name string, data []byte) error {
	if err := checkStateName(name); err != nil {
		return err
	}
	if err := newEngineHost().prepare(); err != nil {
		return ErrNoEngine
	}
	return pushGuestState(name, data)
}

// RemoveState deletes <name> from the engine's state directory. A missing file
// is not an error — removing a licence the engine never received should say
// "removed", not fail.
func RemoveState(name string) error {
	if err := checkStateName(name); err != nil {
		return err
	}
	return removeGuestState(name)
}

// checkStateName keeps the name to something that cannot escape the state
// directory or mean anything to a shell. The names are ours, all of them
// literals in this repository, so this is a guard against a future mistake
// rather than against a user — but it is the one place a host-side string is
// interpolated into a command in the guest, so it is checked here and not
// trusted anywhere below.
func checkStateName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("%q is not a state file name", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return fmt.Errorf("%q is not a state file name", name)
		}
	}
	return nil
}

// guestStateDirScript is a shell snippet leaving the engine's state directory
// in $d, resolved by the guest's own shell. $HOME there belongs to whichever
// user the engine runs as, which is the question that matters and the one this
// machine cannot answer: on Lima it is the guest user's home, not root's.
//
// It mirrors brand.resolveStateDir, retired names included. Creating ~/.fox
// where a retired directory is still waiting would strand that install's
// accounts, keys and anchors — resolveStateDir only moves the old directory
// while the new one does not exist — so the old one is written to instead, and
// the engine moves it on its next run with the licence inside it.
func guestStateDirScript() string {
	var b strings.Builder
	fmt.Fprintf(&b, `d="$HOME/%s"; `, brand.StateDirName)
	var old []string
	for _, p := range brand.Previous {
		if p.StateDir != "" {
			old = append(old, `"$HOME/`+p.StateDir+`"`)
		}
	}
	if len(old) > 0 {
		// A plain `[ -d "$o" ] && d="$o" && break` would be the whole command
		// of the loop body, so a directory that is simply absent would end the
		// script under `set -e`. An `if` cannot do that.
		fmt.Fprintf(&b, `if [ ! -d "$d" ]; then for o in %s; do if [ -d "$o" ]; then d="$o"; break; fi; done; fi; `,
			strings.Join(old, " "))
	}
	return b.String()
}

// guestStateWriteScript writes stdin to <name> in the engine's state directory.
//
// The content arrives on stdin, never in the command: nothing is quoted, and a
// licence does not appear in the guest's process list. Written to a temporary
// name and renamed, so the engine never reads a half-written file — the same
// rule internal/secrets follows on this side of the boundary.
func guestStateWriteScript(name string) string {
	return "set -e; umask 077; " + guestStateDirScript() +
		`mkdir -p "$d"; chmod 0700 "$d"; ` +
		`cat > "$d/` + name + `.new"; chmod 0600 "$d/` + name + `.new"; ` +
		`mv -f "$d/` + name + `.new" "$d/` + name + `"`
}

func guestStateRemoveScript(name string) string {
	return "set -e; " + guestStateDirScript() + `rm -f "$d/` + name + `"`
}
