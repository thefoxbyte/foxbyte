// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/host"
	"github.com/thefoxbyte/foxbyte/internal/license"
)

// `fox license` — activate, show, rebind, remove.
//
// It runs on the host and is never forwarded into the VM (localCommands), for
// the same reason the fingerprint is read there: recreating the VM is an
// ordinary repair step, and a licence that moved with it would be rebound by a
// routine fix.
func licenseCmd(args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "activate":
		return licenseActivate(args[1:])
	case "show", "":
		return licenseShow()
	case "rebind":
		return licenseRebind()
	case "remove":
		return licenseRemove()
	default:
		return fmt.Errorf("unknown: %s license %s\n\n%s", brand.CLI, sub, licenseUsage())
	}
}

func licenseUsage() string {
	return fmt.Sprintf(`%[1]s license show                 what is installed, and this machine's fingerprint
%[1]s license activate <file|->   install a licence (- reads stdin)
%[1]s license rebind              move the installed licence to this machine
%[1]s license remove              uninstall it`, brand.CLI)
}

// activate reads a licence, checks it, and installs it.
//
// From a file or stdin, never from an argument: a licence is not a secret, but
// arguments end up in shell history and in the process list, and that is a
// habit worth not teaching — the same reason `fox license` takes a path here
// and the update tooling takes its token from the environment.
func licenseActivate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s license activate <file|->", brand.CLI)
	}
	var raw []byte
	var err error
	if args[0] == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(args[0])
	}
	if err != nil {
		return err
	}
	var l license.License
	if err := json.Unmarshal(raw, &l); err != nil {
		return fmt.Errorf("that file is not a licence: %w", err)
	}
	pub, err := license.PublicKey()
	if err != nil {
		return err
	}
	// Refuse a forgery outright. Everything else — expired, bound elsewhere —
	// installs with a warning, because those are states a real customer can be
	// in and the way out differs for each.
	if err := license.CheckSignature(l, pub); err != nil {
		return fmt.Errorf("%w\n\nNothing was installed", err)
	}
	fp := host.MachineID()
	// Bound to whatever it was issued for, not to this machine: activating a
	// licence meant for another one should say so, and `rebind` is the way to
	// move it. Binding silently on activation would make the warning
	// unreachable and the record meaningless.
	if err := license.Save(l, l.Fingerprint, 0); err != nil {
		return err
	}
	fmt.Printf("Activated %s for %s.\n", l.ID, l.Customer)
	st := license.EvaluateBound(l, pub, l.Fingerprint, fp, time.Now())
	printLicenseState(st, fp)
	return nil
}

func licenseShow() error {
	fp := host.MachineID()
	l, boundTo, rebinds, err := license.Load()
	if err == license.ErrNone {
		fmt.Printf("No licence is installed, so this is the %s edition.\n\n", edition.Name())
		printFingerprint(fp)
		return nil
	}
	if err != nil {
		return err
	}
	pub, perr := license.PublicKey()
	if perr != nil {
		return perr
	}
	fmt.Printf("%s — %s\n", l.ID, l.Customer)
	if len(l.Features) > 0 {
		fmt.Printf("  unlocks    %s\n", strings.Join(l.Features, ", "))
	}
	fmt.Printf("  issued     %s\n", l.IssuedAt.UTC().Format("2 January 2006"))
	if !l.NotAfter.IsZero() {
		fmt.Printf("  runs to    %s\n", l.NotAfter.UTC().Format("2 January 2006"))
	}
	switch {
	case l.Fingerprint == "":
		fmt.Printf("  machine    any — this licence is not tied to one\n")
	default:
		fmt.Printf("  issued for %s\n", short(l.Fingerprint))
		fmt.Printf("  bound to   %s", short(boundTo))
		if rebinds > 0 {
			fmt.Printf(" (moved %d time%s)", rebinds, plural(rebinds))
		}
		fmt.Println()
	}
	fmt.Println()
	printLicenseState(license.EvaluateBound(l, pub, boundTo, fp, time.Now()), fp)
	return nil
}

// rebind moves an installed licence to this machine. It is one command rather
// than reinstalling because the count is kept across it, which is what makes
// the record worth anything.
func licenseRebind() error {
	l, _, rebinds, err := license.Load()
	if err == license.ErrNone {
		return fmt.Errorf("there is no licence to move — install one with `%s license activate <file>`", brand.CLI)
	}
	if err != nil {
		return err
	}
	fp := host.MachineID()
	if fp == "" {
		return fmt.Errorf("this machine's identifier could not be read, so there is nothing to bind to")
	}
	if err := license.Save(l, fp, rebinds+1); err != nil {
		return err
	}
	fmt.Printf("Moved %s to this machine (%s).\n", l.ID, short(fp))
	fmt.Printf("That is move %d. It is recorded here and in the security log; the\n"+
		"number of machines on an account is counted where the licence was issued.\n", rebinds+1)
	return nil
}

func licenseRemove() error {
	if _, _, _, err := license.Load(); err == license.ErrNone {
		fmt.Println("No licence was installed.")
		return nil
	}
	if err := license.Remove(); err != nil {
		return err
	}
	fmt.Printf("Removed. This install is the %s edition again; no data was touched.\n", edition.Name())
	return nil
}

// printLicenseState says what is true and what to do about it, in that order.
// One place, so the CLI, `fox check` and the console cannot drift into saying
// three different things about the same licence.
func printLicenseState(st license.Status, fp string) {
	switch st.State {
	case license.Active:
		fmt.Println("Status: active.")
	default:
		fmt.Printf("Status: %s — %s.\n", st.State, st.Reason)
		if st.Action != "" {
			fmt.Printf("        %s\n", st.Action)
		}
	}
	if st.State != license.Active {
		fmt.Println()
		printFingerprint(fp)
	}
}

// The fingerprint is the one piece of output designed to be copied: it is what
// someone pastes into a renewal or sends to support, so it goes on a line of
// its own with nothing to trim off.
func printFingerprint(fp string) {
	if fp == "" {
		fmt.Println("This machine's identifier could not be read. That does not stop anything;")
		fmt.Println("a licence bound to another machine still works, with a warning.")
		return
	}
	fmt.Println("This machine's fingerprint, for a new or renewed licence:")
	fmt.Println()
	fmt.Println("  " + fp)
}

func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12] + "…"
	}
	return fp
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
