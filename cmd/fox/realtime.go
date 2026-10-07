// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// `fox realtime …` — turning the change feed on, off, and seeing what it holds.
//
// setup and teardown live in the core rather than behind the build tag, and
// that is on purpose: someone who installed Enterprise, enabled the feed and
// then went back to Standard must still be able to undo it. A teardown that
// only existed in the binary they no longer have would leave their databases
// running with logical decoding on and publications nobody can remove.
func realtimeCmd(args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "setup":
		return realtimeSetup(args[1:])
	case "teardown":
		return realtimeTeardown(args[1:])
	case "slots":
		return realtimeSlots(args[1:])
	case "status", "":
		return realtimeStatus()
	default:
		// enable, disable and tables are the paid half, and exist only in the
		// Enterprise build.
		if realtimeEnterpriseCmd(args) {
			return nil
		}
		return fmt.Errorf("unknown: %s realtime %s\n\n%s%s", brand.CLI, sub, realtimeUsage(),
			realtimeEnterpriseUsage())
	}
}

func realtimeUsage() string {
	return fmt.Sprintf(`%[1]s realtime status             whether the databases are ready for a change feed
%[1]s realtime setup [--yes]     make them ready (restarts main)
%[1]s realtime teardown [--yes]  undo it (restarts main)
%[1]s realtime slots [branch]    the feed's replication slots, and the WAL they hold`, brand.CLI)
}

func realtimeStatus() error {
	if !branch.RealtimeOn() {
		fmt.Printf("The change feed is off. Databases run with wal_level=replica, which is\n"+
			"what they have always done; nothing is paying for a feature nobody asked for.\n\n"+
			"Turn it on with: %s realtime setup\n", brand.CLI)
		return nil
	}
	fmt.Printf("The change feed is available: databases run with wal_level=logical and\n"+
		"hold at most %s of WAL for a subscriber that has stopped reading.\n", branch.WALKeepSize())
	if !edition.Has(edition.Realtime) {
		fmt.Printf("\nNo licence covers the feed itself on this install, so nothing is streaming.\n"+
			"The setting above is harmless; `%s realtime teardown` puts it back.\n", brand.CLI)
	}
	return nil
}

// setup is the one way in, and it says what it will do before doing it.
//
// Changing wal_level needs a restart, and a restart drops connections. An
// upgrade must never do that on its own, which is why this is a command someone
// runs rather than something `fox up` decides.
func realtimeSetup(args []string) error {
	if branch.RealtimeOn() {
		fmt.Println("Already set up. Nothing to do.")
		return nil
	}
	if err := branch.RealtimeHAGuard("setup"); err != nil {
		return err
	}
	if !hasFlag(args, "--yes") {
		fmt.Printf("This turns on logical decoding, which `main` has to restart to pick up.\n"+
			"Connections drop for 5–15 seconds while it comes back; nothing is lost.\n\n"+
			"Branches pick it up as the reaper suspends and resumes them, or the next\n"+
			"time each one starts. Databases will hold at most %s of WAL for a\n"+
			"subscriber that has stopped reading (%s).\n\n"+
			"Run again with --yes to go ahead.\n",
			branch.WALKeepSize(), brand.EnvName("REALTIME_WAL_KEEP"))
		return nil
	}
	if err := branch.SetRealtimeOn(true); err != nil {
		return err
	}
	// The role a decoder connects as. Created here because this is the opt-in,
	// and again before each connection in case a branch predates it.
	if err := branch.EnsureRealtimeRole("main", branch.RealtimeRolePassword()); err != nil {
		_ = branch.SetRealtimeOn(false)
		return fmt.Errorf("creating the %s role: %w", branch.RealtimeRole, err)
	}
	fmt.Println("Restarting main…")
	if err := branch.RestartPrimary(); err != nil {
		// Put the marker back as it was: a half-done setup is worse than none,
		// because every later branch would start with settings main does not
		// have.
		_ = branch.SetRealtimeOn(false)
		return fmt.Errorf("main did not come back, so nothing was changed: %w", err)
	}
	fmt.Printf("Done. `%s realtime status` confirms it.\n", brand.CLI)
	return nil
}

func realtimeTeardown(args []string) error {
	if !branch.RealtimeOn() {
		fmt.Println("The change feed is already off. Nothing to do.")
		return nil
	}
	if err := branch.RealtimeHAGuard("teardown"); err != nil {
		return err
	}
	if !hasFlag(args, "--yes") {
		fmt.Printf("This turns logical decoding off, which `main` has to restart to pick up.\n" +
			"Connections drop for 5–15 seconds.\n\n" +
			"Any publications and replication slots the feed made are removed first;\n" +
			"a slot left behind would hold WAL that nothing will ever read.\n\n" +
			"Run again with --yes to go ahead.\n")
		return nil
	}
	if err := branch.DropRealtimeObjects(); err != nil {
		return fmt.Errorf("removing the feed's publications and slots: %w", err)
	}
	if err := branch.SetRealtimeOn(false); err != nil {
		return err
	}
	fmt.Println("Restarting main…")
	if err := branch.RestartPrimary(); err != nil {
		return fmt.Errorf("the feed is off but main did not come back: %w", err)
	}
	fmt.Println("Done.")
	return nil
}

func realtimeSlots(args []string) error {
	name := "main"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
	}
	slots, err := branch.RealtimeSlots(name)
	if err != nil {
		return err
	}
	if len(slots) == 0 {
		fmt.Printf("No change-feed slots on %q.\n", name)
		return nil
	}
	for _, s := range slots {
		state := "idle"
		if s.Active {
			state = "streaming"
		}
		fmt.Printf("%-40s %-10s %s of WAL held\n", s.Name, state, humanBytes(s.WALBytes))
	}
	fmt.Printf("\nAn idle slot still holds WAL. Drop one with:\n  %s realtime slots %s --drop <name>\n",
		brand.CLI, name)
	if drop := optValue(args, "--drop"); drop != "" {
		if err := branch.DropRealtimeSlot(name, drop); err != nil {
			return err
		}
		fmt.Printf("\nDropped %s.\n", drop)
	}
	return nil
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f kB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
