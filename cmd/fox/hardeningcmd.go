// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// hardeningCmd is `fox hardening` (point 3.2): how a branch's PostgreSQL, and
// the install around it, stand against FoxByte's hardening checks.
//
//	fox hardening [--branch b] [--level basic|strict] [--failed] [--json]
//	fox hardening fix <check> [--branch b] [--yes]               (Enterprise, 3.3)
//	fox hardening profile baseline|strict [--branch b] [--yes]   (Enterprise, 3.4)
//
// The report is in every edition. Each report, fix and profile is in the
// security log: a list of a database's weak points is itself worth knowing
// about, and so is every change made to them.
func hardeningCmd(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "fix":
			hardeningFix(args[1:])
			return
		case "profile":
			hardeningProfile(args[1:])
			return
		}
	}
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	level := optValue(args, "--level")
	if level != "" && level != "basic" && level != "strict" {
		must(fmt.Errorf("--level is basic or strict, not %q", level))
	}
	rep, err := branch.ProduceHardening(b)
	must(err)
	if s := openStore(); s != nil {
		s.Audit(auth.EvHardeningReported, cliActor(), b, "", rep.LogLine())
		s.Close()
	}
	rep.Checks = filterHardening(rep.Checks, level, hasFlag(args, "--failed"))
	if hasFlag(args, "--json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		must(enc.Encode(rep))
		return
	}
	printHardening(rep)
}

// filterHardening keeps the checks of one level, and only those that did not
// pass when failed is set.
func filterHardening(cs []branch.HardeningCheck, level string, failed bool) []branch.HardeningCheck {
	var out []branch.HardeningCheck
	for _, c := range cs {
		if level != "" && c.Level != level {
			continue
		}
		if failed && (c.Status == branch.HardenPass || c.Status == branch.HardenNA) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func printHardening(rep branch.HardeningReport) {
	fmt.Printf("Hardening: %s, PostgreSQL %s\n", rep.Branch, rep.Postgres)
	fmt.Printf("%d pass, %d fail, %d manual, %d not applicable\n", rep.Summary[branch.HardenPass], rep.Summary[branch.HardenFail],
		rep.Summary[branch.HardenManual], rep.Summary[branch.HardenNA])
	mark := map[string]string{branch.HardenPass: "pass  ", branch.HardenFail: "FAIL  ", branch.HardenManual: "manual", branch.HardenNA: "n/a   "}
	section := ""
	for _, c := range rep.Checks {
		if c.Section != section {
			section = c.Section
			fmt.Printf("\n%s\n", strings.ToUpper(section[:1])+section[1:])
		}
		fmt.Printf("  %s  %-20s %s (%s)\n", mark[c.Status], c.ID, c.Title, c.Level)
		fmt.Printf("          %s\n", c.Evidence)
		if c.Fixable {
			fmt.Printf("          fix: %s hardening fix %s --branch %s   (shows what it changes first)\n", brand.CLI, c.ID, rep.Branch)
		} else if c.Fix != "" {
			fmt.Printf("          fix: %s\n", c.Fix)
		}
	}
	if rep.Profile != nil {
		fmt.Printf("\nProfile %s applied by %s at %s.\n", rep.Profile.Profile, rep.Profile.By, rep.Profile.At)
	}
	fmt.Printf("\n%s\n", rep.Basis)
	for _, l := range rep.Limits {
		fmt.Printf("  %s\n", l)
	}
	fmt.Printf("\nAs JSON: %s hardening --json > hardening.json\n", brand.CLI)
}

// hardeningFix shows what fixing one check changes, and with --yes makes it
// and checks again.
func hardeningFix(args []string) {
	requireFeature(edition.Hardening)
	ps := positionals(args, "--branch")
	if len(ps) != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s hardening fix <check> [--branch b] [--yes]\n", brand.CLI)
		os.Exit(2)
	}
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	if !hasFlag(args, "--yes") {
		f, err := branch.PlanHardeningFix(b, ps[0])
		must(err)
		printFixPlan(b, f)
		fmt.Printf("\nRun again with --yes to make it.\n")
		return
	}
	res, err := branch.ApplyHardeningFix(b, ps[0], cliActor())
	must(err)
	recordHardening(auth.EvHardeningFixed, b, res.FixLogLine())
	printFixResult(res)
	if res.Error != "" {
		os.Exit(1)
	}
}

// hardeningProfile shows every fix a profile makes on a branch, and the
// failing checks it leaves to a person; with --yes it makes them.
func hardeningProfile(args []string) {
	requireFeature(edition.Hardening)
	ps := positionals(args, "--branch")
	if len(ps) != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s hardening profile %s [--branch b] [--yes]\n", brand.CLI, strings.Join(branch.HardeningProfiles(), "|"))
		os.Exit(2)
	}
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	profile := ps[0]
	if !hasFlag(args, "--yes") {
		fixes, manual, err := branch.PlanHardeningProfile(b, profile)
		must(err)
		if len(fixes) == 0 {
			fmt.Printf("The %s profile has nothing to fix on %s.\n", profile, b)
		} else {
			fmt.Printf("The %s profile on %s makes %d fix(es):\n", profile, b, len(fixes))
			for _, f := range fixes {
				fmt.Println()
				printFixPlan(b, f)
			}
		}
		if len(manual) > 0 {
			fmt.Printf("\nFailing, and left to a person (%d):\n", len(manual))
			for _, c := range manual {
				fmt.Printf("  %-20s %s\n", c.ID, c.Fix)
			}
		}
		if len(fixes) > 0 {
			fmt.Printf("\nRun again with --yes to make them.\n")
		}
		return
	}
	results, err := branch.ApplyHardeningProfile(b, profile, cliActor())
	failed := 0
	for _, r := range results {
		recordHardening(auth.EvHardeningFixed, b, r.FixLogLine())
		printFixResult(r)
		if r.Error != "" {
			failed++
		}
	}
	recordHardening(auth.EvHardeningProfile, b, fmt.Sprintf("profile %s on %s: %d fix(es) made, %d did not hold", profile, b, len(results)-failed, failed))
	must(err)
	fmt.Printf("\nThe %s profile: %d fix(es) made on %s, %d did not hold.\n", profile, len(results)-failed, b, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func printFixPlan(b string, f branch.HardeningFix) {
	fmt.Printf("%s on %s: %s (%s)\n", f.ID, b, f.Title, f.Level)
	for _, c := range f.Changes {
		fmt.Printf("  change: %s\n", c)
	}
	for _, s := range f.SQL {
		fmt.Printf("  runs:   %s\n", s)
	}
	if f.Note != "" {
		fmt.Printf("  note:   %s\n", f.Note)
	}
}

func printFixResult(r branch.HardeningFixResult) {
	if r.Error != "" {
		fmt.Printf("%s: NOT fixed: %s\n", r.Fix.ID, r.Error)
		return
	}
	fmt.Printf("%s: %s → %s (%s)\n", r.Fix.ID, r.Before.Status, r.After.Status, strings.Join(r.Fix.Changes, "; "))
}

func recordHardening(kind, b, detail string) {
	if s := openStore(); s != nil {
		s.Audit(kind, cliActor(), b, "", detail)
		s.Close()
	}
}
