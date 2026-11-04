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
)

// hardeningCmd is `fox hardening` (point 3.2): how a branch's PostgreSQL, and
// the install around it, stand against FoxByte's hardening checks.
//
//	fox hardening [--branch b] [--level basic|strict] [--failed] [--json]
//
// In every edition. Each report is in the security log: a list of a
// database's weak points is itself worth knowing about.
func hardeningCmd(args []string) {
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
		if c.Fix != "" {
			fmt.Printf("          fix: %s\n", c.Fix)
		}
	}
	fmt.Printf("\n%s\n", rep.Basis)
	for _, l := range rep.Limits {
		fmt.Printf("  %s\n", l)
	}
	fmt.Printf("\nAs JSON: %s hardening --json > hardening.json\n", brand.CLI)
}
