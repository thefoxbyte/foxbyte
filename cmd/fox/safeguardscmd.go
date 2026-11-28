// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// fox dpdp evidence | declare | declarations: the safeguards evidence
// (point 11.4, Rule 6).
//
//	fox dpdp evidence [--json]
//	fox dpdp declare                      what Rule 6 asks you to declare
//	fox dpdp declare ITEM "what is true"  record it, with who and when
//	fox dpdp declare ITEM --withdraw
//	fox dpdp declarations [--json]
func safeguardsCmd(sub string, args []string) {
	st := openStore()
	if st == nil {
		must(fmt.Errorf("the install's store could not be opened, and the evidence reads it"))
	}
	defer st.Close()
	switch sub {
	case "evidence":
		ev, err := branch.SafeguardsEvidenceFor(st, branch.SafeguardsOptions{By: cliActor(), Access: access.SafeguardAccessOf(st)})
		must(err)
		if hasFlag(args, "--json") {
			printJSON(ev)
			return
		}
		printSafeguards(os.Stdout, ev)
	case "declare":
		pos := positionals(args)
		if len(pos) <= 1 {
			fmt.Println("What Rule 6 asks you to declare (clause, item, what to state):")
			fmt.Println()
			for _, it := range branch.SafeguardItems() {
				fmt.Printf("  %-8s %-16s %s\n", it.Clause, it.Item, it.Asks)
			}
			fmt.Printf("\n%s dpdp declare ITEM \"what is true\"; %s dpdp declarations lists what is declared.\n", brand.CLI, brand.CLI)
			return
		}
		item, value := pos[1], strings.Join(pos[2:], " ")
		if hasFlag(args, "--withdraw") == (value != "") {
			must(fmt.Errorf("give %s a statement, or --withdraw it", item))
		}
		_, err := branch.DeclareSafeguard(st, item, value, cliActor())
		must(err)
		if value == "" {
			fmt.Printf("%s withdrawn: its clause is open until it is declared again.\n", item)
		} else {
			fmt.Printf("%s declared, by %s.\n", item, cliActor())
		}
	case "declarations":
		ds, err := branch.SafeguardDeclarations(st)
		must(err)
		if hasFlag(args, "--json") {
			printJSON(ds)
			return
		}
		if len(ds) == 0 {
			fmt.Printf("Nothing is declared (%s dpdp declare lists what Rule 6 asks).\n", brand.CLI)
		}
		for _, d := range ds {
			fmt.Printf("%-16s %s, by %s: %s\n", d.Item, d.DeclaredAt.Local().Format("2006-01-02 15:04"), d.DeclaredBy, d.Value)
		}
	}
}

func printSafeguards(w io.Writer, ev *branch.SafeguardsEvidence) {
	fmt.Fprintf(w, "Safeguards evidence (%s): %s\n", ev.Format, ev.Rule)
	fmt.Fprintf(w, "  in force %s; generated %s by %s; %s %s, %s edition\n", ev.InForce, ev.Generated, ev.By, ev.Product, ev.Version, ev.Edition)
	fmt.Fprintf(w, "  %d met, %d not met, %d open\n", ev.Summary[branch.VaultMet], ev.Summary[branch.VaultNotMet], ev.Summary[branch.VaultOpen])
	for _, r := range ev.Rules {
		fmt.Fprintf(w, "\n%s  %s\n  %s\n", r.Clause, strings.ToUpper(r.Verdict), r.Requirement)
		for _, c := range r.Checks {
			mark := "ok  "
			if !c.OK {
				mark = "FAIL"
			}
			fmt.Fprintf(w, "    %s %s (%s): %s\n", mark, c.What, c.Basis, c.Detail)
		}
		for _, it := range r.Items {
			found := false
			for _, d := range r.Declared {
				if d.Item == it {
					fmt.Fprintf(w, "    declared %s by %s, %s: %s\n", it, d.DeclaredBy, d.DeclaredAt.Local().Format("2006-01-02"), d.Value)
					found = true
				}
			}
			if !found {
				fmt.Fprintf(w, "    open: %s is not declared (%s dpdp declare %s \"…\")\n", it, brand.CLI, it)
			}
		}
		fmt.Fprintf(w, "    guards against: %s\n    not against: %s\n", r.Guards, r.NotAgainst)
		for _, n := range r.Notes {
			fmt.Fprintf(w, "    note: %s\n", n)
		}
	}
	fmt.Fprintln(w, "\nLimits:")
	for _, l := range ev.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
}
