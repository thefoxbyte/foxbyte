// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// dpdpCmd is `fox dpdp` (point 11): the DPDP compliance manager. First, the
// personal-data inventory (11.1).
//
//	fox dpdp inventory [--branch b] [--gaps] [--json | --csv]
//	fox dpdp set <schema.table[.column]> --basis b --purpose "…" --principals p,q
//	        --keep 3y --from f --reason r [--citation "…"] [--note "…"] [--branch b]   (Enterprise)
//	fox dpdp unset <schema.table[.column]> [--branch b]                               (Enterprise)
//	fox dpdp history <schema.table[.column]> [--branch b] [--json]
//
// The inventory lists every table holding personal data a reviewer confirmed
// (fox pii mark), with its entry: the basis under the DPDP Act, the purpose,
// whose data it is and how long it is kept. A confirmed column with no entry,
// its own or its table's, is a gap. Reading is free in every edition.
func dpdpCmd(args []string) {
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	ps := positionals(args, "--branch", "--basis", "--purpose", "--principals", "--keep", "--from", "--reason", "--citation", "--note")
	sub := "inventory"
	if len(ps) > 0 {
		sub = ps[0]
	}
	place := func() (string, string, string) {
		if len(ps) < 2 {
			fmt.Fprintf(os.Stderr, "usage: %s dpdp %s <schema.table[.column]> …\n", brand.CLI, sub)
			os.Exit(2)
		}
		s, t, c, err := branch.SplitDPDPPlace(ps[1])
		must(err)
		return s, t, c
	}
	switch sub {
	case "inventory":
		inv, err := branch.DPDPInventoryOf(b)
		must(err)
		if hasFlag(args, "--gaps") {
			kept := inv.Tables[:0]
			for _, t := range inv.Tables {
				if t.Gaps > 0 {
					kept = append(kept, t)
				}
			}
			inv.Tables = kept
		}
		switch {
		case hasFlag(args, "--json"):
			printJSON(inv)
		case hasFlag(args, "--csv"):
			must(branch.WriteDPDPCSV(os.Stdout, inv))
		default:
			printDPDP(os.Stdout, inv)
		}
	case "set":
		requireFeature(edition.DPDP)
		s, t, c := place()
		count, unit, err := parseKeep(optValue(args, "--keep"))
		must(err)
		e := branch.DPDPEntry{
			Schema: s, Table: t, Column: c,
			Basis:   optValue(args, "--basis"),
			Purpose: optValue(args, "--purpose"),
			Note:    optValue(args, "--note"),
			Keep: branch.DPDPKeep{
				Count: count, Unit: unit,
				From:     strings.ReplaceAll(optValue(args, "--from"), "-", "_"),
				Reason:   optValue(args, "--reason"),
				Citation: optValue(args, "--citation"),
			},
		}
		for _, p := range strings.Split(optValue(args, "--principals"), ",") {
			if p = strings.TrimSpace(p); p != "" {
				e.Principals = append(e.Principals, p)
			}
		}
		got, err := branch.SetDPDPEntry(b, e, cliActor())
		must(err)
		if st := historyStore(); st != nil {
			st.Audit(auth.EvDPDPSet, cliActor(), b, "", got.Summary())
			st.Close()
		}
		fmt.Printf("%s on %s: %s\n", got.Where(), b, branch.DPDPLabel(branch.DPDPWords.Bases, got.Basis))
		fmt.Printf("  purpose: %s\n  whose: %s\n  kept: %s\n", got.Purpose, principals(got.Principals), got.Keep)
	case "unset":
		requireFeature(edition.DPDP)
		s, t, c := place()
		must(branch.RemoveDPDPEntry(b, s, t, c, cliActor()))
		where := branch.DPDPEntry{Schema: s, Table: t, Column: c}.Where()
		if st := historyStore(); st != nil {
			st.Audit(auth.EvDPDPRemoved, cliActor(), b, "", where)
			st.Close()
		}
		fmt.Printf("removed the entry for %s on %s; %s dpdp history %s keeps it\n", where, b, brand.CLI, where)
	case "history":
		s, t, c := place()
		hs, err := branch.DPDPHistory(b, s, t, c)
		must(err)
		if hasFlag(args, "--json") {
			printJSON(hs)
			return
		}
		if len(hs) == 0 {
			fmt.Printf("no entry has been set for %s on %s\n", ps[1], b)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "WHEN\tWHO\tWHAT\tWHERE\tBASIS\tKEPT")
		for _, h := range hs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.At.Local().Format("2006-01-02 15:04"), h.Actor, h.Action,
				h.Entry.Where(), h.Entry.Basis, h.Entry.Keep.Brief())
		}
		tw.Flush()
	default:
		fmt.Fprintf(os.Stderr, `usage:
  %[1]s dpdp inventory [--branch b] [--gaps] [--json | --csv]
  %[1]s dpdp set <schema.table[.column]> --basis consent|7a…7i --purpose "…" --principals customer,child
        --keep 3y|18m|90d|0 --from collection|last-contact|account-closed|contract-end|purpose-served
        --reason law|contract|purpose [--citation "the law or contract"] [--note "…"] [--branch b]
  %[1]s dpdp unset <schema.table[.column]> [--branch b]
  %[1]s dpdp history <schema.table[.column]> [--branch b] [--json]
`, brand.CLI)
		os.Exit(2)
	}
}

// parseKeep reads a retention's period: 3y, 18m, 90d, "3 years", or 0.
func parseKeep(s string) (int, string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, "", fmt.Errorf("--keep says how long: 3y, 18m, 90d, or 0 (until the --from event)")
	}
	i := strings.IndexFunc(s, func(r rune) bool { return !unicode.IsDigit(r) })
	num, unit := s, ""
	if i >= 0 {
		num, unit = s[:i], strings.TrimSpace(s[i:])
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, "", fmt.Errorf("--keep is a number and a unit, such as 3y or 90d, not %q", s)
	}
	switch unit {
	case "":
		if n != 0 {
			return 0, "", fmt.Errorf("--keep %d what? Days, months or years: %dd, %dm or %dy", n, n, n, n)
		}
		return 0, "days", nil
	case "d", "day", "days":
		return n, "days", nil
	case "m", "month", "months":
		return n, "months", nil
	case "y", "year", "years":
		return n, "years", nil
	}
	return 0, "", fmt.Errorf("--keep's unit is d, m or y (days, months, years), not %q", unit)
}

func principals(ps []string) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = branch.DPDPLabel(branch.DPDPWords.Principals, p)
	}
	return strings.Join(out, "; ")
}

// printDPDP prints the inventory table by table: each one's entry, then its
// confirmed columns and what covers each.
func printDPDP(w io.Writer, inv branch.DPDPInventory) {
	when := "never scanned"
	if inv.Scanned != nil {
		when = "scanned " + inv.Scanned.Local().Format("2006-01-02 15:04")
	}
	fmt.Fprintf(w, "DPDP inventory of %s (%s): %d table(s) with confirmed personal data", inv.Branch, when, len(inv.Tables))
	if inv.GapColumns > 0 {
		fmt.Fprintf(w, "; %d column(s) in %d table(s) have no entry", inv.GapColumns, inv.GapTables)
	}
	fmt.Fprintln(w)
	entry := func(e *branch.DPDPEntry) string {
		return fmt.Sprintf("%s; whose: %s; kept %s", branch.DPDPLabel(branch.DPDPWords.Bases, e.Basis), principals(e.Principals), e.Keep)
	}
	for _, t := range inv.Tables {
		fmt.Fprintf(w, "\n%s.%s\n", t.Schema, t.Table)
		if t.Entry != nil {
			fmt.Fprintf(w, "  %s\n  purpose: %s\n", entry(t.Entry), t.Entry.Purpose)
		} else {
			fmt.Fprintln(w, "  no entry for the table")
		}
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, c := range t.Columns {
			what := strings.Join(c.Categories, ", ")
			if len(c.Paths) > 0 {
				what += " at " + strings.Join(c.Paths, ", ")
			}
			cover := "the table's entry"
			switch c.By {
			case "column":
				cover = "its own entry: " + entry(c.Override) + "; purpose: " + c.Override.Purpose
			case "":
				cover = "NO ENTRY: " + fmt.Sprintf("%s dpdp set %s.%s --basis …", brand.CLI, t.Schema, t.Table)
			}
			fmt.Fprintf(tw, "    %s\t%s\t%s\n", c.Column, what, cover)
		}
		tw.Flush()
		for _, n := range t.Notices {
			fmt.Fprintf(w, "  ! %s\n", n)
		}
	}
	if len(inv.Tables) == 0 {
		fmt.Fprintf(w, "\nNothing confirmed yet: scan with %[1]s pii scan, and confirm findings with %[1]s pii mark.\n", brand.CLI)
	}
	if len(inv.Stale) > 0 {
		fmt.Fprintln(w, "\nEntries whose place no longer holds confirmed personal data (remove with dpdp unset, or confirm the findings again):")
		for _, e := range inv.Stale {
			fmt.Fprintf(w, "  %s (set by %s, %s)\n", e.Where(), e.SetBy, e.SetAt.Local().Format("2006-01-02"))
		}
	}
	fmt.Fprintln(w, "\nWhat this cannot claim:")
	for _, l := range inv.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
}

// checkDPDP is fox check's line for main's DPDP inventory: a confirmed
// column with no entry is a warning (decided for 11.1: report and warn, never
// block). A main that is not running is not woken for it.
func checkDPDP() checkLine {
	if st := branch.ContainerState("main"); st != "running" {
		return ok("DPDP inventory", "main is "+st+"; not read")
	}
	inv, err := branch.DPDPInventoryOf("main")
	if err != nil {
		return ok("DPDP inventory", "could not be read: "+firstLine(err.Error()))
	}
	return dpdpLine(inv, edition.Has(edition.DPDP))
}

func dpdpLine(inv branch.DPDPInventory, licensed bool) checkLine {
	const name = "DPDP inventory"
	recorded := len(inv.Stale)
	notices := 0
	for _, t := range inv.Tables {
		if t.Entry != nil {
			recorded++
		}
		for _, c := range t.Columns {
			if c.Override != nil {
				recorded++
			}
		}
		notices += len(t.Notices)
	}
	switch {
	case !licensed && recorded == 0:
		return ok(name, "not in use")
	case len(inv.Tables) == 0 && recorded == 0:
		return ok(name, "main holds no confirmed personal data yet")
	}
	var also []string
	if notices > 0 {
		also = append(also, fmt.Sprintf("%d notice(s), such as a child's data its entry does not mention", notices))
	}
	if len(inv.Stale) > 0 {
		also = append(also, fmt.Sprintf("%d entry(ies) for places that no longer hold confirmed personal data", len(inv.Stale)))
	}
	tail := ""
	if len(also) > 0 {
		tail = "; " + strings.Join(also, "; ")
	}
	if inv.GapColumns > 0 {
		return warn(name, fmt.Sprintf("%d column(s) in %d table(s) of main hold confirmed personal data with no entry%s",
			inv.GapColumns, inv.GapTables, tail), brand.CLI+" dpdp inventory --gaps")
	}
	if notices > 0 || len(inv.Stale) > 0 {
		return warn(name, fmt.Sprintf("every confirmed column of main has an entry%s", tail), brand.CLI+" dpdp inventory")
	}
	return ok(name, fmt.Sprintf("every confirmed column of main's %d table(s) has an entry", len(inv.Tables)))
}
