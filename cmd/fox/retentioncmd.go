// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// fox dpdp retention: retention acted on (point 11.3).
//
//	fox dpdp retention [status] [--json]
//	fox dpdp retention on --notify https://…       (Enterprise; prints the signing secret once)
//	fox dpdp retention off
//	fox dpdp retention column <schema.table> <column>
//	fox dpdp retention arm <schema.table> --reason "…" [--yes]
//	fox dpdp retention disarm <schema.table>
//	fox dpdp retention run [--json]
//	fox dpdp retention notices [<schema.table>] [--open] [--json]
func retentionCmd(args []string) {
	ps := positionals(args, "--notify", "--reason")
	sub := "status"
	if len(ps) > 0 {
		sub = ps[0]
	}
	arg := func(i int, what string) string {
		if len(ps) <= i {
			fmt.Fprintf(os.Stderr, "usage: %s dpdp retention %s %s\n", brand.CLI, sub, what)
			os.Exit(2)
		}
		return ps[i]
	}
	s := openStore()
	if s == nil {
		must(fmt.Errorf("the install's store could not be opened, and retention keeps its tables and notices there"))
	}
	defer s.Close()
	switch sub {
	case "status":
		st, err := branch.GetRetentionStatus(s)
		must(err)
		if hasFlag(args, "--json") {
			printJSON(st)
			return
		}
		printRetentionStatus(os.Stdout, st)
	case "on":
		secret, err := branch.SetRetentionOn(s, optValue(args, "--notify"), cliActor())
		must(err)
		fmt.Printf("Retention is on. Each notice is posted to %s, signed in the %s header:\n", optValue(args, "--notify"), branch.NoticeSignature)
		fmt.Printf("  sha256=<HMAC-SHA256 of the body, keyed with %s>\n", secret)
		fmt.Println("Keep the key: it is not shown again. Only armed tables are erased from; arm each after its preview:")
		fmt.Printf("  %s dpdp retention arm <schema.table> --reason \"…\"\n", brand.CLI)
	case "off":
		must(branch.SetRetentionOff(s, cliActor()))
		fmt.Println("Retention is off: nothing is noticed or erased until it is on again. Open notices wait.")
	case "column":
		table, col := arg(1, "<schema.table> <column>"), arg(2, "<schema.table> <column>")
		d, err := branch.SetRetentionColumn(s, table, col, cliActor())
		must(err)
		fmt.Printf("%s's period runs from %s. %d row(s) are past it now, %d have no date there.\n", table, col, d.Total, d.Undated)
	case "arm":
		table := arg(1, "<schema.table> --reason \"…\" [--yes]")
		d, err := branch.RetentionPreview(s, table)
		must(err)
		printPreview(os.Stdout, d)
		if !hasFlag(args, "--yes") {
			if !isTerminal(os.Stdin) {
				must(fmt.Errorf("arming erases these rows once their notices' time is up: pass --yes to arm it"))
			}
			fmt.Printf("Type the table's name (%s.%s) to arm it: ", d.Schema, d.Table)
			line, _ := bufio.NewReader(io.LimitReader(os.Stdin, 1024)).ReadString('\n')
			if strings.TrimSpace(line) != d.Schema+"."+d.Table {
				must(fmt.Errorf("not armed"))
			}
		}
		_, err = branch.ArmRetention(s, table, cliActor(), optValue(args, "--reason"))
		must(err)
		fmt.Printf("%s.%s is armed: each run notices its rows past the period, and erases them %s after a delivered notice if they are still past it.\n",
			d.Schema, d.Table, branch.RetentionNoticePeriod())
	case "disarm":
		table := arg(1, "<schema.table>")
		must(branch.DisarmRetention(s, table, cliActor()))
		fmt.Printf("%s is disarmed: nothing of it is noticed or erased. Open notices wait.\n", table)
	case "run":
		run, err := branch.RunRetention(s, cliActor())
		must(err)
		if hasFlag(args, "--json") {
			printJSON(run)
			return
		}
		printRetentionRun(os.Stdout, run)
	case "notices":
		schema, table := "", ""
		if len(ps) > 1 {
			sc, tb, _, err := branch.SplitDPDPPlace(ps[1])
			must(err)
			schema, table = sc, tb
		}
		ns, err := s.RetentionNotices(schema, table, hasFlag(args, "--open"), 500)
		must(err)
		if hasFlag(args, "--json") {
			printJSON(ns)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTABLE\tKEY\tDATED\tNOTICED\tERASE AFTER\tSTATE\tREQUEST")
		for _, n := range ns {
			req := ""
			if n.Request > 0 {
				req = fmt.Sprintf("#%d", n.Request)
			}
			fmt.Fprintf(tw, "%d\t%s.%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.Schema, n.Table, n.Key, day(n.Since), day(n.Noticed), day(n.EraseAfter), n.State, req)
		}
		tw.Flush()
	default:
		fmt.Fprintf(os.Stderr, `usage:
  %[1]s dpdp retention [status] [--json]                        each table with a period: its date column, armed or not, rows past it
  %[1]s dpdp retention on --notify https://…                    turn it on; notices are posted there, signed
  %[1]s dpdp retention off
  %[1]s dpdp retention column <schema.table> <column>           the date a table's period runs from
  %[1]s dpdp retention arm <schema.table> --reason "…" [--yes]  erase from it from now on, after its preview
  %[1]s dpdp retention disarm <schema.table>
  %[1]s dpdp retention run [--json]                             notice and erase now, once (the scheduler does it daily)
  %[1]s dpdp retention notices [<schema.table>] [--open] [--json]

A row past its period is noticed (posted to the address, Rule 8(2)), and erased
%[2]s later if it is still past it: on main and every branch, by key, as an
erasure request. Never sooner than a year from its date (Rule 8(3)).
`, brand.CLI, branch.RetentionNoticePeriod())
		os.Exit(2)
	}
}

func day(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04")
}

func printRetentionStatus(w io.Writer, st branch.RetentionStatus) {
	set := st.Settings
	switch {
	case set.On:
		fmt.Fprintf(w, "Retention is on (since %s, by %s); notices go to %s, %s before an erasure.\n", day(set.Since), set.By, set.Notify, st.Notice)
	default:
		fmt.Fprintf(w, "Retention is off: nothing is noticed or erased (%s dpdp retention on --notify https://…).\n", brand.CLI)
	}
	if set.LastRun != nil {
		fmt.Fprintf(w, "Last run %s: %s\n", day(*set.LastRun), set.LastSummary)
	}
	if len(st.Tables) == 0 {
		fmt.Fprintln(w, "\nNo table in main's inventory has an entry, so none has a period.")
	} else {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "TABLE\tKEPT\tDATE COLUMN\tARMED\tPAST IT\tUNDATED\tNOTICED")
		for _, t := range st.Tables {
			armed := "no"
			if t.Armed {
				armed = "yes"
			}
			kept := t.Keep.String()
			if t.Raised {
				kept += " (a year, Rule 8(3))"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%d\n", t.Where(), kept, t.Column, armed, t.Due, t.Undated, t.Noticed)
		}
		tw.Flush()
		for _, t := range st.Tables {
			if t.Why != "" {
				fmt.Fprintf(w, "  %s: %s\n", t.Where(), t.Why)
			}
		}
	}
	fmt.Fprintln(w, "\nWhat this cannot claim:")
	for _, l := range st.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
}

func printPreview(w io.Writer, d branch.RetentionDue) {
	fmt.Fprintf(w, "%s.%s: %d row(s) dated by %s before %s are past their period now; %d have no date and are never acted on.\n",
		d.Schema, d.Table, d.Total, d.Column, day(d.Cutoff), d.Undated)
	for _, r := range d.Rows {
		fmt.Fprintf(w, "  %s  dated %s\n", r.Key, day(r.Since))
	}
	if d.Total > len(d.Rows) {
		fmt.Fprintf(w, "  … and %d more\n", d.Total-len(d.Rows))
	}
}

func printRetentionRun(w io.Writer, run branch.RetentionRun) {
	fmt.Fprintf(w, "Retention run at %s: %s\n", day(run.At), run.Summary())
	for _, t := range run.Tables {
		fmt.Fprintf(w, "  %s: %d past the period; %d noticed now, %d waiting, %d renewed, %d erased", t.Table, t.Due, t.Noticed, t.Waiting, t.Renewed, t.Erased)
		if t.Request > 0 {
			fmt.Fprintf(w, " (erasure request #%d)", t.Request)
		}
		fmt.Fprintln(w)
		if t.Error != "" {
			fmt.Fprintf(w, "    %s\n", t.Error)
		}
	}
	for _, n := range run.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
}
