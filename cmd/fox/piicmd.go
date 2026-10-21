// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// piiCmd is `fox pii` (point 4.1): where a branch holds personal data.
//
//	fox pii scan [--branch b] [--sample n] [--json]   scan now (Enterprise)
//	fox pii [findings] [--branch b] [--json]          what scans have found
//
// A scan reads up to n rows of every table (1,000 unless told), recognises
// identifiers by their names and values, and keeps where it found them, never
// the values. Reading the findings is free in every edition.
func piiCmd(args []string) {
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	ps := positionals(args, "--branch", "--sample")
	sub := "findings"
	if len(ps) > 0 {
		sub = ps[0]
	}
	switch sub {
	case "scan":
		requireFeature(edition.PersonalData)
		o := branch.PIIScanOptions{Actor: cliActor()}
		if v := optValue(args, "--sample"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				must(fmt.Errorf("--sample is a number of rows, not %q", v))
			}
			o.Sample = n
		}
		rep, err := branch.ScanPersonalData(b, o)
		must(err)
		if s := historyStore(); s != nil {
			s.Audit(auth.EvPersonalDataScanned, o.Actor, b, "", rep.Summary())
			s.Close()
		}
		if hasFlag(args, "--json") {
			printJSON(rep)
			return
		}
		printPII(os.Stdout, rep, true)
	case "findings":
		rep, err := branch.PersonalDataFindings(b)
		must(err)
		if hasFlag(args, "--json") {
			printJSON(rep)
			return
		}
		printPII(os.Stdout, rep, false)
	default:
		fmt.Fprintf(os.Stderr, "usage: %s pii scan [--branch b] [--sample n] [--json]\n       %s pii [findings] [--branch b] [--json]\n", brand.CLI, brand.CLI)
		os.Exit(2)
	}
}

func printPII(w io.Writer, rep branch.PIIReport, justScanned bool) {
	s := rep.Scan
	if s == nil {
		fmt.Fprintf(w, "%s has not been scanned. Scan it with: %s pii scan --branch %s\n", rep.Branch, brand.CLI, rep.Branch)
		return
	}
	when := "Last scanned " + s.Finished.Local().Format("2 Jan 2006 15:04")
	if justScanned {
		when = "Scanned"
	}
	fmt.Fprintf(w, "%s %s: %d table(s), %d column(s) read, up to %d rows each; %d skipped.\n",
		when, rep.Branch, s.Tables, s.Columns, s.Sample, len(s.Skipped))
	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "\nNothing recognised as personal data.")
	} else {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "WHERE\tCATEGORY\tCONFIDENCE\tMATCHED\tFOUND BY\tSTATE")
		for _, f := range rep.Findings {
			where := f.Schema + "." + f.Table + "." + f.Column
			if f.Path != "" {
				where += " " + f.Path
			}
			matched := "-"
			if f.Sampled > 0 {
				matched = fmt.Sprintf("%d/%d", f.Matched, f.Sampled)
			}
			state := f.State
			if f.LastScan != s.ID {
				state += " (not seen in the latest scan)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", where, f.Category, f.Confidence, matched, f.Rule, state)
		}
		tw.Flush()
	}
	if len(s.Skipped) > 0 {
		fmt.Fprintln(w, "\nNot read:")
		for _, k := range s.Skipped {
			fmt.Fprintf(w, "  %s: %s\n", k.Object, k.Reason)
		}
	}
	fmt.Fprintln(w, "\nWhat this cannot claim:")
	for _, l := range s.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
}
