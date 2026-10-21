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

// piiCmd is `fox pii` (points 4.1, 4.2, 4.6): where a branch holds personal
// data, and what a reviewer decided it is.
//
//	fox pii scan [--branch b] [--sample n] [--json]             scan now (Enterprise)
//	fox pii [findings] [--branch b] [--state s] [--json]        what scans have found
//	fox pii show <id> [--branch b] [--json]                     one finding and its decisions
//	fox pii samples <id> [--branch b] [--n 5] [--json]          masked samples to decide by (Enterprise)
//	fox pii mark <id> confirm|reject|reopen [--note "…"] [--branch b]
//	                                                            decide (Enterprise)
//
// `--state suggested` is the review queue.
// A scan reads up to n rows of every table (1,000 unless told), recognises
// identifiers by their names and values, and keeps where it found them, never
// the values. Reading the findings is free in every edition.
func piiCmd(args []string) {
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	ps := positionals(args, "--branch", "--sample", "--state", "--n", "--note")
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
		if st := optValue(args, "--state"); st != "" {
			if st != branch.PIISuggested && st != branch.PIIConfirmed && st != branch.PIIRejected {
				must(fmt.Errorf("--state is suggested, confirmed or rejected, not %q", st))
			}
			kept := rep.Findings[:0]
			for _, f := range rep.Findings {
				if f.State == st {
					kept = append(kept, f)
				}
			}
			rep.Findings = kept
		}
		if hasFlag(args, "--json") {
			printJSON(rep)
			return
		}
		printPII(os.Stdout, rep, false)
	case "show":
		d, err := branch.PersonalDataFinding(b, findingID(ps))
		must(err)
		if hasFlag(args, "--json") {
			printJSON(d)
			return
		}
		printFinding(os.Stdout, d)
	case "samples":
		requireFeature(edition.PersonalData)
		n := 0
		if v := optValue(args, "--n"); v != "" {
			var err error
			if n, err = strconv.Atoi(v); err != nil {
				must(fmt.Errorf("--n is a number of samples, not %q", v))
			}
		}
		// As the operator: at this machine the CLI is the superuser already,
		// and the samples are masked all the same.
		ss, err := branch.PersonalDataSamples(b, findingID(ps), n, "")
		must(err)
		if s := historyStore(); s != nil {
			s.Audit(auth.EvPersonalDataSampled, cliActor(), b, "", ss.Summary())
			s.Close()
		}
		if hasFlag(args, "--json") {
			printJSON(ss)
			return
		}
		fmt.Printf("%s (%s), read as %s; %d value(s) read:\n", ss.Finding.Where(), ss.Finding.Category, ss.As, ss.Read)
		if len(ss.Samples) == 0 {
			fmt.Println("  nothing there to show")
		}
		for _, x := range ss.Samples {
			like := "does not look like one"
			if x.Matches {
				like = "looks like one"
			}
			fmt.Printf("  %-32s %s\n", x.Masked, like)
		}
	case "mark":
		requireFeature(edition.PersonalData)
		if len(ps) < 3 {
			usagePII()
		}
		state := map[string]string{"confirm": branch.PIIConfirmed, "reject": branch.PIIRejected, "reopen": branch.PIISuggested}[ps[2]]
		if state == "" {
			must(fmt.Errorf("a finding is confirmed, rejected or reopened: %s pii mark <id> confirm|reject|reopen", brand.CLI))
		}
		me := cliActor()
		d, err := branch.MarkPersonalData(b, findingID(ps), state, optValue(args, "--note"), me)
		must(err)
		if s := historyStore(); s != nil {
			s.Audit(auth.EvPersonalDataMarked, me, b, "", d.Finding.MarkSummary())
			s.Close()
		}
		fmt.Printf("Finding %d, %s (%s): %s.\n", d.Finding.ID, d.Finding.Where(), d.Finding.Category, d.Finding.State)
	default:
		usagePII()
	}
}

func usagePII() {
	fmt.Fprintf(os.Stderr, "usage: %[1]s pii scan [--branch b] [--sample n] [--json]\n"+
		"       %[1]s pii [findings] [--branch b] [--state suggested|confirmed|rejected] [--json]\n"+
		"       %[1]s pii show <id> [--branch b] [--json]\n"+
		"       %[1]s pii samples <id> [--branch b] [--n 5] [--json]\n"+
		"       %[1]s pii mark <id> confirm|reject|reopen [--note \"…\"] [--branch b]\n", brand.CLI)
	os.Exit(2)
}

// findingID reads the finding's number, the second positional.
func findingID(ps []string) int64 {
	if len(ps) < 2 {
		usagePII()
	}
	id, err := strconv.ParseInt(ps[1], 10, 64)
	if err != nil || id < 1 {
		must(fmt.Errorf("a finding is named by its number (the ID column of %s pii), not %q", brand.CLI, ps[1]))
	}
	return id
}

func printFinding(w io.Writer, d branch.PIIFindingDetail) {
	f := d.Finding
	fmt.Fprintf(w, "Finding %d: %s\n  what        %s, %s confidence, found by %s\n  why         %s\n  state       %s\n",
		f.ID, f.Where(), f.Category, f.Confidence, f.Rule, f.Why, f.State)
	if len(d.Decisions) == 0 {
		fmt.Fprintln(w, "  decisions   none yet")
		return
	}
	fmt.Fprintln(w, "  decisions")
	for _, x := range d.Decisions {
		note := ""
		if x.Note != "" {
			note = ": " + x.Note
		}
		fmt.Fprintf(w, "    %s  %-9s by %s%s\n", x.At.Local().Format("2 Jan 2006 15:04"), x.State, x.Actor, note)
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
		fmt.Fprintln(tw, "ID\tWHERE\tCATEGORY\tCONFIDENCE\tMATCHED\tFOUND BY\tSTATE")
		for _, f := range rep.Findings {
			where := f.Where()
			matched := "-"
			if f.Sampled > 0 {
				matched = fmt.Sprintf("%d/%d", f.Matched, f.Sampled)
			}
			state := f.State
			if f.LastScan != s.ID {
				state += " (not seen in the latest scan)"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", f.ID, where, f.Category, f.Confidence, matched, f.Rule, state)
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
