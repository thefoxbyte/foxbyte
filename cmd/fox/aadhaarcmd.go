// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// aadhaarCmd is `fox pii aadhaar` (point 4.5): which person's Aadhaar is
// exposed in a branch, where, and since when.
//
//	fox pii aadhaar run [--branch b] [--table-timeout 5m] [--logs] [--json]   read every row now (Enterprise)
//	fox pii aadhaar [--branch b] [--json]                                     the latest report
//	fox pii aadhaar places [--person n] [--column s.t.c] [--gone] [--limit n] [--json]
//	fox pii aadhaar places --logs [--source s] [--person n] [--gone] [--limit n] [--json]
//
// A number is shown as UIDAI masks it, XXXX XXXX 1234, and is kept no other
// way. Reading the report is free; a run is Enterprise and is in the security
// log with its counts. The logs part (--logs) is the machine's operator's, as
// everyone's history is (`fox history --user`): the CLI reads it always.
func aadhaarCmd(args []string, b string, ps []string) {
	sub := "report"
	if len(ps) > 0 {
		sub = ps[0]
	}
	switch sub {
	case "run":
		requireFeature(edition.PersonalData)
		st := historyStore()
		if st != nil {
			defer st.Close()
		}
		o := branch.AadhaarRunOptions{Actor: cliActor(), Logs: hasFlag(args, "--logs"), Store: st}
		if v := optValue(args, "--table-timeout"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				must(fmt.Errorf("--table-timeout is a duration (90s, 5m), not %q", v))
			}
			o.TableTimeout = d
		}
		rep, err := branch.RunAadhaarExposure(b, o)
		must(err)
		if st != nil {
			st.Audit(auth.EvAadhaarExposure, o.Actor, b, "", rep.Summary())
		}
		if hasFlag(args, "--json") {
			printJSON(rep)
			return
		}
		printAadhaar(os.Stdout, rep)
	case "report":
		st := historyStore()
		if st != nil {
			defer st.Close()
		}
		rep, err := branch.AadhaarExposureFor(b, st)
		must(err)
		if hasFlag(args, "--json") {
			printJSON(rep)
			return
		}
		printAadhaar(os.Stdout, rep)
	case "places":
		if hasFlag(args, "--logs") || optValue(args, "--source") != "" {
			aadhaarLogPlacesCmd(args, b)
			return
		}
		f := branch.AadhaarPlaceFilter{Gone: hasFlag(args, "--gone")}
		for flag, to := range map[string]*int{"--person": &f.Person, "--limit": &f.Limit} {
			if v := optValue(args, flag); v != "" {
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 {
					must(fmt.Errorf("%s is a number, not %q", flag, v))
				}
				*to = n
			}
		}
		if c := optValue(args, "--column"); c != "" {
			w, err := branch.ParseAadhaarWhere(c)
			must(err)
			f.Where = w
		}
		places, err := branch.AadhaarPlaces(b, f)
		must(err)
		if hasFlag(args, "--json") {
			printJSON(places)
			return
		}
		printAadhaarPlaces(os.Stdout, places, f.Gone, b)
	default:
		usagePII()
	}
}

// aadhaarLogPlacesCmd is `fox pii aadhaar places --logs`: the log entries of
// the branch's latest logs run that hold a number, or no longer do.
func aadhaarLogPlacesCmd(args []string, b string) {
	st := historyStore()
	if st == nil {
		must(fmt.Errorf("the install's store could not be opened; the logs part is kept there"))
	}
	defer st.Close()
	f := auth.AadhaarLogFilter{Gone: hasFlag(args, "--gone"), Source: optValue(args, "--source")}
	for flag, to := range map[string]*int{"--person": &f.Person, "--limit": &f.Limit} {
		if v := optValue(args, flag); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				must(fmt.Errorf("%s is a number, not %q", flag, v))
			}
			*to = n
		}
	}
	places, err := branch.AadhaarLogPlaces(b, st, f)
	must(err)
	if hasFlag(args, "--json") {
		printJSON(places)
		return
	}
	printAadhaarLogPlaces(os.Stdout, places, f.Gone, b)
}

func printAadhaarLogPlaces(w io.Writer, places []auth.AadhaarLogPlace, gone bool, b string) {
	if len(places) == 0 {
		if gone {
			fmt.Fprintf(w, "No log entry on %s has gone since an earlier run.\n", b)
		} else {
			fmt.Fprintf(w, "No log entries on %s match.\n", b)
		}
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if gone {
		fmt.Fprintln(tw, "NUMBER\tLOG\tENTRY\tBY\tAT\tLAST SEEN")
	} else {
		fmt.Fprintln(tw, "PERSON\tNUMBER\tLOG\tENTRY\tBY\tAT")
	}
	for _, p := range places {
		entry := strconv.FormatInt(p.Entry, 10)
		if p.Field != "" {
			entry += " (" + p.Field + ")"
		}
		by := p.Actor
		if by == "" {
			by = "–"
		}
		at := p.At.Local().Format("2006-01-02 15:04")
		if gone {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p.Masked, auth.AadhaarLogSourceName(p.Source), entry, by, at, shortDay(p.LastSeen))
			continue
		}
		person := strconv.Itoa(p.Person)
		if p.Person == 0 {
			person = "–"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", person, p.Masked, auth.AadhaarLogSourceName(p.Source), entry, by, at)
	}
	tw.Flush()
}

// printAadhaarLogs is the report's logs part.
func printAadhaarLogs(w io.Writer, rep branch.AadhaarReport) {
	l := rep.Logs
	r := l.Run
	fmt.Fprintf(w, "\nThe logs (admins only), read with run %d: %d query history entr(ies), %d audit statement text(s), %d Blackbox entr(ies).\n",
		r.BranchRun, r.Read[auth.AadhaarLogHistory], r.Read[auth.AadhaarLogAudit], r.Read[auth.AadhaarLogBlackbox])
	fmt.Fprintf(w, "%d number(s) found, %d distinct, %d also in the tables; %d place(s) kept.\n", r.Numbers, r.People, r.Linked, r.Listed)
	for _, s := range r.Skipped {
		fmt.Fprintf(w, "  not read: %s (%s)\n", auth.AadhaarLogSourceName(s.Source), s.Reason)
	}
	if len(l.Sources) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  LOG\tENTRIES\tPLACES\tSINCE")
		for _, c := range l.Sources {
			since := "–"
			if c.Since != nil {
				since = shortDay(*c.Since)
			}
			fmt.Fprintf(tw, "  %s\t%d\t%d\t%s\n", auth.AadhaarLogSourceName(c.Source), c.Entries, c.Places, since)
		}
		tw.Flush()
		fmt.Fprintf(w, "The entries: %s pii aadhaar places --logs [--source history|audit|blackbox] --branch %s\n", brand.CLI, rep.Branch)
	}
	if !l.Linked && len(l.People) > 0 {
		fmt.Fprintf(w, "\nRead with run %d, before the latest, so its people are numbered apart:\n", r.BranchRun)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  PERSON\tNUMBER\tPLACES\tSINCE\tWHERE")
		for _, p := range l.People {
			fmt.Fprintf(tw, "  %d\t%s\t%d\t%s\t%s\n", p.Person, p.Masked, p.Places, shortDay(p.Since), strings.Join(p.Where, ", "))
		}
		tw.Flush()
	}
	if l.Gone > 0 {
		fmt.Fprintf(w, "%d log place(s) earlier runs found are no longer there: %s pii aadhaar places --logs --gone --branch %s\n", l.Gone, brand.CLI, rep.Branch)
	}
	if len(r.Limits) > 0 {
		fmt.Fprintln(w, "What the logs part cannot claim:")
		for _, x := range r.Limits {
			fmt.Fprintf(w, "  - %s\n", x)
		}
	}
}

func shortDay(t time.Time) string { return t.Local().Format("2006-01-02") }

func printAadhaar(w io.Writer, rep branch.AadhaarReport) {
	r := rep.Run
	if r == nil {
		fmt.Fprintf(w, "No Aadhaar exposure report on %s yet: `%s pii aadhaar run --branch %s` reads it (Enterprise).\n", rep.Branch, brand.CLI, rep.Branch)
		return
	}
	by := ""
	if r.Actor != "" {
		by = " by " + r.Actor
	}
	fmt.Fprintf(w, "Aadhaar exposure on %s: run %d, %s%s.\n", rep.Branch, r.ID, r.Finished.Local().Format("2006-01-02 15:04"), by)
	fmt.Fprintf(w, "%d table(s), %d column(s) read; %d row(s) held twelve digits in its shape. %d number(s) found, %d distinct; %d place(s) kept.\n",
		r.Tables, r.Columns, r.Rows, r.Numbers, r.People, r.Listed)
	for _, s := range r.Skipped {
		fmt.Fprintf(w, "  not read: %s (%s)\n", s.Object, s.Reason)
	}
	if len(rep.Columns) == 0 {
		fmt.Fprintln(w, "\nNo Aadhaar number was found in the tables read.")
	} else {
		fmt.Fprintln(w, "\nBy column")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  COLUMN\tNUMBERS\tROWS\tKEPT\tSINCE")
		for _, c := range rep.Columns {
			kept := strconv.Itoa(c.Listed)
			if c.Capped {
				kept += " (first)"
			}
			since := "–"
			if c.Since != nil {
				since = shortDay(*c.Since)
			}
			fmt.Fprintf(tw, "  %s\t%d\t%d\t%s\t%s\n", c.Where(), c.Numbers, c.Rows, kept, since)
		}
		tw.Flush()
	}
	if len(rep.People) > 0 {
		more := ""
		if rep.PeopleListed > len(rep.People) {
			more = fmt.Sprintf(", the first %d of %d", len(rep.People), rep.PeopleListed)
		}
		fmt.Fprintf(w, "\nBy person (the most places first%s)\n", more)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  PERSON\tNUMBER\tPLACES\tSINCE\tWHERE")
		for _, p := range rep.People {
			fmt.Fprintf(tw, "  %d\t%s\t%d\t%s\t%s\n", p.Person, p.Masked, p.Places, shortDay(p.Since), strings.Join(p.Where, ", "))
		}
		tw.Flush()
		fmt.Fprintf(w, "One person's rows: %s pii aadhaar places --person <n> --branch %s\n", brand.CLI, rep.Branch)
	}
	if rep.Gone > 0 {
		fmt.Fprintf(w, "\n%d place(s) earlier runs found are no longer there: %s pii aadhaar places --gone --branch %s\n", rep.Gone, brand.CLI, rep.Branch)
	}
	if len(r.Limits) > 0 {
		fmt.Fprintln(w, "\nWhat this report cannot claim:")
		for _, l := range r.Limits {
			fmt.Fprintf(w, "  - %s\n", l)
		}
	}
	if rep.Logs != nil {
		printAadhaarLogs(w, rep)
	}
}

func printAadhaarPlaces(w io.Writer, places []branch.AadhaarPlace, gone bool, b string) {
	if len(places) == 0 {
		if gone {
			fmt.Fprintf(w, "No place on %s has gone since an earlier run.\n", b)
		} else {
			fmt.Fprintf(w, "No places on %s match.\n", b)
		}
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if gone {
		fmt.Fprintln(tw, "NUMBER\tWHERE\tROW\tSINCE\tLAST SEEN")
		for _, p := range places {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Masked, aadhaarCol(p), p.Row, shortDay(p.Since), shortDay(p.LastSeen))
		}
	} else {
		fmt.Fprintln(tw, "PERSON\tNUMBER\tWHERE\tROW\tSINCE")
		for _, p := range places {
			person := strconv.Itoa(p.Person)
			if p.Person == 0 {
				person = "–"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", person, p.Masked, aadhaarCol(p), p.Row, shortDay(p.Since))
		}
	}
	tw.Flush()
}

func aadhaarCol(p branch.AadhaarPlace) string {
	return branch.AadhaarColumn{Schema: p.Schema, Table: p.Table, Column: p.Column, Path: p.Path}.Where()
}
