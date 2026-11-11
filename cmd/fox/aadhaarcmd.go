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
//	fox pii aadhaar run [--branch b] [--table-timeout 5m] [--json]   read every row now (Enterprise)
//	fox pii aadhaar [--branch b] [--json]                            the latest report
//	fox pii aadhaar places [--person n] [--column s.t.c] [--gone] [--limit n] [--json]
//
// A number is shown as UIDAI masks it, XXXX XXXX 1234, and is kept no other
// way. Reading the report is free; a run is Enterprise and is in the security
// log with its counts.
func aadhaarCmd(args []string, b string, ps []string) {
	sub := "report"
	if len(ps) > 0 {
		sub = ps[0]
	}
	switch sub {
	case "run":
		requireFeature(edition.PersonalData)
		o := branch.AadhaarRunOptions{Actor: cliActor()}
		if v := optValue(args, "--table-timeout"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				must(fmt.Errorf("--table-timeout is a duration (90s, 5m), not %q", v))
			}
			o.TableTimeout = d
		}
		rep, err := branch.RunAadhaarExposure(b, o)
		must(err)
		if s := historyStore(); s != nil {
			s.Audit(auth.EvAadhaarExposure, o.Actor, b, "", rep.Summary())
			s.Close()
		}
		if hasFlag(args, "--json") {
			printJSON(rep)
			return
		}
		printAadhaar(os.Stdout, rep)
	case "report":
		rep, err := branch.AadhaarExposure(b)
		must(err)
		if hasFlag(args, "--json") {
			printJSON(rep)
			return
		}
		printAadhaar(os.Stdout, rep)
	case "places":
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
