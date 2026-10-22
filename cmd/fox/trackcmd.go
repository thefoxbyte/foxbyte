// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// trackCmd is `fox track` (points 5.1, 5.2 and 6.1): who changed each row of
// a table, whom for, and when, kept by Postgres.
//
//	fox track [--branch b]                         what is tracked, and whether new tables are
//	fox track <table> [--branch b] [--label-existing]
//	          [--created c] [--updated u] [--by col] [--for col]
//	          [--no-created] [--no-updated] [--no-by] [--no-for]
//	                                               start tracking a table; on one tracked
//	                                               already, add the for column it lacks
//	fox track <table> --off                        stop; the columns and what they hold stay
//	fox track --new on|off [--created …]           track every table made from now on
//
// <table> is a name or schema.name. Opt-in, because adding columns to a table
// that exists breaks an INSERT written without a column list.
func trackCmd(args []string) {
	b := optValue(args, "--branch")
	if b == "" {
		b = "main"
	}
	o := trackOptions(args)
	ps := positionals(args, "--branch", "--created", "--updated", "--by", "--for", "--new")
	me := cliActor()
	switch {
	case optValue(args, "--new") != "":
		v := optValue(args, "--new")
		if v != "on" && v != "off" {
			must(fmt.Errorf("--new is on or off, not %q", v))
		}
		must(branch.SetTrackNew(b, v == "on", o, me, "fox track"))
		auditTracking(me, b, "new tables "+v)
		if v == "on" {
			fmt.Printf("Every table made on %s from now on is tracked (%s). Tables that exist are not changed.\n", b, trackCols(o))
		} else {
			fmt.Printf("New tables on %s are no longer tracked. Tables already tracked stay so.\n", b)
		}
	case len(ps) == 0:
		t, err := branch.TrackingOf(b)
		must(err)
		printTracking(os.Stdout, t, b)
	default:
		schema, table := splitTableName(strings.Join(ps, " "))
		if hasFlag(args, "--off") {
			must(branch.UntrackTable(b, schema, table, me, "fox track"))
			auditTracking(me, b, "stopped tracking "+schema+"."+table)
			fmt.Printf("%s.%s is no longer tracked. Its columns, and what they hold, are still there.\n", schema, table)
			return
		}
		// Whether it was tracked already decides what tracking it did: a
		// table tracked before only gains the for column.
		was, _ := trackedAs(b, schema, table)
		must(branch.TrackTable(b, schema, table, o, me, "fox track"))
		now, ok := trackedAs(b, schema, table)
		switch {
		case was != nil && ok && was.For == "" && now.For != "":
			auditTracking(me, b, "added "+now.For+" to the tracking of "+schema+"."+table)
			fmt.Printf("%s.%s was tracked already, and now keeps %s too: whom each row was changed for, where an application said so. Its rows are left empty there until they next change.\n",
				schema, table, now.For)
		case was != nil:
			fmt.Printf("%s.%s is tracked already: %s. Nothing was changed.\n", schema, table,
				trackCols(branch.TrackOptions{Created: was.Created, Updated: was.Updated, By: was.By, For: was.For}))
		default:
			auditTracking(me, b, "started tracking "+schema+"."+table)
			existing := "Rows already there are left empty."
			if o.LabelExisting {
				existing = "Rows already there are labelled with this moment."
			}
			fmt.Printf("%s.%s is tracked: %s. %s\n", schema, table, trackCols(o), existing)
		}
	}
}

// trackedAs is how a table is tracked, or nil when it is not.
func trackedAs(b, schema, table string) (*branch.TrackedTable, bool) {
	t, err := branch.TrackingOf(b)
	if err != nil {
		return nil, false
	}
	for i := range t.Tables {
		if t.Tables[i].Schema == schema && t.Tables[i].Name == table {
			return &t.Tables[i], true
		}
	}
	return nil, true
}

// trackOptions reads the column names, the defaults unless changed or dropped.
func trackOptions(args []string) branch.TrackOptions {
	o := branch.DefaultTrackOptions
	for _, f := range []struct {
		flag, no string
		to       *string
	}{{"--created", "--no-created", &o.Created}, {"--updated", "--no-updated", &o.Updated}, {"--by", "--no-by", &o.By},
		{"--for", "--no-for", &o.For}} {
		if v := optValue(args, f.flag); v != "" {
			*f.to = v
		}
		if hasFlag(args, f.no) {
			*f.to = ""
		}
	}
	o.LabelExisting = hasFlag(args, "--label-existing")
	return o
}

// splitTableName reads schema.table, or a table in public.
func splitTableName(s string) (string, string) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "."); i > 0 && !strings.HasPrefix(s, `"`) {
		return s[:i], s[i+1:]
	}
	return "public", strings.Trim(s, `"`)
}

func trackCols(o branch.TrackOptions) string {
	var c []string
	if o.Created != "" {
		c = append(c, o.Created+" (when made)")
	}
	if o.Updated != "" {
		c = append(c, o.Updated+" (when last changed)")
	}
	if o.By != "" {
		c = append(c, o.By+" (who last changed it)")
	}
	if o.For != "" {
		c = append(c, o.For+" (whom for, where an application said so)")
	}
	return strings.Join(c, ", ")
}

func printTracking(w io.Writer, t branch.Tracking, b string) {
	if t.Settings.TrackNew {
		fmt.Fprintf(w, "New tables on %s are tracked as they are made.\n", b)
	} else {
		fmt.Fprintf(w, "New tables on %s are not tracked (%s track --new on).\n", b, brand.CLI)
	}
	if len(t.Tables) == 0 {
		fmt.Fprintf(w, "No table is tracked. Start one with %s track <table>.\n", brand.CLI)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TABLE\tCREATED\tUPDATED\tBY\tFOR")
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	for _, x := range t.Tables {
		fmt.Fprintf(tw, "%s.%s\t%s\t%s\t%s\t%s\n", x.Schema, x.Name, dash(x.Created), dash(x.Updated), dash(x.By), dash(x.For))
	}
	tw.Flush()
}

// auditTracking records who changed tracking in the security log.
func auditTracking(actor, branchName, detail string) {
	if s := historyStore(); s != nil {
		s.Audit(auth.EvTrackingChanged, actor, branchName, "", detail)
		s.Close()
	}
}
