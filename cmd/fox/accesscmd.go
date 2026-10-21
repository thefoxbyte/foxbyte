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

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// accessCmd is `fox access` (point 4.8).
//
//	fox access review [--dormant 90] [--json] [--csv accounts|keys|branches]
//
// The access review report: every account, what it can reach and with which
// credentials, who may override the guardrails where, and who has gone quiet.
// At this machine the operator is an admin already, as for `fox user list`.
func accessCmd(args []string) {
	if len(args) == 0 || args[0] != "review" {
		fmt.Fprintf(os.Stderr, "usage: %s access review [--dormant 90] [--json] [--csv accounts|keys|branches]\n", brand.CLI)
		os.Exit(2)
	}
	requireFeature(edition.AccessReview)
	o := access.ReviewOptions{}
	if v := optValue(args, "--dormant"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			must(fmt.Errorf("--dormant is 1 to 3650 days, not %q", v))
		}
		o.DormantDays = n
	}
	s := historyStore()
	if s == nil {
		must(fmt.Errorf("the account store could not be opened"))
	}
	defer s.Close()
	rep, err := access.ProduceReview(s, o)
	must(err)
	s.Audit(auth.EvAccessReviewed, cliActor(), "", "", rep.LogLine())
	switch {
	case hasFlag(args, "--json"):
		printJSON(rep)
	case hasFlag(args, "--csv"):
		section := optValue(args, "--csv")
		if section == "" || strings.HasPrefix(section, "--") {
			section = "accounts"
		}
		must(rep.CSV(section, os.Stdout))
	default:
		printReview(os.Stdout, rep)
	}
}

func printReview(w io.Writer, r access.Review) {
	day := func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		return t.Local().Format("2 Jan 2006")
	}
	yes := func(b bool, word string) string {
		if b {
			return word
		}
		return "-"
	}
	list := func(xs []string) string {
		if len(xs) == 0 {
			return "-"
		}
		return strings.Join(xs, ", ")
	}
	sm := r.Summary
	fmt.Fprintf(w, "Access review, %s (dormant after %d days)\n", r.Generated.Local().Format("2 Jan 2006 15:04"), r.DormantDays)
	fmt.Fprintf(w, "  %d account(s): %d admin, %d dormant · %d key(s): %d agent, %d stale · %d branch(es): %d unowned\n",
		sm.Accounts, sm.Admins, sm.Dormant, sm.Keys, sm.AgentKeys, sm.StaleKeys, sm.Branches, sm.Unowned)

	fmt.Fprintln(w, "\nACCOUNTS")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "EMAIL\tREACHES\tOVERRIDE ON\tKEYS\tLAST ACTIVE\tDORMANT")
	for _, a := range r.Accounts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", a.Email, a.Reaches, list(a.OverrideOn), a.Keys, day(a.LastActive), yes(a.Dormant, "dormant"))
	}
	tw.Flush()

	fmt.Fprintln(w, "\nKEYS")
	if len(r.Keys) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PREFIX\tNAME\tOWNER\tKIND\tREACH\tAGE\tLAST USED\tSTALE")
		for _, k := range r.Keys {
			fmt.Fprintf(tw, "%s…\t%s\t%s\t%s\t%s\t%dd\t%s\t%s\n", k.Prefix, k.Name, k.Owner, k.Kind, k.Reach, k.AgeDays, day(k.LastUsed),
				yes(k.Stale, "stale: "+k.Why))
		}
		tw.Flush()
	}

	fmt.Fprintln(w, "\nBRANCHES")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "BRANCH\tSTATE\tOWNER\tMAY OVERRIDE ITS GUARDRAILS")
	for _, b := range r.Branches {
		owner := b.Owner
		if owner == "" {
			owner = "-"
			if b.Name == "main" {
				owner = "(the install)"
			}
		}
		admins := list(b.Admins)
		if !b.Asked {
			admins = "(not running: not read)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", b.Name, b.State, owner, admins)
	}
	tw.Flush()

	fmt.Fprintln(w, "\nWhat this report cannot claim:")
	for _, l := range r.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
	fmt.Fprintf(w, "\nThe tables as CSV: %s access review --csv accounts|keys|branches\n", brand.CLI)
}
