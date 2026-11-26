// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// erasureCmd is `fox dpdp erase` (point 11.2, F4): erasing one person's
// personal data. Gate 1 step 1 erases main.
//
//	fox dpdp erase new [--note "…"] [--event account_closed=2025-03-31]   (Enterprise)
//	fox dpdp erase plan <id>                                            (Enterprise)
//	fox dpdp erase apply <id> [--yes] [--branch b]                      (Enterprise)
//	fox dpdp erase rewrite <id> [--branch b] [--table schema.table]     (Enterprise)
//	fox dpdp erase status <id> [--json]
//	fox dpdp erase withdraw <id>                                        (Enterprise)
//	fox dpdp erase list [--json]
//	fox dpdp erase show <id> [--json]
//
// The values the person is known by are read from the terminal, or from
// standard input, one a line ("email:asha@example.com", or the value alone to
// be recognised by its shape), never from the command line, where the shell's
// history and the process list would keep them. A request keeps none of them:
// applying asks for them again.
func erasureCmd(args []string) {
	ps := positionals(args, "--note", "--event", "--table", "--branch")
	onBranch := optValue(args, "--branch")
	if onBranch == "main" {
		onBranch = ""
	}
	sub := ""
	if len(ps) > 0 {
		sub = ps[0]
	}
	id := func() int64 {
		if len(ps) < 2 {
			fmt.Fprintf(os.Stderr, "usage: %s dpdp erase %s <request>\n", brand.CLI, sub)
			os.Exit(2)
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(ps[1], "#"), 10, 64)
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "%q is not a request's number\n", ps[1])
			os.Exit(2)
		}
		return n
	}
	switch sub {
	case "new":
		requireFeature(edition.DPDP)
		events := map[string]string{}
		for _, e := range optValues(args, "--event") {
			k, v, ok := strings.Cut(e, "=")
			if !ok {
				die(fmt.Errorf("--event is event=YYYY-MM-DD, such as account_closed=2025-03-31, not %q", e))
			}
			events[strings.ReplaceAll(strings.TrimSpace(k), "-", "_")] = strings.TrimSpace(v)
		}
		values := readErasureValues("The values the person is known by")
		s := openStore()
		defer s.Close()
		v, err := branch.NewErasure(s, "main", values, events, optValue(args, "--note"), cliActor())
		must(err)
		s.Audit(auth.EvErasurePlanned, cliActor(), v.Branch, "", fmt.Sprintf("request #%d: %s", v.ID, v.Plan.Summary()))
		printErasureOr(args, v)
		next(v)
	case "plan":
		requireFeature(edition.DPDP)
		n := id()
		values := readErasureValues(fmt.Sprintf("The values request #%d was made for", n))
		s := openStore()
		defer s.Close()
		v, err := branch.ReplanErasure(s, n, values, cliActor())
		must(err)
		s.Audit(auth.EvErasurePlanned, cliActor(), v.Branch, "", fmt.Sprintf("request #%d planned again: %s", v.ID, v.Plan.Summary()))
		printErasureOr(args, v)
		next(v)
	case "apply":
		requireFeature(edition.DPDP)
		n := id()
		s := openStore()
		defer s.Close()
		cur, err := branch.GetErasure(s, n)
		must(err)
		where := cur.Branch + " and every branch"
		if onBranch != "" {
			where = onBranch
		}
		if !hasFlag(args, "--yes") {
			if !isTerminal(os.Stdin) {
				die(fmt.Errorf("applying erases %s's rows for good; say --yes to apply without being asked", where))
			}
			printErasure(os.Stdout, cur)
		}
		values := readErasureValues(fmt.Sprintf("The values request #%d was made for, again", n))
		if !hasFlag(args, "--yes") {
			fmt.Printf("Apply request #%d to %s? It cannot be undone. Type the request's number to apply: ", n, where)
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimPrefix(strings.TrimSpace(line), "#") != strconv.FormatInt(n, 10) {
				fmt.Println("Not applied.")
				return
			}
		}
		if onBranch != "" {
			v, err := branch.ApplyErasureBranch(s, n, onBranch, values, cliActor())
			if err == nil || errors.Is(err, branch.ErrErasurePlanChanged) {
				auditBranches(s, v, onBranch) // what this apply did; a refusal did nothing
			}
			if errors.Is(err, branch.ErrErasurePlanChanged) {
				printErasureBranch(os.Stdout, v, onBranch)
				die(fmt.Errorf("nothing was applied to %s: %w. Review its plan above, then apply again", onBranch, err))
			}
			must(err)
			printErasureOr(args, v)
			return
		}
		v, err := branch.ApplyErasure(s, n, values, cliActor())
		if errors.Is(err, branch.ErrErasurePlanChanged) {
			s.Audit(auth.EvErasurePlanned, cliActor(), v.Branch, "", fmt.Sprintf("request #%d planned again at apply: %s", v.ID, v.Plan.Summary()))
			printErasure(os.Stdout, v)
			die(fmt.Errorf("nothing was applied: %w. Review the plan above, then apply again", err))
		}
		must(err)
		s.Audit(auth.EvErasureApplied, cliActor(), v.Branch, "", appliedSummary(v))
		auditBranches(s, v, "")
		printErasureOr(args, v)
	case "rewrite":
		requireFeature(edition.DPDP)
		n := id()
		s := openStore()
		defer s.Close()
		var only []string
		for _, t := range optValues(args, "--table") {
			if !strings.Contains(t, ".") {
				t = "public." + t
			}
			only = append(only, t)
		}
		v, err := branch.RewriteErasureOn(s, n, onBranch, only, cliActor())
		must(err)
		s.Audit(auth.EvErasureRewritten, cliActor(), v.Branch, "", fmt.Sprintf("request #%d: %s", v.ID, rewriteSummary(v)))
		printErasureOr(args, v)
	case "withdraw":
		requireFeature(edition.DPDP)
		n := id()
		s := openStore()
		defer s.Close()
		v, err := branch.WithdrawErasure(s, n, cliActor())
		must(err)
		s.Audit(auth.EvErasureWithdrawn, cliActor(), v.Branch, "", fmt.Sprintf("request #%d withdrawn", v.ID))
		fmt.Printf("request #%d withdrawn; nothing was applied\n", v.ID)
	case "list":
		s := openStore()
		defer s.Close()
		vs, err := branch.ListErasures(s)
		must(err)
		if hasFlag(args, "--json") {
			printJSON(vs)
			return
		}
		if len(vs) == 0 {
			fmt.Printf("no erasure requests; %s dpdp erase new makes one\n", brand.CLI)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "#\tSTATE\tBRANCH\tVALUES\tROWS\tMADE\tBY")
		for _, v := range vs {
			rows := strconv.Itoa(v.Plan.Rows)
			if v.Result != nil {
				rows = strconv.Itoa(v.Result.Rows) + " changed"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", v.ID, v.State, v.Branch, refText(v.Refs), rows,
				v.Created.Local().Format("2006-01-02 15:04"), v.CreatedBy)
		}
		tw.Flush()
	case "show", "status":
		s := openStore()
		defer s.Close()
		v, err := branch.GetErasure(s, id())
		must(err)
		if onBranch != "" && !hasFlag(args, "--json") {
			printErasureBranch(os.Stdout, v, onBranch)
			return
		}
		printErasureOr(args, v)
	default:
		fmt.Fprintf(os.Stderr, `usage:
  %[1]s dpdp erase new [--note "…"] [--event account_closed=YYYY-MM-DD]   make a request, and show its plan
  %[1]s dpdp erase plan <request>                                      plan it again
  %[1]s dpdp erase apply <request> [--yes]                             apply it to main and every branch
  %[1]s dpdp erase apply <request> --branch <b> [--yes]                apply it to a branch it skipped
  %[1]s dpdp erase rewrite <request> [--branch b] [--table schema.table]   rewrite the tables left for later
  %[1]s dpdp erase status <request> [--branch b] [--json]              the branches, and those to remake or delete
  %[1]s dpdp erase withdraw <request>                                  close a request without applying it
  %[1]s dpdp erase list [--json]
  %[1]s dpdp erase show <request> [--json]

The values are read from the terminal or standard input, one a line, as
category:value (email:asha@example.com, mobile:98765 43210) or the value alone.
A request keeps only each value's last four characters, so plan and apply ask
for them again.
`, brand.CLI)
		os.Exit(2)
	}
}

// optValues is every value given for a flag that may be repeated.
func optValues(args []string, flag string) []string {
	var out []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			out = append(out, args[i+1])
		}
	}
	return out
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// readErasureValues reads the person's values, one a line, until a blank
// line or the end of input.
func readErasureValues(prompt string) []branch.ErasureValue {
	term := isTerminal(os.Stdin)
	if term {
		fmt.Printf("%s, one a line (category:value, or the value alone); a blank line ends them:\n", prompt)
	}
	in := bufio.NewReader(io.LimitReader(os.Stdin, 64<<10))
	var out []branch.ErasureValue
	for {
		if term {
			fmt.Print("  > ")
		}
		line, err := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			if term || err != nil {
				break
			}
			continue
		}
		out = append(out, branch.ParseErasureValue(line))
		if err != nil {
			break
		}
		if len(out) > 50 {
			die(fmt.Errorf("at most 50 values a request"))
		}
	}
	if len(out) == 0 {
		die(fmt.Errorf("no values were given: give them one a line on standard input"))
	}
	return out
}

func printErasureOr(args []string, v branch.ErasureView) {
	if hasFlag(args, "--json") {
		printJSON(v)
		return
	}
	printErasure(os.Stdout, v)
}

func next(v branch.ErasureView) {
	if v.Plan.Blocked {
		fmt.Printf("\nThe plan cannot be applied until the problems above are dealt with; then %s dpdp erase plan %d.\n", brand.CLI, v.ID)
		return
	}
	fmt.Printf("\nNothing has been changed. To apply it (you will be asked for the values again):\n  %s dpdp erase apply %d\n", brand.CLI, v.ID)
}

func refText(rs []branch.ErasureRef) string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.String()
	}
	return strings.Join(out, "; ")
}

func appliedSummary(v branch.ErasureView) string {
	if v.Result == nil {
		return fmt.Sprintf("request #%d applied", v.ID)
	}
	return fmt.Sprintf("request #%d applied: %d row(s) changed in %d table(s); %s", v.ID, v.Result.Rows, len(v.Result.Tables), rewriteSummary(v))
}

func rewriteSummary(v branch.ErasureView) string {
	if v.Result == nil {
		return "not applied"
	}
	done := 0
	for _, w := range v.Result.Rewrites {
		if w.State == branch.RewriteDone {
			done++
		}
	}
	return fmt.Sprintf("%d of %d table(s) rewritten", done, len(v.Result.Rewrites))
}

var erasureActText = map[string]string{
	branch.ErasureActClear:    "CLEAR",
	branch.ErasureActDelete:   "DELETE",
	branch.ErasureActCascade:  "DELETED WITH IT",
	branch.ErasureActSetNull:  "REFERENCE CLEARED",
	branch.ErasureActKeep:     "LEFT AS IS",
	branch.ErasureActKeptLaw:  "KEPT (LAW)",
	branch.ErasureActReferral: "REFERS TO IT",
}

// auditBranches records each branch's outcome in the security log: applied
// with its count, or skipped and why. Only the one named, when one is.
func auditBranches(s *auth.Store, v branch.ErasureView, only string) {
	for _, b := range v.Branches {
		if only != "" && b.Branch != only {
			continue
		}
		switch b.State {
		case branch.BranchApplied:
			rows := 0
			if b.Result != nil {
				rows = b.Result.Rows
			}
			s.Audit(auth.EvErasureBranch, cliActor(), b.Branch, "", fmt.Sprintf("request #%d on %s: applied, %d row(s) changed", v.ID, b.Branch, rows))
		case branch.BranchSkipped:
			s.Audit(auth.EvErasureBranch, cliActor(), b.Branch, "", fmt.Sprintf("request #%d on %s: skipped", v.ID, b.Branch))
		}
	}
}

var branchStateText = map[string]string{
	branch.BranchPlanned: "PLANNED",
	branch.BranchApplied: "APPLIED",
	branch.BranchSkipped: "SKIPPED",
	branch.BranchListed:  "NOT ERASED",
	branch.BranchGone:    "DELETED",
}

// printBranches is a request's branches: each one's state, the branches made
// before the erasure to remake or delete, and those past the maximum age.
func printBranches(w io.Writer, v branch.ErasureView) {
	if len(v.Branches) > 0 {
		fmt.Fprintf(w, "\nBranches (%d):\n", len(v.Branches))
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, b := range v.Branches {
			what := ""
			switch {
			case b.State == branch.BranchApplied && b.Result != nil:
				what = fmt.Sprintf("%d row(s) changed", b.Result.Rows)
				if n := b.Result.RewritesPending(); n > 0 {
					what += fmt.Sprintf("; %d table(s) still to rewrite (%s dpdp erase rewrite %d --branch %s)", n, brand.CLI, v.ID, b.Branch)
				}
			case b.State == branch.BranchPlanned && b.Plan != nil:
				what = fmt.Sprintf("%d row(s) hold a value; %d change", b.Plan.Matched, b.Plan.Rows)
				if b.Plan.Blocked {
					what += "; PROBLEM: " + firstPlanProblem(*b.Plan)
				}
			default:
				what = b.Why
			}
			if b.Masked {
				what = "masked; " + what
			}
			if b.Done != "" {
				what += fmt.Sprintf(" (%s by %s)", b.Done, b.DoneBy)
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", b.Branch, branchStateText[b.State], what)
		}
		tw.Flush()
		if v.State == auth.ErasureApplied {
			for _, b := range v.Branches {
				if b.State == branch.BranchSkipped && b.Done == "" {
					fmt.Fprintf(w, "  apply to %s on its own: %s dpdp erase apply %d --branch %s\n", b.Branch, brand.CLI, v.ID, b.Branch)
				}
			}
		}
	}
	if len(v.MadeBefore) > 0 {
		fmt.Fprintf(w, "\nBranches made before the erasure (%d): the person remains in their files until each is remade or deleted:\n", len(v.MadeBefore))
		for _, m := range v.MadeBefore {
			owner := ""
			if m.Owner != "" {
				owner = ", owned by " + m.Owner
			}
			fmt.Fprintf(w, "  %s (from %s%s): %s\n    remake: %s branch reset %s --from %s   or delete: %s branch delete %s\n",
				m.Branch, m.Parent, owner, m.Why, brand.CLI, m.Branch, m.Parent, brand.CLI, m.Branch)
		}
	} else if v.State == auth.ErasureApplied {
		fmt.Fprintln(w, "\nNo branch made before the erasure is left.")
	}
	if len(v.Old) > 0 {
		fmt.Fprintf(w, "\nBranches older than %s (%d): an erasure cannot finish while one holds the person:\n", brand.EnvName(branch.EnvBranchMaxAge), len(v.Old))
		for _, o := range v.Old {
			held := "not running: personal data not checked"
			if o.Personal != nil {
				held = "no confirmed personal data"
				if *o.Personal {
					held = "holds confirmed personal data"
				}
			}
			fmt.Fprintf(w, "  %s: made %s, %d day(s) ago; %s\n", o.Branch, o.Made.Local().Format("2006-01-02"), o.Days, held)
		}
	}
}

func firstPlanProblem(p branch.ErasurePlan) string {
	for _, t := range p.Tables {
		if len(t.Problems) > 0 {
			return t.Schema + "." + t.Table + ": " + t.Problems[0]
		}
	}
	return "a table has a problem"
}

// printErasureBranch prints one branch's plan and result.
func printErasureBranch(w io.Writer, v branch.ErasureView, name string) {
	for _, b := range v.Branches {
		if b.Branch != name {
			continue
		}
		fmt.Fprintf(w, "Erasure request #%d on %s: %s", v.ID, name, branchStateText[b.State])
		if b.Why != "" {
			fmt.Fprintf(w, " (%s)", b.Why)
		}
		fmt.Fprintln(w)
		if b.Plan != nil {
			bv := v
			bv.Branch, bv.Plan, bv.Result, bv.Branches, bv.MadeBefore, bv.Old = name, *b.Plan, b.Result, nil, nil, nil
			printPlan(w, bv)
		}
		return
	}
	fmt.Fprintf(w, "request #%d has no part on %s\n", v.ID, name)
}

// printErasure prints a request: what it is for, its plan table by table,
// and, once applied, what it did.
func printErasure(w io.Writer, v branch.ErasureView) {
	fmt.Fprintf(w, "Erasure request #%d on %s: %s\n", v.ID, v.Branch, v.State)
	if v.State == auth.ErasureApplied {
		if n := v.BranchesLeft(); n > 0 {
			fmt.Fprintf(w, "  applied on main, %d branch(es) left\n", n)
		}
	}
	printPlan(w, v)
	printBranches(w, v)
}

// printPlan is a request's plan on one branch, and what applying did there.
func printPlan(w io.Writer, v branch.ErasureView) {
	p := v.Plan
	fmt.Fprintf(w, "  for: %s\n", refText(v.Refs))
	if v.Note != "" {
		fmt.Fprintf(w, "  note: %s\n", v.Note)
	}
	fmt.Fprintf(w, "  made by %s at %s; planned by %s at %s\n", v.CreatedBy, v.Created.Local().Format("2006-01-02 15:04"),
		v.PlannedBy, v.Planned.Local().Format("2006-01-02 15:04"))
	fmt.Fprintf(w, "\nPlan: %d row(s) hold a value; %d row(s) change. %d confirmed place(s) searched.\n", p.Matched, p.Rows, p.Searched)
	for _, t := range p.Tables {
		fmt.Fprintf(w, "\n  %s.%s: %s %d row(s)  (%s)\n", t.Schema, t.Table, erasureActText[t.Action], t.Rows, t.Why)
		switch {
		case t.Entry != nil:
			fmt.Fprintf(w, "    entry: on erasure %s; kept %s\n", erasureText(*t.Entry), t.Entry.Keep)
		case t.Default:
			fmt.Fprintln(w, "    no inventory entry: cleared, the default")
		}
		for _, c := range t.Columns {
			where := c.Column
			if c.Path != "" {
				where += " at " + c.Path
			}
			fmt.Fprintf(w, "    %s (%s) → %s\n", where, strings.Join(c.Categories, ", "), c.To)
		}
		for _, x := range t.Exceptions {
			fmt.Fprintf(w, "    kept: %s\n", x.Text)
		}
		switch t.Rewrite {
		case "apply":
			fmt.Fprintf(w, "    rewritten in the files with the apply (%s)\n", humanSize(t.Size))
		case "later":
			fmt.Fprintf(w, "    rewritten later: %s\n", t.RewriteWhy)
		}
		for _, n := range t.Notes {
			fmt.Fprintf(w, "    note: %s\n", n)
		}
		for _, pr := range t.Problems {
			fmt.Fprintf(w, "    PROBLEM: %s\n", pr)
		}
	}
	if len(p.Tables) == 0 {
		fmt.Fprintln(w, "\n  No row holds any of the values in a confirmed place.")
	}
	if r := v.Result; r != nil {
		fmt.Fprintf(w, "\nApplied at %s by %s: %d row(s) changed", r.Applied.Local().Format("2006-01-02 15:04"), r.By, r.Rows)
		if r.Verified {
			fmt.Fprint(w, "; a search afterwards found none of the values where they were erased")
		}
		fmt.Fprintln(w, ".")
		for _, d := range r.Tables {
			fmt.Fprintf(w, "  %s.%s: %s %d row(s)\n", d.Schema, d.Table, erasureActText[d.Action], d.Rows)
		}
		if r.Vacuumed != nil {
			fmt.Fprintf(w, "  vacuumed %s: removed from live queries\n", r.Vacuumed.Local().Format("2006-01-02 15:04"))
		}
		for _, rw := range r.Rewrites {
			switch rw.State {
			case branch.RewriteDone:
				fmt.Fprintf(w, "  %s.%s rewritten in the files at %s\n", rw.Schema, rw.Table, rw.At.Local().Format("2006-01-02 15:04"))
			case branch.RewriteFailed:
				fmt.Fprintf(w, "  %s.%s NOT rewritten: %s (%s dpdp erase rewrite %d)\n", rw.Schema, rw.Table, rw.Error, brand.CLI, v.ID)
			default:
				fmt.Fprintf(w, "  %s.%s not rewritten yet: %s (%s dpdp erase rewrite %d)\n", rw.Schema, rw.Table, rw.Why, brand.CLI, v.ID)
			}
		}
		if r.Statistics != nil {
			fmt.Fprintf(w, "  statistics rewritten and the WAL switched out at %s\n", r.Statistics.Local().Format("2006-01-02 15:04"))
		}
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  note: %s\n", n)
		}
	}
	fmt.Fprintln(w, "\nWhat this cannot claim:")
	for _, l := range p.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
	fmt.Fprintf(w, "  - %s\n", p.Review)

}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d kB", n/1024)
}
