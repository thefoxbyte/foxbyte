// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Moving Aadhaar numbers into the vault (point 13, step 13.3):
//
//	fox vault migrate --branch b [--column s.t.c ...] [--format opaque|legacy] [--dry-run] [--yes] [--json]
//	fox vault migrations [--branch b] [--json]
//	fox vault orphans [--json]
//	fox vault orphans delete [--run id] [--yes]
//
// On a branch first; main only once a branch made from main has moved the same
// columns with nothing left, and only with --yes.

const vaultMigrateUsage = `usage:
  fox vault migrate --branch BRANCH [--column SCHEMA.TABLE.COLUMN ...] [--format opaque|legacy] [--dry-run] [--yes] [--json]
  fox vault migrations [--branch BRANCH] [--json]
  fox vault orphans [--json]
  fox vault orphans delete [--run ID] [--yes]
`

func vaultMigrate(args []string) {
	name := optValue(args, "--branch")
	if name == "" {
		fmt.Fprint(os.Stderr, "--branch is needed: a migration runs on a branch first, then on main\n\n"+vaultMigrateUsage)
		os.Exit(2)
	}
	var cols []string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--column" {
			for _, c := range strings.Split(args[i+1], ",") {
				if c = strings.TrimSpace(c); c != "" {
					cols = append(cols, c)
				}
			}
		}
	}
	dry := hasFlag(args, "--dry-run")
	if name == "main" && !dry && !hasFlag(args, "--yes") {
		fmt.Printf("This moves main's Aadhaar numbers into the vault: each number in the columns\n" +
			"is replaced by its reference key, where it stands, in batches, while main\n" +
			"keeps serving.\n\n" +
			"It is refused unless a branch made from main has moved the same columns with\n" +
			"no number left; the keys written are the ones that branch got. Check that\n" +
			"branch first: applications reading these columns read keys from now on.\n\n" +
			"Run again with --yes to go ahead, or with --dry-run to see what it would move.\n")
		return
	}
	st := openStore()
	if st == nil {
		must(fmt.Errorf("the install's store could not be opened, and a migration is kept there"))
	}
	defer st.Close()
	actor := cliActor()
	m, err := branch.MigrateToVault(st, name, branch.VaultMigrateOptions{
		Actor: actor, Columns: cols, Format: optValue(args, "--format"), DryRun: dry,
		Call: func(vaultActor, path string, body []byte) ([]byte, int, error) {
			return branch.VaultCallActor(st, actor, vaultActor, "", path, body)
		},
	})
	if m.ID == 0 {
		must(err) // refused before a run was kept: nothing to report but why
	}
	// The run is kept, and its report says how it ended, the error included,
	// so the error is not said twice.
	if hasFlag(args, "--json") {
		printJSON(m)
	} else {
		printVaultMigration(os.Stdout, m)
	}
	// Exit 1 when the run stopped, or a column it planned still holds numbers
	// (skipped, or left), whichever the output asked for.
	if err != nil || (!m.Dry && !m.Clean() && len(m.Columns) > 0) {
		os.Exit(1)
	}
}

func printVaultMigration(w io.Writer, m branch.VaultMigration) {
	what := "Migration"
	if m.Dry {
		what = "Preview"
	}
	fmt.Fprintf(w, "%s %d on %s (%s): %d distinct Aadhaar number(s) in %d column(s).\n", what, m.ID, m.Branch, m.State, m.Distinct, len(m.Columns))
	if !m.Dry && m.State == "done" {
		fmt.Fprintf(w, "Keys: %d made in the vault, %d it held already. Passes: %d.\n", m.Made, m.Reused, m.Passes)
	}
	if len(m.Rehearsals) > 0 {
		ids := make([]string, len(m.Rehearsals))
		for i, id := range m.Rehearsals {
			ids[i] = strconv.FormatInt(id, 10)
		}
		fmt.Fprintf(w, "Rehearsed by run(s) %s.\n", strings.Join(ids, ", "))
	}
	if len(m.Columns) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "\nCOLUMN\tTYPE\tKEYS\tROWS\tNUMBERS\tREWRITTEN\tLEFT")
		for _, c := range m.Columns {
			if c.Skipped != "" {
				fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\t-\tskipped: %s\n", c.Where(), dash(c.Type), c.Skipped)
				continue
			}
			left := strconv.FormatInt(c.Left, 10)
			if m.Dry {
				left = "-"
			}
			rewritten := strconv.FormatInt(c.Replaced, 10)
			if m.Dry {
				rewritten = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", c.Where(), c.Type, c.Format, c.Rows, c.Numbers, rewritten, left)
		}
		_ = tw.Flush()
		for _, c := range m.Columns {
			if len(c.LeftWhy) == 0 {
				continue
			}
			whys := make([]string, 0, len(c.LeftWhy))
			for why, n := range c.LeftWhy {
				whys = append(whys, fmt.Sprintf("%d: %s", n, why))
			}
			sort.Strings(whys)
			fmt.Fprintf(w, "  left in %s: %s\n", c.Where(), strings.Join(whys, "; "))
		}
	}
	if len(m.Vacuumed) > 0 {
		fmt.Fprintf(w, "Vacuumed: %s.\n", strings.Join(m.Vacuumed, ", "))
	}
	if m.Error != "" {
		fmt.Fprintf(w, "\nStopped: %s\n", m.Error)
	}
	switch {
	case m.Dry:
	case m.Clean() && m.Branch != "main":
		fmt.Fprintf(w, "\nEvery column is moved, with no number left. Check the branch; then main is moved\n"+
			"with the same keys: %s vault migrate --branch main --yes\n", brand.CLI)
	case m.Clean():
		fmt.Fprintf(w, "\nEvery column is moved, with no number left.\n")
	}
	if len(m.Limits) > 0 {
		fmt.Fprintln(w, "\nWhat this does not cover:")
		for _, l := range m.Limits {
			fmt.Fprintf(w, "  - %s\n", l)
		}
	}
}

func vaultMigrations(args []string) {
	st := openStore()
	if st == nil {
		must(fmt.Errorf("the install's store could not be opened"))
	}
	defer st.Close()
	ms, err := branch.VaultMigrations(st, optValue(args, "--branch"), 100)
	must(err)
	if hasFlag(args, "--json") {
		printJSON(ms)
		return
	}
	if len(ms) == 0 {
		fmt.Printf("No vault migrations yet. Preview one with `%s vault migrate --branch <branch> --dry-run`.\n", brand.CLI)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RUN\tWHEN\tBRANCH\tBY\tWHAT\tSTATE\tCOLUMNS\tNUMBERS\tMADE\tLEFT")
	for _, m := range ms {
		what := "migrate"
		if m.Dry {
			what = "preview"
		}
		state := m.State
		if m.Clean() {
			state = "done, clean"
		}
		var left int64
		for _, c := range m.Columns {
			left += c.Left
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n", m.ID, m.Started.Local().Format("2006-01-02 15:04"), m.Branch, m.Actor, what, state, len(m.Columns), m.Distinct, m.Made, left)
	}
	_ = w.Flush()
}

func vaultOrphans(args []string) {
	st := openStore()
	if st == nil {
		must(fmt.Errorf("the install's store could not be opened"))
	}
	defer st.Close()
	pos := positionals(args, "--run")
	if len(pos) > 0 && pos[0] == "delete" {
		var run int64
		if v := optValue(args, "--run"); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 1 {
				must(fmt.Errorf("--run is a migration's number, not %q", v))
			}
			run = n
		}
		if !hasFlag(args, "--yes") {
			fmt.Printf("This deletes from the vault the keys that migrations made on branches now gone\n" +
				"(fox vault orphans lists them). The vault deletes a key only if that branch's\n" +
				"migrations made it and nobody else was handed it or read it back; the rest\n" +
				"are kept, and said so. A key deleted can never be read back.\n\n" +
				"Run again with --yes to go ahead.\n")
			return
		}
		res, err := branch.DeleteVaultOrphans(st, cliActor(), "", run)
		must(err)
		fmt.Printf("Done: %d key(s) deleted from the vault; %d kept, because someone else was handed them.\n", res.Deleted, res.Kept)
		return
	}
	orphans, err := branch.VaultOrphans(st)
	must(err)
	if hasFlag(args, "--json") {
		printJSON(orphans)
		return
	}
	pending := 0
	for _, o := range orphans {
		pending += o.Keys.Pending
	}
	if len(orphans) == 0 {
		fmt.Println("No orphaned keys: every branch a migration ran on is still there.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RUN\tBRANCH\tRAN\tBY\tWHY\tMADE\tTO DELETE\tDELETED\tKEPT")
	for _, o := range orphans {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n", o.Run, o.Branch, o.Ran.Local().Format("2006-01-02 15:04"), o.Actor, o.Why, o.Keys.Made, o.Keys.Pending, o.Keys.Deleted, o.Keys.Kept)
	}
	_ = w.Flush()
	if pending > 0 {
		fmt.Printf("\n%d key(s) to delete: %s vault orphans delete [--run ID] --yes\n", pending, brand.CLI)
	}
}
