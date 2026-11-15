// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Unmasked personal data (PRIV-1): branches are unmasked by default, and the
// two places the command line hands one on say so. `fox branch create` warns
// as it prints the connection line; `fox check` lists every branch an agent or
// a non-admin account reads real personal data on. Neither refuses anything:
// masking is opt-in, and these make it a choice somebody made.

// branchWarnings is the engine's warning, as a variable so the tests need no
// database.
var branchWarnings = branch.PersonalDataWarnings

// printPersonalDataWarnings is `fox branch create`'s warning. The branch is
// judged as a reader no account masking applies to: made here, it is an
// admin's, and whoever is given its DSN reads what it holds.
func printPersonalDataWarnings(w io.Writer, name string) {
	for _, line := range branchWarnings(name, "", "people and agents given its connection string", "") {
		fmt.Fprintf(w, "\nWarning: %s\n", line)
	}
}

// piiReach is one branch as `fox check` judges it: who reaches it, and the
// worst of what any of them reads unmasked.
type piiReach struct {
	Branch string
	// Agents is whether agents read it: an agent's branch, or main while
	// agent branches (copies of it) exist.
	Agents bool
	// Accounts is how many non-admin accounts read real values on it.
	Accounts int
	Summary  branch.UnmaskedSummary
}

// checkPersonalData is the `fox check` line. A warning at most: unmasked data
// is the default, and an install that chose it is not broken.
func checkPersonalData() checkLine {
	rows, err := personalDataReach()
	if err != nil {
		return ok("personal data", "could not be judged: "+firstLine(err.Error()))
	}
	return personalDataLine(rows, maskingOn(rows))
}

// maskingOn reports what the engine said about masking, from any summary it
// gave (they all carry it).
func maskingOn(rows []piiReach) bool {
	for _, r := range rows {
		if r.Summary.MaskingAvailable {
			return true
		}
	}
	return false
}

// personalDataReach reads every running branch's records, as each reader that
// reaches it would see them. A suspended branch is not woken for it: this is a
// report.
func personalDataReach() ([]piiReach, error) {
	bs, err := branch.Branches()
	if err != nil {
		return nil, err
	}
	type acct struct {
		id    int64
		email string
	}
	var plain []acct // the non-admin accounts
	owners := map[string]int64{}
	if st, err := auth.OpenFromEnv(); err == nil {
		defer st.Close()
		if list, err := st.ListAccounts(); err == nil {
			for _, a := range list {
				if admin, err := branch.IsAdmin("main", a.Email); err == nil && !admin {
					plain = append(plain, acct{a.ID, a.Email})
				}
			}
		}
		if o, err := st.BranchOwners(); err == nil {
			owners = o
		}
	}
	agentsExist := false
	for _, b := range bs {
		agentsExist = agentsExist || b.Agent
	}
	var out []piiReach
	for _, b := range bs {
		if b.State != "running" {
			continue
		}
		r := piiReach{Branch: b.Name, Agents: b.Agent || (b.Primary && agentsExist)}
		// The agent's own role (or the masked branch it was given), as the
		// account-free reader.
		s, err := branch.UnmaskedPersonalData(b.Name, "")
		if err != nil {
			continue // a branch that cannot be asked is not a finding about it
		}
		if !b.Agent {
			// Main is reached by every account; any other branch by its owner.
			// An agent of a non-admin account reads as that account does.
			worst := branch.UnmaskedSummary{Branch: b.Name, Scanned: s.Scanned,
				MaskingAvailable: s.MaskingAvailable, ScanningAvailable: s.ScanningAvailable}
			for _, a := range plain {
				if !b.Primary && owners[b.Name] != a.id {
					continue
				}
				as, err := branch.UnmaskedPersonalData(b.Name, a.email)
				if err != nil || !as.Exposed() {
					continue
				}
				r.Accounts++
				if as.Columns > worst.Columns {
					worst = as
				}
			}
			if !r.Agents {
				s = worst
			} else if worst.Columns > s.Columns {
				s = worst
			}
		}
		r.Summary = s
		out = append(out, r)
	}
	return out, nil
}

// maxCheckBranches is how many branches the line names before "and N more".
const maxCheckBranches = 5

// personalDataLine is the judgement: which branches hand real personal data to
// an agent or a non-admin account, and which have agents on them and have never
// been scanned, so nobody knows.
func personalDataLine(rows []piiReach, masking bool) checkLine {
	var exposed, unknown []string
	sort.Slice(rows, func(i, j int) bool { return rows[i].Branch < rows[j].Branch })
	for _, r := range rows {
		s := r.Summary
		switch {
		case !s.Scanned && r.Agents:
			unknown = append(unknown, r.Branch)
		case s.Exposed() && (r.Agents || r.Accounts > 0):
			var who []string
			if r.Agents {
				who = append(who, "agents")
			}
			if r.Accounts > 0 {
				who = append(who, countOf(r.Accounts, "non-admin account"))
			}
			exposed = append(exposed, fmt.Sprintf("%s (%s, read unmasked by %s)", r.Branch, s.Counts(), strings.Join(who, " and ")))
		}
	}
	if len(exposed) == 0 && len(unknown) == 0 {
		return ok("personal data", "no branch an agent or non-admin account reaches holds confirmed personal data unmasked for it")
	}
	var parts []string
	if len(exposed) > 0 {
		parts = append(parts, "unmasked confirmed personal data on "+listSome(exposed))
	}
	if len(unknown) > 0 {
		parts = append(parts, "never scanned, with agents on it: "+listSome(unknown))
	}
	detail := strings.Join(parts, "; ") + ". Branches are unmasked by default"
	fix := fmt.Sprintf("masking and scanning need %s Enterprise; see the README's Security defaults", brand.Product)
	if masking {
		fix = fmt.Sprintf("%[1]s pii scan --branch main, then %[1]s mask rule <table.column> for each column "+
			"and %[1]s mask account <email> for whoever should read masks", brand.CLI)
	}
	return warn("personal data", detail, fix)
}

func listSome(xs []string) string {
	if len(xs) <= maxCheckBranches {
		return strings.Join(xs, ", ")
	}
	return strings.Join(xs[:maxCheckBranches], ", ") + fmt.Sprintf(" and %d more", len(xs)-maxCheckBranches)
}

func countOf(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}
