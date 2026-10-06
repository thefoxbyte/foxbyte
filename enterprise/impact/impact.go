//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package impact computes a change's blast radius: what depends on the table,
// view, index or column a statement touches, which other branches have it, and
// a score with the reasons. It is the paid half of `fox impact`; the report it
// produces stays in internal/branch, because the free agent-provenance record
// embeds one and the CLI renders one.
package impact

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// textOrNull renders an optional string as a SQL literal or NULL. Three lines,
// kept here rather than exported from internal/branch: the primitives that
// package offers the paid edition are worth keeping few, and this is not one
// anybody else needs.
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// init registers the analysis with internal/branch, which is how the free half
// reaches it without importing this package.
func init() { branch.SetImpactAnalyser(compute) }

type blastRadius struct {
	Found        bool                     `json:"found"`
	Target       string                   `json:"target"`
	Type         string                   `json:"type"`
	Column       *string                  `json:"column"`
	RowsEstimate int64                    `json:"rows_estimate"`
	SizeBytes    int64                    `json:"size_bytes"`
	Truncated    bool                     `json:"truncated"`
	Dependents   []branch.ImpactDependent `json:"dependents"`
}

func countOf(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// scoreImpact turns a report into a score, a level and the reasons for it:
// a destructive change starts at 5 (any other change at 1); each dependent view,
// function or foreign key from another table adds 3, each trigger or policy 2,
// each index or other dependent 1; a truncated walk adds 3; a large table adds up
// to 3; each other running branch with the object adds 1 (at most 5); a policy
// rule that would block adds 5, one that warns 2. 15+ is high, 5–14 medium.
func scoreImpact(r branch.ImpactReport) (int, string, []string) {
	if !r.Found {
		return 0, "none", []string{"the object doesn't exist on this branch"}
	}
	score := 0
	reasons := []string{}
	add := func(n int, why string) {
		score += n
		reasons = append(reasons, fmt.Sprintf("+%d %s", n, why))
	}
	if r.Destructive {
		add(5, r.Action+" can lose data or break code that uses it")
	} else {
		add(1, "changes an existing object")
	}
	var views, funcs, fks, triggers, policies, indexes, other int
	for _, d := range r.Dependents {
		switch {
		case d.Type == "view" || d.Type == "materialized view":
			views++
		case d.Type == "function" || d.Type == "procedure":
			funcs++
		case d.Type == "table constraint" && !d.SameRelation:
			fks++
		case d.Type == "trigger":
			triggers++
		case d.Type == "policy":
			policies++
		case d.Type == "index":
			indexes++
		default:
			other++
		}
	}
	for _, c := range []struct {
		n, w      int
		one, many string
	}{
		{views, 3, "dependent view", "dependent views"},
		{funcs, 3, "dependent function", "dependent functions"},
		{fks, 3, "constraint on another table (e.g. a foreign key)", "constraints on other tables (e.g. foreign keys)"},
		{triggers, 2, "trigger", "triggers"},
		{policies, 2, "row-level security policy", "row-level security policies"},
		{indexes, 1, "index", "indexes"},
		{other, 1, "other dependent object", "other dependent objects"},
	} {
		if c.n > 0 {
			add(c.n*c.w, countOf(c.n, c.one, c.many))
		}
	}
	if r.Truncated {
		add(3, "dependents go deeper than the depth checked")
	}
	switch {
	case r.RowsEstimate >= 1_000_000:
		add(3, fmt.Sprintf("about %d rows", r.RowsEstimate))
	case r.RowsEstimate >= 10_000:
		add(1, fmt.Sprintf("about %d rows", r.RowsEstimate))
	}
	present := 0
	for _, b := range r.Branches {
		if b.Present {
			present++
		}
	}
	if present > 0 {
		n := present
		if n > 5 {
			n = 5
		}
		add(n, "also on "+countOf(present, "other running branch", "other running branches"))
	}
	for _, p := range r.Policy {
		if p.Action == "block" {
			add(5, "policy rule "+p.RuleID+" would block it")
		} else {
			add(2, "policy rule "+p.RuleID+" warns about it")
		}
	}
	level := "low"
	switch {
	case score >= 15:
		level = "high"
	case score >= 5:
		level = "medium"
	}
	return score, level, reasons
}

func impactErr(name string, err error) error {
	if strings.Contains(err.Error(), "bb.blast_radius") && strings.Contains(err.Error(), "does not exist") {
		return fmt.Errorf("Blackbox impact analysis isn't installed on %q — run: fox blackbox upgrade %s", name, name)
	}
	return err
}

// Impact reports what a change would affect on a branch. Pass the statement, or
// the object (and optionally column) directly; object and column override what
// is found in the statement. Nothing is run.
func compute(name, statement, object, column string) (branch.ImpactReport, error) {
	name, err := branch.ResolveBranch(name)
	if err != nil {
		return branch.ImpactReport{}, err
	}
	statement = strings.TrimSpace(statement)
	t := ledger.Target{Action: "change"}
	if statement != "" {
		if parsed, ok := ledger.ParseTarget(statement); ok {
			t = parsed
		} else if object == "" {
			return branch.ImpactReport{}, fmt.Errorf("%w: couldn't find the table, view or index this statement changes — pass --object (and --column)", branch.ErrInvalidRequest)
		}
	} else if object == "" {
		return branch.ImpactReport{}, fmt.Errorf("%w: sql or object is required", branch.ErrInvalidRequest)
	}
	if object != "" {
		t.Object = object
	}
	if column != "" {
		t.Column = column
	}

	rep := branch.ImpactReport{
		Branch: name, Statement: statement, Action: t.Action, Destructive: t.Destructive(), Target: t.Object,
		Dependents: []branch.ImpactDependent{}, Branches: []branch.BranchPresence{}, Policy: []ledger.PolicyDetail{},
	}
	if statement != "" {
		rep.Command = ledger.CommandTag(statement)
	}
	lines, err := branch.LedgerQuery(name, fmt.Sprintf("SELECT bb.blast_radius(%s, %s, 5)::text", branch.QuoteLiteral(t.Object), branch.QuoteLiteralOrNull(&t.Column)))
	if err != nil {
		return branch.ImpactReport{}, impactErr(name, err)
	}
	if len(lines) == 0 {
		return branch.ImpactReport{}, fmt.Errorf("no answer from branch %q", name)
	}
	var br blastRadius
	if err := json.Unmarshal([]byte(lines[0]), &br); err != nil {
		return branch.ImpactReport{}, fmt.Errorf("reading the impact analysis: %w", err)
	}
	rep.Found, rep.Target, rep.Type, rep.Column = br.Found, br.Target, br.Type, br.Column
	rep.RowsEstimate, rep.SizeBytes, rep.Truncated = br.RowsEstimate, br.SizeBytes, br.Truncated
	if br.Dependents != nil {
		rep.Dependents = br.Dependents
	}
	if rep.Found {
		rep.Branches = branchPresence(name, rep.Target, deref(rep.Column))
	}
	if statement != "" {
		if _, matches, err := branch.PolicyCheck(name, statement); err == nil {
			rep.Policy = matches
		}
	}
	rep.Score, rep.Level, rep.Reasons = scoreImpact(rep)
	return rep, nil
}

// branchPresence checks the other running branches for the object. branch.Branches that
// aren't running are listed but not woken.
func branchPresence(self, object, column string) []branch.BranchPresence {
	out := []branch.BranchPresence{}
	infos, err := branch.Branches()
	if err != nil {
		return out
	}
	q := fmt.Sprintf(`SELECT coalesce((SELECT CASE WHEN %[2]s IS NULL THEN true ELSE EXISTS (
    SELECT 1 FROM pg_attribute a WHERE a.attrelid = r AND a.attname = %[2]s AND a.attnum > 0 AND NOT a.attisdropped) END
  FROM to_regclass(%[1]s) AS r WHERE r IS NOT NULL), false)`, branch.QuoteLiteral(object), branch.QuoteLiteralOrNull(&column))
	for _, b := range infos {
		if b.Name == self || b.Name == "standby" || b.Name == "restore" {
			continue
		}
		p := branch.BranchPresence{Branch: b.Name, State: b.State, Parent: branch.BranchParent(b.Name)}
		if b.State == "running" {
			if l, err := branch.LedgerQuery(b.Name, q); err == nil && len(l) > 0 {
				p.Checked, p.Present = true, l[0] == "t"
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Branch < out[j].Branch })
	return out
}
