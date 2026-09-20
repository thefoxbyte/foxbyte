// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/foxbyte/foxbyte/internal/ledger"
)

// Blackbox impact analysis: before a change, what would it affect? The objects
// that depend on the table, view or column it changes (bb.blast_radius,
// internal/ledger/impact.sql), the other running branches that have the object,
// what the policy gate would say, and a score with the reasons behind it.

// ImpactDependent is one object that depends on the target.
type ImpactDependent struct {
	Type         string  `json:"type"`
	Identity     string  `json:"identity"`
	Depth        int     `json:"depth"`
	Relation     *string `json:"relation"`
	SameRelation bool    `json:"same_relation"`
	Dependency   string  `json:"dependency"`
	Via          *string `json:"via"`
}

// BranchPresence says whether another branch has the target.
type BranchPresence struct {
	Branch  string `json:"branch"`
	State   string `json:"state"`
	Parent  string `json:"parent,omitempty"`
	Checked bool   `json:"checked"` // false for branches that aren't running (they aren't woken)
	Present bool   `json:"present"`
}

// ImpactReport is the result of Impact.
type ImpactReport struct {
	Branch       string                `json:"branch"`
	Statement    string                `json:"statement,omitempty"`
	Command      string                `json:"command,omitempty"`
	Action       string                `json:"action"`
	Destructive  bool                  `json:"destructive"`
	Found        bool                  `json:"found"`
	Target       string                `json:"target"`
	Type         string                `json:"type,omitempty"`
	Column       *string               `json:"column"`
	RowsEstimate int64                 `json:"rows_estimate"`
	SizeBytes    int64                 `json:"size_bytes"`
	Dependents   []ImpactDependent     `json:"dependents"`
	Truncated    bool                  `json:"truncated"`
	Branches     []BranchPresence      `json:"branches"`
	Policy       []ledger.PolicyDetail `json:"policy"`
	Score        int                   `json:"score"`
	Level        string                `json:"level"` // none | low | medium | high
	Reasons      []string              `json:"reasons"`
}

type blastRadius struct {
	Found        bool              `json:"found"`
	Target       string            `json:"target"`
	Type         string            `json:"type"`
	Column       *string           `json:"column"`
	RowsEstimate int64             `json:"rows_estimate"`
	SizeBytes    int64             `json:"size_bytes"`
	Truncated    bool              `json:"truncated"`
	Dependents   []ImpactDependent `json:"dependents"`
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
func scoreImpact(r ImpactReport) (int, string, []string) {
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
func Impact(name, statement, object, column string) (ImpactReport, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return ImpactReport{}, err
	}
	statement = strings.TrimSpace(statement)
	t := ledger.Target{Action: "change"}
	if statement != "" {
		if parsed, ok := ledger.ParseTarget(statement); ok {
			t = parsed
		} else if object == "" {
			return ImpactReport{}, fmt.Errorf("%w: couldn't find the table, view or index this statement changes — pass --object (and --column)", ErrInvalidRequest)
		}
	} else if object == "" {
		return ImpactReport{}, fmt.Errorf("%w: sql or object is required", ErrInvalidRequest)
	}
	if object != "" {
		t.Object = object
	}
	if column != "" {
		t.Column = column
	}

	rep := ImpactReport{
		Branch: name, Statement: statement, Action: t.Action, Destructive: t.Destructive(), Target: t.Object,
		Dependents: []ImpactDependent{}, Branches: []BranchPresence{}, Policy: []ledger.PolicyDetail{},
	}
	if statement != "" {
		rep.Command = ledger.CommandTag(statement)
	}
	lines, err := ledgerLines(name, fmt.Sprintf("SELECT bb.blast_radius(%s, %s, 5)::text", quoteLiteral(t.Object), sqlTextOrNull(&t.Column)))
	if err != nil {
		return ImpactReport{}, impactErr(name, err)
	}
	if len(lines) == 0 {
		return ImpactReport{}, fmt.Errorf("no answer from branch %q", name)
	}
	var br blastRadius
	if err := json.Unmarshal([]byte(lines[0]), &br); err != nil {
		return ImpactReport{}, fmt.Errorf("reading the impact analysis: %w", err)
	}
	rep.Found, rep.Target, rep.Type, rep.Column = br.Found, br.Target, br.Type, br.Column
	rep.RowsEstimate, rep.SizeBytes, rep.Truncated = br.RowsEstimate, br.SizeBytes, br.Truncated
	if br.Dependents != nil {
		rep.Dependents = br.Dependents
	}
	if rep.Found {
		rep.Branches = branchPresence(name, rep.Target, str(rep.Column))
	}
	if statement != "" {
		if _, matches, err := PolicyCheck(name, statement); err == nil {
			rep.Policy = matches
		}
	}
	rep.Score, rep.Level, rep.Reasons = scoreImpact(rep)
	return rep, nil
}

// branchPresence checks the other running branches for the object. Branches that
// aren't running are listed but not woken.
func branchPresence(self, object, column string) []BranchPresence {
	out := []BranchPresence{}
	infos, err := Branches()
	if err != nil {
		return out
	}
	q := fmt.Sprintf(`SELECT coalesce((SELECT CASE WHEN %[2]s IS NULL THEN true ELSE EXISTS (
    SELECT 1 FROM pg_attribute a WHERE a.attrelid = r AND a.attname = %[2]s AND a.attnum > 0 AND NOT a.attisdropped) END
  FROM to_regclass(%[1]s) AS r WHERE r IS NOT NULL), false)`, quoteLiteral(object), sqlTextOrNull(&column))
	for _, b := range infos {
		if b.Name == self || b.Name == "standby" || b.Name == "restore" {
			continue
		}
		p := BranchPresence{Branch: b.Name, State: b.State, Parent: BranchParent(b.Name)}
		if b.State == "running" {
			if l, err := ledgerLines(b.Name, q); err == nil && len(l) > 0 {
				p.Checked, p.Present = true, l[0] == "t"
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Branch < out[j].Branch })
	return out
}

// BranchParent is the branch a branch was cloned from, read from the storage
// layer (ZFS origin, btrfs parent UUID); "" when it wasn't cloned (main, a
// restored branch) or can't be told.
func BranchParent(name string) string {
	switch activeStorage().name() {
	case "zfs":
		out, err := capture("zfs", "get", "-H", "-o", "value", "origin", dataset(name))
		if err != nil {
			return ""
		}
		return parentFromZFSOrigin(out)
	case "btrfs":
		show, err := capture("btrfs", "subvolume", "show", btrfsSubvol(name))
		if err != nil {
			return ""
		}
		uuid := parentUUIDFromShow(show)
		if uuid == "" {
			return ""
		}
		list, err := capture("btrfs", "subvolume", "list", "-u", btrfsMount)
		if err != nil {
			return ""
		}
		return subvolumeByUUID(list, uuid)
	}
	return ""
}

// parentFromZFSOrigin maps "dbpool/branches/main@for-qa" to "main".
func parentFromZFSOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	prefix := datasetBase + "/"
	if !strings.HasPrefix(origin, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(origin, prefix)
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return rest
}

// parentUUIDFromShow reads "Parent UUID:" from `btrfs subvolume show`.
func parentUUIDFromShow(show string) string {
	for _, l := range strings.Split(show, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Parent UUID:") {
			v := strings.TrimSpace(strings.TrimPrefix(l, "Parent UUID:"))
			if v == "-" {
				return ""
			}
			return v
		}
	}
	return ""
}

// subvolumeByUUID finds the subvolume with uuid in `btrfs subvolume list -u`.
func subvolumeByUUID(list, uuid string) string {
	for _, l := range strings.Split(list, "\n") {
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "uuid" && f[i+1] == uuid {
				for j := i + 2; j+1 < len(f); j++ {
					if f[j] == "path" {
						return filepath.Base(strings.Join(f[j+1:], " "))
					}
				}
			}
		}
	}
	return ""
}

// FormatImpact renders a report for people.
func FormatImpact(r ImpactReport) string {
	var b strings.Builder
	col := ""
	if r.Column != nil {
		col = ", column " + *r.Column
	}
	if !r.Found {
		fmt.Fprintf(&b, "impact on %s: %s%s — not found on this branch", r.Branch, r.Target, col)
		return b.String()
	}
	fmt.Fprintf(&b, "impact on %s: %s (%s)%s — %s (score %d)\n", r.Branch, r.Target, r.Type, col, strings.ToUpper(r.Level), r.Score)
	destructive := ""
	if r.Destructive {
		destructive = " (destructive)"
	}
	fmt.Fprintf(&b, "  change   %s%s\n", r.Action, destructive)
	fmt.Fprintf(&b, "  size     ~%d rows, %s\n", r.RowsEstimate, humanBytes(uint64(max(r.SizeBytes, 0))))
	b.WriteString("  why\n")
	for _, why := range r.Reasons {
		fmt.Fprintf(&b, "    %s\n", why)
	}
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	if len(r.Dependents) > 0 {
		fmt.Fprintln(tw, "  depends on it")
		for _, d := range r.Dependents {
			via := ""
			if d.Via != nil {
				via = "via " + *d.Via
			}
			fmt.Fprintf(tw, "    %s\t%s\t%s\t%s\n", d.Type, d.Identity, d.Dependency, via)
		}
	} else {
		fmt.Fprintln(tw, "  nothing depends on it")
	}
	if r.Truncated {
		fmt.Fprintln(tw, "    … and more beyond the depth checked")
	}
	if len(r.Branches) > 0 {
		fmt.Fprintln(tw, "  other branches")
		for _, p := range r.Branches {
			has := "not checked (not running)"
			if p.Checked {
				has = "does not have it"
				if p.Present {
					has = "has it"
				}
			}
			parent := ""
			if p.Parent != "" {
				parent = "cloned from " + p.Parent
			}
			fmt.Fprintf(tw, "    %s\t%s\t%s\n", p.Branch, has, parent)
		}
	}
	if len(r.Policy) > 0 {
		fmt.Fprintln(tw, "  policy")
		for _, p := range r.Policy {
			fmt.Fprintf(tw, "    %s\t%s\t%s\n", strings.ToUpper(p.Action), p.RuleID, p.Reason)
		}
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}
