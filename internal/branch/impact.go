// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
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

// computeImpact is the analysis, supplied by enterprise/impact in an Enterprise
// build and nil in a Standard one, where that code is not compiled in. The
// report, the branch-parent lookup and the rendering above stay here: the
// provenance record embeds a report, `blackbox diff` uses BranchParent, and
// rendering a struct is not the feature — computing it is.
var computeImpact func(name, statement, object, column string) (ImpactReport, error)

// SetImpactAnalyser installs the analysis. Called from enterprise/impact's
// init, and from nowhere else.
func SetImpactAnalyser(fn func(name, statement, object, column string) (ImpactReport, error)) {
	computeImpact = fn
}

// Impact reports what a statement would affect.
func Impact(name, statement, object, column string) (ImpactReport, error) {
	// The analysis itself. `blackbox diff` is a read of two records and is
	// not gated: reading the record stays free in every edition.
	if err := requireFeature(edition.Impact); err != nil {
		return ImpactReport{}, err
	}
	if computeImpact == nil {
		return ImpactReport{}, ErrImpactNotLicensed
	}
	return computeImpact(name, statement, object, column)
}
