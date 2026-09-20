// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/foxbyte/foxbyte/internal/ledger"
)

// Blackbox diff: which schema changes distinguish two branches. A branch is a
// copy-on-write clone, so it starts with its parent's Blackbox history, entry
// for entry. The fork point is where the two histories stop being identical
// (same id, same recomputed hash); everything after it happened on one side only.
// Diff only — nothing is merged or changed.

// DiffEntry is one Blackbox entry in a diff.
type DiffEntry struct {
	ID         int64  `json:"id"`
	At         string `json:"at"`
	Actor      string `json:"actor"`
	CommandTag string `json:"command_tag"`
	Object     string `json:"object_identity"`
	Status     string `json:"status"`
}

// DiffOverlap is an object changed on both sides since the fork.
type DiffOverlap struct {
	Object   string  `json:"object_identity"`
	AEntries []int64 `json:"a_entries"`
	BEntries []int64 `json:"b_entries"`
}

// LedgerDiff compares two branches' Blackbox histories.
type LedgerDiff struct {
	A             string        `json:"a"`
	B             string        `json:"b"`
	AParent       string        `json:"a_parent,omitempty"`
	BParent       string        `json:"b_parent,omitempty"`
	CommonEntries int           `json:"common_entries"`
	ForkAfterID   int64         `json:"fork_after_id"` // last shared entry (0: no shared history)
	ForkAfterAt   string        `json:"fork_after_at,omitempty"`
	AOnly         []DiffEntry   `json:"a_only"`
	BOnly         []DiffEntry   `json:"b_only"`
	BothTouched   []DiffOverlap `json:"both_touched"`
}

func diffEntry(r ledger.Row) DiffEntry {
	return DiffEntry{ID: r.ID, At: r.At.UTC().Format(time.RFC3339), Actor: r.Actor, CommandTag: r.CommandTag,
		Object: r.ObjectIdentity, Status: r.Status}
}

// buildDiff compares two id-ordered histories.
func buildDiff(aName, bName string, a, b []ledger.Row) LedgerDiff {
	d := LedgerDiff{A: aName, B: bName, AOnly: []DiffEntry{}, BOnly: []DiffEntry{}, BothTouched: []DiffOverlap{}}
	n := 0
	for n < len(a) && n < len(b) && a[n].ID == b[n].ID && ledger.RowHash(a[n]) == ledger.RowHash(b[n]) {
		n++
	}
	d.CommonEntries = n
	if n > 0 {
		d.ForkAfterID = a[n-1].ID
		d.ForkAfterAt = a[n-1].At.UTC().Format(time.RFC3339)
	}
	touched := func(rows []ledger.Row) map[string][]int64 {
		m := map[string][]int64{}
		for _, r := range rows {
			if r.ObjectIdentity != "" && r.Status != "BLOCKED" { // a blocked change didn't happen
				m[r.ObjectIdentity] = append(m[r.ObjectIdentity], r.ID)
			}
		}
		return m
	}
	for _, r := range a[n:] {
		d.AOnly = append(d.AOnly, diffEntry(r))
	}
	for _, r := range b[n:] {
		d.BOnly = append(d.BOnly, diffEntry(r))
	}
	ta, tb := touched(a[n:]), touched(b[n:])
	for obj, ids := range ta {
		if other, ok := tb[obj]; ok {
			d.BothTouched = append(d.BothTouched, DiffOverlap{Object: obj, AEntries: ids, BEntries: other})
		}
	}
	sort.Slice(d.BothTouched, func(i, j int) bool { return d.BothTouched[i].Object < d.BothTouched[j].Object })
	return d
}

// DiffLedgers compares the Blackbox histories of branches a and b (running them
// if they are suspended).
func DiffLedgers(a, b string) (LedgerDiff, error) {
	var err error
	if a, err = ledgerBranchName(a); err != nil {
		return LedgerDiff{}, err
	}
	if b, err = ledgerBranchName(b); err != nil {
		return LedgerDiff{}, err
	}
	rows := map[string][]ledger.Row{}
	for _, n := range []string{a, b} {
		if _, ok := rows[n]; ok {
			continue
		}
		if _, err := EnsureRunning(n); err != nil {
			return LedgerDiff{}, err
		}
		r, err := loadLedgerRows(n, false, "")
		if err != nil {
			return LedgerDiff{}, fmt.Errorf("reading %q's Blackbox: %w", n, err)
		}
		rows[n] = r
	}
	d := buildDiff(a, b, rows[a], rows[b])
	d.AParent, d.BParent = BranchParent(a), BranchParent(b)
	return d, nil
}

// FormatDiff renders a diff for people.
func FormatDiff(d LedgerDiff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Blackbox diff: %s vs %s\n", d.A, d.B)
	for _, p := range []struct{ name, parent string }{{d.A, d.AParent}, {d.B, d.BParent}} {
		if p.parent != "" {
			fmt.Fprintf(&b, "  %s was cloned from %s\n", p.name, p.parent)
		}
	}
	if d.CommonEntries > 0 {
		fmt.Fprintf(&b, "  shared history: %d entries, up to #%d (%s)\n", d.CommonEntries, d.ForkAfterID, d.ForkAfterAt)
	} else {
		b.WriteString("  no shared history\n")
	}
	section := func(title string, es []DiffEntry) {
		fmt.Fprintf(&b, "only on %s (%d):\n", title, len(es))
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, e := range es {
			fmt.Fprintf(tw, "  #%d\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.At, e.CommandTag, e.Object, e.Status, e.Actor)
		}
		_ = tw.Flush()
	}
	section(d.A, d.AOnly)
	section(d.B, d.BOnly)
	fmt.Fprintf(&b, "changed on both (%d):\n", len(d.BothTouched))
	for _, o := range d.BothTouched {
		fmt.Fprintf(&b, "  %s  %s %s  %s %s\n", o.Object, d.A, ids(o.AEntries), d.B, ids(o.BEntries))
	}
	return strings.TrimRight(b.String(), "\n")
}

func ids(xs []int64) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("#%d", x)
	}
	return strings.Join(parts, ",")
}
