// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
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

// commonPrefix is how many entries two histories share: same id, same recomputed
// hash. A branch starts as a copy of its parent's Blackbox, so this is the fork
// point — everything after it happened on one side only. Used by the diff and by
// promotion (promote.go), which must agree about where the branches split.
func commonPrefix(a, b []ledger.Row) int {
	n := 0
	// The effective hash: an entry an erasure redacted on one branch and not
	// (yet) on the other is still the same entry, by the hash it was chained
	// with (F4).
	for n < len(a) && n < len(b) && a[n].ID == b[n].ID && ledger.EffectiveHash(a[n]) == ledger.EffectiveHash(b[n]) {
		n++
	}
	return n
}

// diffBuilder assembles a LedgerDiff from a fork walk (LedgerFork). It keeps
// only what the diff shows: a short summary of each entry after the fork, and
// the ids of the objects each side touched. The shared history, and every
// statement's text, are never held.
type diffBuilder struct {
	d      LedgerDiff
	ta, tb map[string][]int64
}

func newDiffBuilder(aName, bName string) *diffBuilder {
	return &diffBuilder{
		d:  LedgerDiff{A: aName, B: bName, AOnly: []DiffEntry{}, BOnly: []DiffEntry{}, BothTouched: []DiffOverlap{}},
		ta: map[string][]int64{}, tb: map[string][]int64{},
	}
}

func (b *diffBuilder) visitor() LedgerFork {
	touch := func(m map[string][]int64, r ledger.Row) {
		if r.ObjectIdentity != "" && r.Status != "BLOCKED" { // a blocked change didn't happen
			m[r.ObjectIdentity] = append(m[r.ObjectIdentity], r.ID)
		}
	}
	return LedgerFork{
		Fork: func(n int, last *ledger.Row) {
			b.d.CommonEntries = n
			if last != nil {
				b.d.ForkAfterID = last.ID
				b.d.ForkAfterAt = last.At.UTC().Format(time.RFC3339)
			}
		},
		OnlyA: func(r ledger.Row) { b.d.AOnly = append(b.d.AOnly, diffEntry(r)); touch(b.ta, r) },
		OnlyB: func(r ledger.Row) { b.d.BOnly = append(b.d.BOnly, diffEntry(r)); touch(b.tb, r) },
	}
}

func (b *diffBuilder) finish() LedgerDiff {
	for obj, ids := range b.ta {
		if other, ok := b.tb[obj]; ok {
			b.d.BothTouched = append(b.d.BothTouched, DiffOverlap{Object: obj, AEntries: ids, BEntries: other})
		}
	}
	sort.Slice(b.d.BothTouched, func(i, j int) bool { return b.d.BothTouched[i].Object < b.d.BothTouched[j].Object })
	return b.d
}

// buildDiff compares two id-ordered histories already in memory.
func buildDiff(aName, bName string, a, b []ledger.Row) LedgerDiff {
	db := newDiffBuilder(aName, bName)
	WalkRowsFork(a, b, db.visitor())
	return db.finish()
}

// DiffLedgers compares the Blackbox histories of branches a and b (running them
// if they are suspended). Both are read as streams, side by side
// (WalkLedgerFork), so neither ledger is held in memory.
func DiffLedgers(a, b string) (LedgerDiff, error) {
	var err error
	if a, err = ledgerBranchName(a); err != nil {
		return LedgerDiff{}, err
	}
	if b, err = ledgerBranchName(b); err != nil {
		return LedgerDiff{}, err
	}
	names := []string{a, b}
	if a == b {
		names = names[:1]
	}
	for _, n := range names {
		if _, err := EnsureRunning(n); err != nil {
			return LedgerDiff{}, err
		}
	}
	db := newDiffBuilder(a, b)
	if err := WalkLedgerFork(a, b, db.visitor()); err != nil {
		return LedgerDiff{}, err
	}
	d := db.finish()
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
