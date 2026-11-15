// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"testing"
)

// verifyAllAtOnce is Verify as it was before the Verifier: every row in
// memory, each anchor's range sliced out and hashed whole. Kept here as the
// reference the streamed checker must agree with.
func verifyAllAtOnce(rows []Row, anchors []Anchor) Report {
	rep := Report{Problems: []string{}, Notes: []string{}}
	rows = append([]Row(nil), rows...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	rep.Rows = len(rows)
	c := chainCheck(rows, "")
	rep.ChainedRows, rep.LegacyRows, rep.FirstBrokenID = c.chained, c.legacy, c.firstBroken
	for _, p := range c.problems {
		rep.problem("%s", p)
	}
	anchors = append([]Anchor(nil), anchors...)
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].ToID < anchors[j].ToID })
	rep.Checkpoints = len(anchors)
	for i, a := range anchors {
		label := fmt.Sprintf("checkpoint %d (ledger ids %d–%d)", a.CheckpointID, a.FromID, a.ToID)
		if a.Format != AnchorFormat {
			rep.problem("%s: unknown anchor format %q", label, a.Format)
			continue
		}
		if i > 0 {
			p := anchors[i-1]
			if a.FromID != p.ToID+1 {
				rep.problem("%s does not continue checkpoint %d (ids %d–%d): anchors are missing or overlap", label, p.CheckpointID, p.FromID, p.ToID)
			}
			if a.PrevRoot != p.MerkleRoot {
				rep.problem("%s: anchor chain broken (prev_root does not match checkpoint %d)", label, p.CheckpointID)
			}
		} else if a.PrevRoot != "" {
			rep.Notes = append(rep.Notes, fmt.Sprintf("the earliest anchor here (%s) continues an older checkpoint whose anchor file is not present; rows before id %d are only hash-chain checked", label, a.FromID))
		}
		lo := sort.Search(len(rows), func(k int) bool { return rows[k].ID >= a.FromID })
		hi := sort.Search(len(rows), func(k int) bool { return rows[k].ID > a.ToID })
		in := rows[lo:hi]
		rep.AnchoredRows += len(in)
		if len(in) != a.EntryCount {
			rep.problem("%s: %d rows were anchored but the ledger now has %d in that range (rows deleted or inserted)", label, a.EntryCount, len(in))
			continue
		}
		if rootOf(in) != a.MerkleRoot {
			rep.problem("%s: the rows no longer match what was anchored (Merkle root mismatch)", label)
			continue
		}
		if RowHash(in[len(in)-1]) != a.LastRowHash {
			rep.problem("%s: the last anchored row differs from its anchor", label)
		}
	}
	if len(anchors) == 0 {
		rep.UnanchoredRows = len(rows)
	} else {
		first, last := anchors[0].FromID, anchors[len(anchors)-1].ToID
		for _, r := range rows {
			if r.ID < first || r.ID > last {
				rep.UnanchoredRows++
			}
		}
	}
	rep.Intact = len(rep.Problems) == 0
	return rep
}

func TestMerkleBuilderMatchesMerkleRoot(t *testing.T) {
	var leaves [][32]byte
	var m MerkleBuilder
	if m.Root() != "" {
		t.Error("no leaves should have no root")
	}
	for n := 1; n <= 300; n++ {
		l := LeafHash(fmt.Sprint(n), "")
		leaves = append(leaves, l)
		m.Add(l)
		if got, want := m.Root(), MerkleRoot(leaves); got != want {
			t.Fatalf("%d leaves: streamed root %s, want %s", n, got, want)
		}
	}
	one := LeafHash("x", "")
	var single MerkleBuilder
	single.Add(one)
	if single.Root() != hex.EncodeToString(one[:]) {
		t.Error("a single leaf is its own root")
	}
}

// The streamed checker and the one that held every row give the same report
// on the same input, tampered or not.
func TestVerifierMatchesVerifyAllAtOnce(t *testing.T) {
	cases := map[string]func(t *testing.T) ([]Row, []Anchor){
		"intact with a tail": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(9)
			return r, anchors(t, r, 3, 7)
		},
		"no anchors": func(t *testing.T) ([]Row, []Anchor) { return chain(5), nil },
		"no rows":    func(t *testing.T) ([]Row, []Anchor) { return nil, anchors(t, chain(4), 2, 4) },
		"broken chain": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(8)
			as := anchors(t, r, 4, 8)
			r[2].Statement = "DROP TABLE secrets"
			return r, as
		},
		"forged chain": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(8)
			as := anchors(t, r, 4, 8)
			r[5].Statement = "DROP TABLE secrets"
			rechain(r)
			return r, as
		},
		"row deleted": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(8)
			as := anchors(t, r, 4, 8)
			return append(r[:3], r[4:]...), as
		},
		"truncated stream": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(10)
			as := anchors(t, r, 5, 10)
			return r[:7], as
		},
		"capture hash changed": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(6)
			as := anchors(t, r, 3, 6)
			r[4].ExtHash = "forged"
			return r, as
		},
		"last row hash differs": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(6)
			as := anchors(t, r, 3, 6)
			as[1].LastRowHash = "nope"
			return r, as
		},
		"anchor missing, overlapping, unknown format": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(12)
			as := anchors(t, r, 3, 6, 9, 12)
			over := as[2]
			over.FromID, over.CheckpointID = 5, 9
			odd := as[3]
			odd.Format = "ledger-anchor/9"
			return r, []Anchor{as[0], over, as[2], odd}
		},
		"anchor continues an older one": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(8)
			as := anchors(t, r, 4, 8)
			return r, as[1:]
		},
		"legacy rows before the chain": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(6)
			r[0].RowHash, r[1].RowHash = "", ""
			r[2].PrevHash = ""
			rechainFrom(r, 2)
			return r, anchors(t, r, 4)
		},
		"more problems than a report shows": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(60)
			as := anchors(t, r, 30, 60)
			for i := range r {
				r[i].Statement = "edited"
			}
			return r, as
		},
		"rows out of order in the input": func(t *testing.T) ([]Row, []Anchor) {
			r := chain(6)
			as := anchors(t, r, 3, 6)
			r[1], r[4] = r[4], r[1]
			return r, as
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			rows, as := mk(t)
			want := verifyAllAtOnce(rows, as)
			got := Verify(rows, as)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("streamed report differs\n got: %+v\nwant: %+v", got, want)
			}
		})
	}
}

func rechainFrom(rows []Row, from int) {
	prev := ""
	for i := from; i < len(rows); i++ {
		rows[i].PrevHash = prev
		rows[i].RowHash = RowHash(rows[i])
		prev = rows[i].RowHash
	}
}

// Rows fed to a Verifier directly must come in id order; one that goes
// backwards is refused rather than checked against the wrong anchors.
func TestVerifierRefusesRowsOutOfOrder(t *testing.T) {
	r := chain(3)
	v := NewVerifier(nil)
	if err := v.Add(r[1]); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(r[0]); err == nil {
		t.Error("a row with a lower id was accepted")
	}
}
