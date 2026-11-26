// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Verifier is Verify one row at a time, for a ledger read as a stream.
//
// Verify takes every row at once, and the engine used to read a branch's whole
// Blackbox into memory to call it: the output of psql, then its lines, then
// the decoded rows, which for a ledger of a million entries was gigabytes for
// one `fox ledger integrity`. A Verifier keeps only what the report needs: the
// chain's last hash, the first problems found, and for each anchor whose range
// is being read, a running count, its last row's hash and a Merkle root built
// as the leaves arrive (MerkleBuilder), which is a few hashes, not one per row.
//
// The report is the same as Verify's for the same rows, problem for problem
// and in the same order: the chain's problems first, then each anchor's in
// anchor order. Rows must arrive in ascending id order, as RowsQuery returns
// them. Verify sorts first and then uses this, so there is one checker.
type Verifier struct {
	anchors []Anchor // sorted by ToID, as Verify reports them
	checks  []anchorCheck
	byFrom  []int // indices into anchors, by FromID, for opening ranges in order
	nextOpn int
	open    []int // anchors whose range the stream is inside

	first, last int64 // covered range for UnanchoredRows; only with anchors

	rows, chained, legacy int
	firstBroken           int64
	prev                  string // the last chained row's hash
	chainProblems         []string
	unanchored            int
	notes                 []string

	lastID  int64
	started bool

	// Seals (F4): what each ERASURE REDACT entry wrote, as "id:seal", to check
	// its digest when it arrives; and whether the stream began at the start
	// of the chain, without which a digest cannot be checked.
	seals     map[int64][]string
	fromStart bool
	sealed    int
}

// anchorCheck is what one anchor still needs to be checked against.
type anchorCheck struct {
	skip     bool // unknown format: reported, never compared
	problems []string
	count    int
	root     MerkleBuilder
	lastHash string
}

// NewVerifier prepares to check a ledger against anchors.
func NewVerifier(anchors []Anchor) *Verifier {
	v := &Verifier{}
	v.anchors = append([]Anchor(nil), anchors...)
	// The same call Verify always made, so anchors that tie on to_id come out
	// in the same order as they always did.
	sort.Slice(v.anchors, func(i, j int) bool { return v.anchors[i].ToID < v.anchors[j].ToID })
	v.checks = make([]anchorCheck, len(v.anchors))
	for i, a := range v.anchors {
		c := &v.checks[i]
		label := anchorLabel(a)
		if a.Format != AnchorFormat {
			c.problems = append(c.problems, fmt.Sprintf("%s: unknown anchor format %q", label, a.Format))
			c.skip = true
			continue
		}
		if i > 0 {
			p := v.anchors[i-1]
			if a.FromID != p.ToID+1 {
				c.problems = append(c.problems, fmt.Sprintf("%s does not continue checkpoint %d (ids %d–%d): anchors are missing or overlap", label, p.CheckpointID, p.FromID, p.ToID))
			}
			if a.PrevRoot != p.MerkleRoot {
				c.problems = append(c.problems, fmt.Sprintf("%s: anchor chain broken (prev_root does not match checkpoint %d)", label, p.CheckpointID))
			}
		} else if a.PrevRoot != "" {
			v.notes = append(v.notes, fmt.Sprintf("the earliest anchor here (%s) continues an older checkpoint whose anchor file is not present; rows before id %d are only hash-chain checked", label, a.FromID))
		}
		v.byFrom = append(v.byFrom, i)
	}
	sort.SliceStable(v.byFrom, func(i, j int) bool { return v.anchors[v.byFrom[i]].FromID < v.anchors[v.byFrom[j]].FromID })
	if len(v.anchors) > 0 {
		v.first, v.last = v.anchors[0].FromID, v.anchors[len(v.anchors)-1].ToID
	}
	return v
}

func anchorLabel(a Anchor) string {
	return fmt.Sprintf("checkpoint %d (ledger ids %d–%d)", a.CheckpointID, a.FromID, a.ToID)
}

// Add checks the next row. It refuses a row whose id is lower than the one
// before it: a stream out of order would be checked against the wrong anchors.
func (v *Verifier) Add(r Row) error {
	if v.started && r.ID < v.lastID {
		return fmt.Errorf("ledger rows out of order: id %d after %d", r.ID, v.lastID)
	}
	if !v.started {
		v.fromStart = r.RowHash == "" || r.PrevHash == ""
	}
	v.started, v.lastID = true, r.ID
	v.rows++
	hash := EffectiveHash(r)

	// Seals: a redacted entry counts with its original hash when its seal
	// holds; each ERASURE REDACT entry's digest covers the seals it wrote.
	if r.Seal != "" {
		v.sealed++
		if v.seals == nil {
			v.seals = map[int64][]string{}
		}
		v.seals[r.SealBy] = append(v.seals[r.SealBy], fmt.Sprintf("%d:%s", r.ID, r.Seal))
	}
	if r.CommandTag == RedactTag && v.fromStart {
		want := SealsDigest(v.seals[r.ID])
		if !strings.HasSuffix(r.Statement, "seals sha256:"+want) {
			v.chainProblem(fmt.Sprintf("ledger id %d: the seals are not the ones this erasure's redaction recorded (a seal was added, changed or removed)", r.ID))
			if v.firstBroken == 0 {
				v.firstBroken = r.ID
			}
		}
		delete(v.seals, r.ID)
	}

	// The hash chain, as chainCheck does it.
	if r.RowHash == "" {
		v.legacy++
	} else {
		v.chained++
		broken := false
		if hash != r.RowHash {
			v.chainProblem(editedProblem(r))
			broken = true
		}
		if r.PrevHash != v.prev {
			v.chainProblem(fmt.Sprintf("ledger id %d: chain link broken (an earlier row was removed or rewritten)", r.ID))
			broken = true
		}
		if broken && v.firstBroken == 0 {
			v.firstBroken = r.ID
		}
		v.prev = r.RowHash
	}

	if len(v.anchors) == 0 || r.ID < v.first || r.ID > v.last {
		v.unanchored++
	}

	// Close the ranges this row has passed, open the ones it has reached.
	kept := v.open[:0]
	for _, i := range v.open {
		if r.ID > v.anchors[i].ToID {
			continue
		}
		kept = append(kept, i)
	}
	v.open = kept
	for v.nextOpn < len(v.byFrom) && v.anchors[v.byFrom[v.nextOpn]].FromID <= r.ID {
		i := v.byFrom[v.nextOpn]
		v.nextOpn++
		if r.ID <= v.anchors[i].ToID {
			v.open = append(v.open, i)
		}
	}
	if len(v.open) > 0 {
		leaf := LeafHash(hash, r.ExtHash)
		for _, i := range v.open {
			c := &v.checks[i]
			c.count++
			c.root.Add(leaf)
			c.lastHash = hash
		}
	}
	return nil
}

// chainProblem keeps a chain problem, but only as many as a report can show:
// one past the cap is enough for the report to say more were omitted.
func (v *Verifier) chainProblem(p string) {
	if len(v.chainProblems) <= maxProblems {
		v.chainProblems = append(v.chainProblems, p)
	}
}

// Report is the outcome so far, which once every row has been added is the
// same report Verify gives.
func (v *Verifier) Report() Report {
	rep := Report{Problems: []string{}, Notes: append([]string{}, v.notes...)}
	rep.Rows = v.rows
	rep.ChainedRows, rep.LegacyRows, rep.FirstBrokenID = v.chained, v.legacy, v.firstBroken
	for _, p := range v.chainProblems {
		rep.problem("%s", p)
	}
	rep.Checkpoints = len(v.anchors)
	for i, a := range v.anchors {
		c := &v.checks[i]
		for _, p := range c.problems {
			rep.problem("%s", p)
		}
		if c.skip {
			continue
		}
		label := anchorLabel(a)
		rep.AnchoredRows += c.count
		if c.count != a.EntryCount {
			rep.problem("%s: %d rows were anchored but the ledger now has %d in that range (rows deleted or inserted)", label, a.EntryCount, c.count)
			continue
		}
		if c.root.Root() != a.MerkleRoot {
			rep.problem("%s: the rows no longer match what was anchored (Merkle root mismatch)", label)
			continue
		}
		if c.count > 0 && c.lastHash != a.LastRowHash {
			rep.problem("%s: the last anchored row differs from its anchor", label)
		}
	}
	rep.UnanchoredRows = v.unanchored
	// A seal no redaction in the stream wrote: added afterwards. Only for
	// writers the stream has reached; a later one may yet come.
	var orphans []int64
	for by := range v.seals {
		if v.fromStart && by <= v.lastID {
			orphans = append(orphans, by)
		}
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i] < orphans[j] })
	for _, by := range orphans {
		rep.problem("seals name entry %d as the redaction that wrote them, and it is not one (a seal was added afterwards)", by)
	}
	if v.sealed > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d entries were redacted by erasure requests, and are checked by their seals", v.sealed))
	}
	rep.Sealed = v.sealed
	rep.Intact = len(rep.Problems) == 0
	return rep
}

// MerkleBuilder computes MerkleRoot over leaves added one at a time, holding
// one pending node per level of the tree rather than every leaf.
type MerkleBuilder struct {
	n       int
	pending []*[32]byte // pending[i]: a complete subtree of 2^i leaves waiting for its pair
}

// Add appends a leaf.
func (m *MerkleBuilder) Add(leaf [32]byte) {
	m.n++
	node := leaf
	for i := 0; ; i++ {
		if i == len(m.pending) {
			m.pending = append(m.pending, nil)
		}
		if m.pending[i] == nil {
			n := node
			m.pending[i] = &n
			return
		}
		node = merkleNode(*m.pending[i], node)
		m.pending[i] = nil
	}
}

// Root is MerkleRoot of the leaves added so far, as hex ("" for none).
//
// MerkleRoot duplicates the last node of any odd-sized level. Level i of a
// tree of n leaves has ceil(n/2^i) nodes; the complete pairs were joined as
// they arrived, so what is left at each level is at most a pending node and
// the node carried up from the incomplete tail below it, and the rule decides
// how those two join.
func (m *MerkleBuilder) Root() string {
	if m.n == 0 {
		return ""
	}
	var carry *[32]byte
	size := m.n
	for i := 0; size > 1; i++ {
		var p *[32]byte
		if i < len(m.pending) {
			p = m.pending[i]
		}
		switch {
		case p != nil && carry != nil:
			n := merkleNode(*p, *carry)
			carry = &n
		case p != nil:
			n := merkleNode(*p, *p)
			carry = &n
		case carry != nil:
			n := merkleNode(*carry, *carry)
			carry = &n
		}
		size = (size + 1) / 2
	}
	// One node is left at the top level: the pending one, or the carry.
	top := carry
	if top == nil {
		for i := len(m.pending) - 1; i >= 0; i-- {
			if m.pending[i] != nil {
				top = m.pending[i]
				break
			}
		}
	}
	return hex.EncodeToString(top[:])
}

func merkleNode(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l[:])
	h.Write(r[:])
	var n [32]byte
	copy(n[:], h.Sum(nil))
	return n
}
