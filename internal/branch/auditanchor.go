// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Anchors for the audit log's chain (F6 Gate 1, step 6; design, sections 9
// and 14).
//
// The chain shows a record changed, or taken out of the middle. It cannot show
// the newest records removed with state.json edited to match, or the whole
// store rewritten with every hash recomputed: whoever can write the store can
// do both. An anchor is the chain's head at one moment, signed with the
// install's anchor key and kept outside the store: beside the Blackbox's and
// the security log's anchors, copied to the backup bucket, and locked in the
// anchor target when there is one. Verify checks the store against each.
//
// Writing them is Enterprise (enterprise/anchor), as the Blackbox's are.
// Checking them is free in every edition, so an install that anchored can
// still prove it after changing edition.

const (
	auditAnchorDirName = "_audit-log" // beside the branches' directories: no branch name starts with '_'
	// AuditAnchorFormat and AuditAnchorAlgorithm name what an audit log anchor
	// is: LastRowHash (and MerkleRoot) is the hash of record ToID, and
	// PrevRoot the anchor before's LastRowHash.
	AuditAnchorFormat    = "audit-anchor/1"
	AuditAnchorAlgorithm = "sha256-chain-v1"
)

// AuditAnchorDir is where the audit log's anchors are written.
func AuditAnchorDir() string { return filepath.Join(anchorBase(), auditAnchorDirName) }

// writeAuditAnchor is the paid half, supplied by enterprise/anchor in an
// Enterprise build and nil in a Standard one.
var writeAuditAnchor func() (*ledger.Anchor, error)

// SetAuditAnchorWriter installs it. Called from enterprise/anchor's init, and
// from nowhere else.
func SetAuditAnchorWriter(fn func() (*ledger.Anchor, error)) { writeAuditAnchor = fn }

// CheckpointAuditLog anchors the records collected since the last anchor, and
// copies the anchor off this machine. It returns nil when there is nothing new.
func CheckpointAuditLog() (*ledger.Anchor, error) {
	if err := requireFeature(edition.Anchors); err != nil {
		return nil, err
	}
	if writeAuditAnchor == nil {
		return nil, ErrAnchorsNotLicensed
	}
	if _, err := os.Stat(AuditStoreDir()); errors.Is(err, os.ErrNotExist) {
		return nil, nil // never collected: nothing to anchor
	}
	// Held while the head is read and the anchor written: a collection in
	// between would move the head, and a second writer would make an anchor
	// that does not follow this one.
	unlock, err := lockAuditStore()
	if err != nil {
		return nil, err
	}
	a, err := writeAuditAnchor()
	unlock()
	if err != nil || a == nil {
		return a, err
	}
	if _, err := MirrorAnchors(); err != nil {
		log.Printf("audit log anchor: copying it to the backup target: %v", err)
	}
	return a, nil
}

// AuditAnchorBasis is what the next anchor is made from.
type AuditAnchorBasis struct {
	LastTo int64  // the last anchor's last record (0 before the first)
	Prev   string // its hash
	Seq    int64  // the store's last record
	Hash   string
}

// AuditAnchorFrom reads the last anchor and the store's head, with the store
// held (CheckpointAuditLog holds it). It refuses records that do not verify:
// an anchor over a broken chain would bless it. After the first anchor only
// the records since the last are checked, so a year of records is not read
// every ten minutes; verify reads them all.
func AuditAnchorFrom() (AuditAnchorBasis, error) {
	var b AuditAnchorBasis
	anchors, err := ledger.LoadAnchors(AuditAnchorDir())
	if err != nil {
		return b, err
	}
	for _, a := range anchors {
		if a.ToID > b.LastTo {
			b.LastTo, b.Prev = a.ToID, a.LastRowHash
		}
	}
	s, err := loadAuditState()
	if err != nil {
		return b, err
	}
	refuse := func(why string) (AuditAnchorBasis, error) {
		return b, fmt.Errorf("not anchoring the audit log: %s — inspect with: %s audit-log verify", why, brand.CLI)
	}
	if b.LastTo == 0 || b.LastTo <= s.Base.Seq {
		rep, err := VerifyAudit()
		if err != nil {
			return b, err
		}
		if !rep.Intact {
			return refuse(strings.Join(rep.Problems, "; "))
		}
		b.Seq, b.Hash = rep.Last, rep.LastHash
		return b, nil
	}
	// From the record the last anchor holds, which must still be as anchored.
	recs, err := auditTail(b.LastTo - 1)
	if err != nil {
		return refuse(err.Error())
	}
	if len(recs) == 0 || recs[0].Seq != b.LastTo || recs[0].Hash != b.Prev {
		return refuse(fmt.Sprintf("record %d, which the last anchor holds, is gone or no longer matches it", b.LastTo))
	}
	recs = recs[1:]
	rep := verifyChain(recs, b.LastTo, b.Prev)
	b.Seq, b.Hash = b.LastTo, b.Prev
	if n := len(recs); n > 0 {
		b.Seq, b.Hash = recs[n-1].Seq, recs[n-1].Hash
	}
	switch {
	case !rep.Intact:
		return refuse(strings.Join(rep.Problems, "; "))
	case b.Seq != s.Seq || b.Hash != s.Head:
		return refuse(fmt.Sprintf("the store ends at record %d, and the collector wrote up to %d", b.Seq, s.Seq))
	}
	return b, nil
}

// auditTail reads the records after seq, in order, from the newest day file
// back to the one that holds seq.
func auditTail(seq int64) ([]AuditRecord, error) {
	days := storedDays()
	var parts [][]AuditRecord
	for i := len(days) - 1; i >= 0; i-- {
		recs, err := readDay(days[i])
		if err != nil {
			return nil, fmt.Errorf("the records of %s cannot all be read (%v)", days[i], err)
		}
		parts = append(parts, recs)
		if len(recs) > 0 && recs[0].Seq <= seq+1 {
			break
		}
	}
	var out []AuditRecord
	for i := len(parts) - 1; i >= 0; i-- {
		for _, r := range parts[i] {
			if r.Seq > seq {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// AuditAnchorStatus is how far anchoring has got, for the status and the
// console: no verifying, so it is cheap.
type AuditAnchorStatus struct {
	Anchors    int   `json:"anchors"`
	Anchored   int64 `json:"anchored"`   // the last record an anchor covers
	Unanchored int64 `json:"unanchored"` // records collected since
	Writes     bool  `json:"writes"`     // whether this install writes them (Enterprise)
	Locked     int   `json:"locked"`     // anchors copied to the anchor target, under Object Lock
}

// AuditAnchors reads the audit log's anchors and the store's head.
func AuditAnchors() AuditAnchorStatus {
	st := AuditAnchorStatus{Writes: edition.Has(edition.Anchors) && writeAuditAnchor != nil}
	anchors, _ := ledger.LoadAnchors(AuditAnchorDir())
	st.Anchors = len(anchors)
	for _, a := range anchors {
		st.Anchored = max(st.Anchored, a.ToID)
		if _, err := os.Stat(filepath.Join(AuditAnchorDir(), ledger.AnchorFileName(a.ToID)+lockedSuffix)); err == nil {
			st.Locked++
		}
	}
	if s, err := loadAuditState(); err == nil {
		st.Unanchored = max(0, s.Seq-st.Anchored)
	}
	return st
}

// checkAuditAnchors checks the records against every anchor: each follows the
// one before it, and the record it names is there and unchanged. recs are the
// store's records in order; baseSeq and baseHash the record before the first
// kept, which retention removed. copied are the anchors copied off this
// machine, by file name, which must still be here. pub, when not nil, checks
// their signatures.
func checkAuditAnchors(rep *ChainReport, recs []AuditRecord, baseSeq int64, baseHash string,
	anchors []ledger.Anchor, copied []string, pub ed25519.PublicKey) {
	sorted := append([]ledger.Anchor(nil), anchors...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ToID < sorted[j].ToID })
	have := map[string]bool{}
	for _, a := range sorted {
		have[ledger.AnchorFileName(a.ToID)] = true
	}
	for _, name := range copied {
		if !have[name] {
			rep.Problems = append(rep.Problems, fmt.Sprintf("anchor %s was copied off this machine and is gone here: the copy shows what was anchored", name))
		}
	}
	if len(sorted) == 0 {
		rep.Intact = len(rep.Problems) == 0
		return
	}
	hashOf := make(map[int64]string, len(recs))
	last := baseSeq
	for _, r := range recs {
		hashOf[r.Seq] = r.Hash
		last = r.Seq
	}
	var lastTo int64
	prev, removed := "", 0
	for _, a := range sorted {
		bad := func(format string, args ...any) {
			rep.Problems = append(rep.Problems, fmt.Sprintf("anchor %s: ", ledger.AnchorFileName(a.ToID))+fmt.Sprintf(format, args...))
		}
		switch {
		case a.Format != AuditAnchorFormat || a.Algorithm != AuditAnchorAlgorithm:
			bad("not an audit log anchor (%s, %s)", a.Format, a.Algorithm)
		case a.FromID != lastTo+1 || a.PrevRoot != prev:
			bad("does not follow the anchor before it")
		case a.ToID > last:
			bad("it anchors records up to %d, and the store ends at %d: anchored records were removed", a.ToID, last)
		case a.ToID < baseSeq:
			removed++ // its record went with retention: the anchors after it still hold
		case a.ToID == baseSeq:
			if a.LastRowHash != baseHash {
				bad("record %d, the last retention removed, no longer matches it", a.ToID)
			}
		default:
			h, ok := hashOf[a.ToID]
			switch {
			case !ok:
				bad("record %d, which it anchors, is gone", a.ToID)
			case h != a.LastRowHash:
				bad("record %d no longer matches it", a.ToID)
			}
		}
		lastTo, prev = a.ToID, a.LastRowHash
	}
	rep.Anchors, rep.Anchored = len(sorted), lastTo
	if removed > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d anchor(s) cover only records retention has removed", removed))
	}
	if last > lastTo {
		rep.Notes = append(rep.Notes, fmt.Sprintf("records after %d are not anchored yet", lastTo))
	}
	if pub != nil {
		lr := ledger.Report{Intact: true}
		ledger.VerifySignatures(&lr, sorted, pub)
		rep.Problems = append(rep.Problems, lr.Problems...)
		rep.Notes = append(rep.Notes, lr.Notes...)
	}
	rep.Intact = len(rep.Problems) == 0
}

// copiedAuditAnchors lists the anchors marked as copied to the backup bucket
// or the anchor target.
func copiedAuditAnchors() []string {
	entries, _ := os.ReadDir(AuditAnchorDir())
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, suffix := range []string{mirroredSuffix, lockedSuffix} {
			if name, ok := strings.CutSuffix(e.Name(), suffix); ok && strings.HasSuffix(name, ".json") && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}
