// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// The security log (auth.Store.Audit) is anchored like a branch's Blackbox: a
// signed file outside the store records the chain's head, so rewriting the
// log — recomputing every hash — no longer matches an anchor. Its anchors live
// in a directory of their own beside the branches' ("_security-log": no branch
// name starts with '_').

const secLogAnchorDir = "_security-log"

// SecurityLogAnchorDir is where the security log's anchors are written.
func SecurityLogAnchorDir() string {
	base := strings.TrimSpace(brand.Getenv("ANCHOR_DIR"))
	if base == "" {
		base = brand.StatePath("anchors")
	}
	return filepath.Join(base, secLogAnchorDir)
}

const (
	secAnchorFormat    = "security-anchor/1"
	secAnchorAlgorithm = "sha256-chain-v1" // LastRowHash is the head of auth.EventHash's chain
)

// secLogCheckPageSize is how many events a checkpoint holds at once. A variable
// so a test can reach a page boundary without writing thousands of events.
var secLogCheckPageSize = 5000

// CheckpointSecurityLog anchors the security log's events added since its last
// anchor. It returns nil when there is nothing new.
//
// It verifies incrementally, so its cost follows what is new rather than how
// long the log has grown. Before anchoring it checks:
//   - that the last anchored event is still there, is unchanged, and has the
//     hash the anchor signed;
//   - that every event since chains from that hash, with no id missing and no
//     event changed.
//
// So it catches any edit after the last anchor, and any rewrite of older
// events that was re-hashed through to the present, because that changes the
// hash the new events chain from.
//
// It does not re-read events before the last anchored one. An older event
// edited in place, with the rows after it left alone, is not noticed here and
// this will go on anchoring; nor are the older anchors or any signature looked
// at. `fox audit verify` (VerifySecurityLog) checks every event against every
// anchor and is what catches those: this is a guard against anchoring a log
// already known to be bad, and passing it says nothing about the older rows.
func CheckpointSecurityLog(store *auth.Store) (*ledger.Anchor, error) {
	dir := SecurityLogAnchorDir()
	anchors, err := ledger.LoadAnchors(dir)
	if err != nil {
		return nil, err
	}
	var lastTo int64
	prev := ""
	for _, a := range anchors {
		if a.ToID > lastTo {
			lastTo, prev = a.ToID, a.LastRowHash
		}
	}
	page, err := store.SecurityEvents(lastTo, secLogCheckPageSize)
	if err != nil || len(page) == 0 {
		return nil, err
	}
	// Refuse to anchor a log that no longer chains: that would bless it.
	refuse := func(why string) (*ledger.Anchor, error) {
		return nil, fmt.Errorf("not anchoring the security log: %s — inspect with: %s audit verify", why, brand.CLI)
	}
	if lastTo > 0 {
		anchored, err := store.SecurityEvents(lastTo-1, 1)
		if err != nil {
			return nil, err
		}
		if len(anchored) != 1 || anchored[0].ID != lastTo {
			return refuse(fmt.Sprintf("event %d, the last one anchored, is gone", lastTo))
		}
		if e := anchored[0]; e.RowHash != prev || auth.EventHash(e) != e.RowHash {
			return refuse(fmt.Sprintf("event %d no longer matches its anchor", lastTo))
		}
	}
	var head auth.SecurityEvent
	n, after, hash := 0, lastTo, prev
	for {
		if id, why := auth.CheckEventChainFrom(page, after, hash); id != 0 {
			return refuse(why)
		}
		head = page[len(page)-1]
		n, after, hash = n+len(page), head.ID, head.RowHash
		if len(page) < secLogCheckPageSize {
			break
		}
		if page, err = store.SecurityEvents(after, secLogCheckPageSize); err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
	}
	a := ledger.Anchor{Format: secAnchorFormat, Algorithm: secAnchorAlgorithm, Branch: secLogAnchorDir,
		CheckpointID: head.ID, FromID: lastTo + 1, ToID: head.ID, EntryCount: n,
		LastRowHash: head.RowHash, MerkleRoot: head.RowHash, PrevRoot: prev, CreatedAt: time.Now().UTC()}
	key, err := ledger.LoadOrCreateSigningKey(AnchorKeyPath())
	if err != nil {
		return nil, err
	}
	ledger.SignAnchor(&a, key)
	if _, err := ledger.WriteAnchor(dir, a); err != nil {
		return nil, err
	}
	if _, err := MirrorAnchors(); err != nil {
		fmt.Fprintf(os.Stderr, "security log anchor: copying it to the backup target: %v\n", err)
	}
	return &a, nil
}

// VerifySecurityLog checks the security log's chain, its anchors, and — when
// pub is not nil — their signatures.
func VerifySecurityLog(evs []auth.SecurityEvent, anchors []ledger.Anchor, pub ed25519.PublicKey) ledger.Report {
	rep := ledger.Report{Intact: true, Rows: len(evs), ChainedRows: len(evs), Checkpoints: len(anchors), Problems: []string{}, Notes: []string{}}
	if id, why := auth.CheckEventChain(evs); id != 0 {
		rep.Intact, rep.FirstBrokenID = false, id
		rep.Problems = append(rep.Problems, why)
	}
	byID := map[int64]auth.SecurityEvent{}
	for _, e := range evs {
		byID[e.ID] = e
	}
	sorted := append([]ledger.Anchor(nil), anchors...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ToID < sorted[j].ToID })
	var lastTo int64
	prev := ""
	for _, a := range sorted {
		bad := func(format string, args ...any) {
			rep.Intact = false
			rep.Problems = append(rep.Problems, fmt.Sprintf("anchor %s: ", ledger.AnchorFileName(a.ToID))+fmt.Sprintf(format, args...))
		}
		switch {
		case a.Format != secAnchorFormat || a.Algorithm != secAnchorAlgorithm:
			bad("not a security-log anchor (%s, %s)", a.Format, a.Algorithm)
		case a.FromID != lastTo+1 || a.PrevRoot != prev:
			bad("does not follow the anchor before it")
		default:
			e, ok := byID[a.ToID]
			n := 0
			for id := a.FromID; id <= a.ToID; id++ {
				if _, ok := byID[id]; ok {
					n++
				}
			}
			switch {
			case !ok:
				bad("event %d, which it anchors, is gone", a.ToID)
			case e.RowHash != a.LastRowHash:
				bad("event %d no longer matches it", a.ToID)
			case n != a.EntryCount:
				bad("it anchors %d events, and %d are there", a.EntryCount, n)
			}
			rep.AnchoredRows += n
		}
		lastTo, prev = a.ToID, a.LastRowHash
	}
	rep.UnanchoredRows = len(evs) - rep.AnchoredRows
	if pub != nil {
		ledger.VerifySignatures(&rep, sorted, pub)
	}
	return rep
}
