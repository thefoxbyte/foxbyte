// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// anchorsIn keeps the store, the anchors and the signing key somewhere
// harmless.
func anchorsIn(t *testing.T) {
	t.Helper()
	settingsIn(t)
	storeIn(t)
	t.Setenv(brand.EnvName("ANCHOR_DIR"), t.TempDir())
	t.Setenv(brand.EnvName("ANCHOR_KEY"), filepath.Join(t.TempDir(), "anchor.key"))
}

// anchorNow does what enterprise/anchor's writer does, with the store held:
// the basis, then a signed anchor written beside the others.
func anchorNow(t *testing.T) *ledger.Anchor {
	t.Helper()
	unlock, err := lockAuditStore()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	b, err := AuditAnchorFrom()
	if err != nil {
		t.Fatalf("the basis: %v", err)
	}
	if b.Seq <= b.LastTo {
		return nil
	}
	a := ledger.Anchor{Format: AuditAnchorFormat, Algorithm: AuditAnchorAlgorithm, Branch: auditAnchorDirName,
		CheckpointID: b.Seq, FromID: b.LastTo + 1, ToID: b.Seq, EntryCount: int(b.Seq - b.LastTo),
		LastRowHash: b.Hash, MerkleRoot: b.Hash, PrevRoot: b.Prev, CreatedAt: time.Now().UTC()}
	key, err := ledger.LoadOrCreateSigningKey(AnchorKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	ledger.SignAnchor(&a, key)
	if _, err := ledger.WriteAnchor(AuditAnchorDir(), a); err != nil {
		t.Fatal(err)
	}
	return &a
}

func verified(t *testing.T) ChainReport {
	t.Helper()
	rep, err := VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// Anchors follow one another, each from the record after the last, and
// verify holds them against the store; nothing new is nothing to anchor.
func TestAuditAnchorsFollowTheChain(t *testing.T) {
	anchorsIn(t)
	seed(t, "2026-11-04", lineObject, lineTxn)
	a := anchorNow(t)
	if a == nil || a.FromID != 1 || a.ToID != 2 || a.PrevRoot != "" || a.Signature == "" {
		t.Fatalf("the first anchor: %+v", a)
	}
	if anchorNow(t) != nil {
		t.Fatal("anchored again with nothing new")
	}
	seed(t, "2026-11-05", lineObject)
	b := anchorNow(t)
	if b == nil || b.FromID != 3 || b.ToID != 3 || b.PrevRoot != a.LastRowHash {
		t.Fatalf("the second anchor does not follow the first: %+v", b)
	}
	rep := verified(t)
	if !rep.Intact || rep.Anchors != 2 || rep.Anchored != 3 || rep.Last != 3 {
		t.Fatalf("verify: %+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, "\n"), "every anchor is signed by key") {
		t.Fatalf("the signatures were not checked: %v", rep.Notes)
	}
	seed(t, "2026-11-05", lineError)
	if rep := verified(t); !rep.Intact || !strings.Contains(strings.Join(rep.Notes, "\n"), "records after 3 are not anchored yet") {
		t.Fatalf("a record after the last anchor: %+v", rep)
	}
	st := AuditAnchors()
	if st.Anchors != 2 || st.Anchored != 3 || st.Unanchored != 1 {
		t.Fatalf("the status: %+v", st)
	}
}

// What the chain alone cannot see, the anchors do: the newest records removed
// with state.json edited to match.
func TestAuditAnchorsCatchARemovedEnd(t *testing.T) {
	anchorsIn(t)
	seed(t, "2026-11-04", lineObject, lineTxn)
	anchorNow(t)
	seed(t, "2026-11-05", lineObject, lineError)
	anchorNow(t)
	// Someone with the store's files takes the last day away and puts
	// state.json back as it was after the first.
	s, _ := loadAuditState()
	recs, _ := readDay("2026-11-04")
	if err := os.Remove(dayPath("2026-11-05")); err != nil {
		t.Fatal(err)
	}
	delete(s.Days, "2026-11-05")
	s.Seq, s.Head = recs[len(recs)-1].Seq, recs[len(recs)-1].Hash
	if err := saveAuditState(s); err != nil {
		t.Fatal(err)
	}
	rep := verified(t)
	if rep.Intact || !strings.Contains(strings.Join(rep.Problems, "\n"), "anchored records were removed") {
		t.Fatalf("a removed end passed: %+v", rep)
	}
	// And the next anchor refuses to bless it.
	unlock, _ := lockAuditStore()
	_, err := AuditAnchorFrom()
	unlock()
	if err == nil || !strings.Contains(err.Error(), "not anchoring the audit log") {
		t.Fatalf("anchored a store that does not verify: %v", err)
	}
}

// A store rewritten with every hash recomputed still chains, and no longer
// matches its anchor.
func TestAuditAnchorsCatchARewrite(t *testing.T) {
	anchorsIn(t)
	seed(t, "2026-11-04", lineObject, lineTxn)
	anchorNow(t)
	recs, _ := readDay("2026-11-04")
	recs[0].Login = "someone-else"
	prev := ""
	for i := range recs {
		sealRecord(&recs[i], recs[i].Seq, prev)
		prev = recs[i].Hash
	}
	if err := os.Remove(dayPath("2026-11-04")); err != nil {
		t.Fatal(err)
	}
	size, err := appendDay("2026-11-04", recs)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := loadAuditState()
	s.Days["2026-11-04"], s.Head = size, prev
	if err := saveAuditState(s); err != nil {
		t.Fatal(err)
	}
	rep := verified(t)
	if rep.Intact || !strings.Contains(strings.Join(rep.Problems, "\n"), "record 2 no longer matches it") {
		t.Fatalf("a rewritten store passed: %+v", rep)
	}
	// The next anchor reads only what is new, and still sees it.
	unlock, _ := lockAuditStore()
	_, err = AuditAnchorFrom()
	unlock()
	if err == nil || !strings.Contains(err.Error(), "record 2, which the last anchor holds, is gone or no longer matches it") {
		t.Fatalf("anchored over a rewrite: %v", err)
	}
}

// The checks on their own: an anchor that does not follow, one taken away
// here after it was copied off, one whose record retention removed, a
// signature that does not hold.
func TestCheckAuditAnchors(t *testing.T) {
	recs := chainOf(t, lineObject, lineTxn, lineError, lineObject)
	key, err := ledger.LoadOrCreateSigningKey(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	anchor := func(from, to int64, prev string) ledger.Anchor {
		a := ledger.Anchor{Format: AuditAnchorFormat, Algorithm: AuditAnchorAlgorithm, FromID: from, ToID: to,
			LastRowHash: recs[to-1].Hash, MerkleRoot: recs[to-1].Hash, PrevRoot: prev}
		ledger.SignAnchor(&a, key)
		return a
	}
	a1 := anchor(1, 2, "")
	a2 := anchor(3, 4, a1.LastRowHash)
	check := func(recs []AuditRecord, baseSeq int64, baseHash string, anchors []ledger.Anchor, copied []string) ChainReport {
		rep := ChainReport{Intact: true}
		checkAuditAnchors(&rep, recs, baseSeq, baseHash, anchors, copied, pub)
		return rep
	}
	if rep := check(recs, 0, "", []ledger.Anchor{a2, a1}, nil); !rep.Intact || rep.Anchored != 4 {
		t.Fatalf("intact: %+v", rep)
	}
	skip := anchor(4, 4, a1.LastRowHash)
	if rep := check(recs, 0, "", []ledger.Anchor{a1, skip}, nil); rep.Intact || !strings.Contains(rep.Problems[0], "does not follow") {
		t.Fatalf("a gap between anchors: %+v", rep)
	}
	if rep := check(recs, 0, "", []ledger.Anchor{a1}, []string{ledger.AnchorFileName(4)}); rep.Intact ||
		!strings.Contains(rep.Problems[0], "copied off this machine and is gone here") {
		t.Fatalf("an anchor removed here: %+v", rep)
	}
	// Retention removed records 1 and 2: the first anchor's record is the
	// base, and still checked.
	if rep := check(recs[2:], 2, recs[1].Hash, []ledger.Anchor{a1, a2}, nil); !rep.Intact {
		t.Fatalf("after retention: %+v", rep)
	}
	if rep := check(recs[2:], 2, "edited", []ledger.Anchor{a1, a2}, nil); rep.Intact {
		t.Fatalf("an edited base passed: %+v", rep)
	}
	if rep := check(recs[3:], 3, recs[2].Hash, []ledger.Anchor{a1, a2}, nil); !rep.Intact ||
		!strings.Contains(strings.Join(rep.Notes, "\n"), "1 anchor(s) cover only records retention has removed") {
		t.Fatalf("an anchor older than retention: %+v", rep)
	}
	forged := a2
	forged.LastRowHash = recs[2].Hash
	forged.ToID = 3
	if rep := check(recs, 0, "", []ledger.Anchor{a1, forged}, nil); rep.Intact {
		t.Fatalf("an anchor changed after it was signed passed: %+v", rep)
	}
}

// Writing an anchor is Enterprise; checking one is not.
func TestAuditAnchorsAreEnterprise(t *testing.T) {
	anchorsIn(t)
	edition.SetEntitlement(nil)
	t.Cleanup(func() { edition.SetEntitlement(nil) })
	if _, err := CheckpointAuditLog(); !errors.Is(err, ErrNotLicensed) {
		t.Fatalf("anchored without a licence: %v", err)
	}
	if AuditAnchors().Writes {
		t.Fatal("says it writes anchors without a licence")
	}
	seed(t, "2026-11-04", lineObject)
	anchorNow(t) // made before the edition changed
	if rep := verified(t); !rep.Intact || rep.Anchors != 1 {
		t.Fatalf("an anchor no longer checked: %+v", rep)
	}
}
