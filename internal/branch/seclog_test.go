// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

func TestVerifySecurityLog(t *testing.T) {
	s, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 6; i++ {
		s.Audit(auth.EvLoginOK, "a@x.com", "", "127.0.0.1", "")
	}
	evs, _ := s.SecurityEvents(0, 0)
	_, key, _ := ed25519.GenerateKey(nil)
	pub := key.Public().(ed25519.PublicKey)
	anchor := func(from, to int64, prev string) ledger.Anchor {
		a := ledger.Anchor{Format: secAnchorFormat, Algorithm: secAnchorAlgorithm, Branch: secLogAnchorDir,
			CheckpointID: to, FromID: from, ToID: to, EntryCount: int(to - from + 1),
			LastRowHash: evs[to-1].RowHash, MerkleRoot: evs[to-1].RowHash, PrevRoot: prev, CreatedAt: time.Now().UTC()}
		ledger.SignAnchor(&a, key)
		return a
	}
	a1 := anchor(1, 4, "")
	anchors := []ledger.Anchor{a1}

	if rep := VerifySecurityLog(evs, anchors, pub); !rep.Intact || rep.AnchoredRows != 4 || rep.UnanchoredRows != 2 {
		t.Fatalf("a genuine log: %+v", rep)
	}
	// An anchored event rewritten, with every hash after it recomputed — the
	// chain alone is fooled, the anchor is not.
	forged := append([]auth.SecurityEvent(nil), evs...)
	forged[2].Actor = "nobody"
	for i := 2; i < len(forged); i++ {
		if i > 0 {
			forged[i].PrevHash = forged[i-1].RowHash
		}
		forged[i].RowHash = auth.EventHash(forged[i])
	}
	if id, _ := auth.CheckEventChain(forged); id != 0 {
		t.Fatal("test setup: the forged chain should verify on its own")
	}
	if rep := VerifySecurityLog(forged, anchors, pub); rep.Intact {
		t.Error("a rewritten, re-hashed log passed against its anchor")
	}
	// The anchor rewritten to match the forgery: its signature no longer holds.
	fake := a1
	fake.LastRowHash, fake.MerkleRoot = forged[3].RowHash, forged[3].RowHash
	if rep := VerifySecurityLog(forged, []ledger.Anchor{fake}, pub); rep.Intact {
		t.Error("a forged anchor passed the signature check")
	}
	// Events cut from the end of an anchored range.
	if rep := VerifySecurityLog(evs[:3], anchors, pub); rep.Intact {
		t.Error("a log missing anchored events passed")
	}
}
