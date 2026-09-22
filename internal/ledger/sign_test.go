// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testAnchor(to int64) Anchor {
	return Anchor{Format: "ledger-anchor/1", Algorithm: "sha256-merkle-v1", Branch: "main", CheckpointID: to,
		FromID: to - 9, ToID: to, EntryCount: 10, LastRowHash: "aa", MerkleRoot: "bb", PrevRoot: "cc",
		CreatedAt: time.Date(2026, 9, 22, 10, 0, 0, 123456000, time.UTC)}
}

func TestAnchorSignatures(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreateSigningKey(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := LoadOrCreateSigningKey(filepath.Join(dir, "k")); !again.Equal(key) {
		t.Fatal("the key changed between loads")
	}
	// Windows has no Unix permission bits: a file written 0600 reads back as
	// 0666. The key only ever lives on Linux (the engine's VM or host).
	if fi, _ := os.Stat(filepath.Join(dir, "k")); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode %v, want 0600", fi.Mode().Perm())
	}
	pub, err := ReadPublicKey(filepath.Join(dir, "k.pub"))
	if err != nil || !pub.Equal(key.Public()) {
		t.Fatalf("public key file: %v", err)
	}

	a := testAnchor(10)
	SignAnchor(&a, key)
	// Through a file and back, as a verifier sees it.
	if _, err := WriteAnchor(dir, a); err != nil {
		t.Fatal(err)
	}
	loaded, _ := LoadAnchors(dir)
	if err := CheckSignature(loaded[0], pub); err != nil {
		t.Fatalf("a genuine anchor: %v", err)
	}
	// Any field changed: the signature no longer matches.
	for name, edit := range map[string]func(*Anchor){
		"merkle_root": func(a *Anchor) { a.MerkleRoot = "forged" },
		"entry_count": func(a *Anchor) { a.EntryCount++ },
		"created_at":  func(a *Anchor) { a.CreatedAt = a.CreatedAt.Add(time.Microsecond) },
	} {
		b := loaded[0]
		edit(&b)
		if err := CheckSignature(b, pub); err == nil {
			t.Errorf("changing %s kept the signature valid", name)
		}
	}
	// Another key's signature is not this key's.
	_, other, _ := ed25519.GenerateKey(nil)
	c := testAnchor(10)
	SignAnchor(&c, other)
	if err := CheckSignature(c, pub); err == nil || !strings.Contains(err.Error(), "not") {
		t.Errorf("another key's anchor: %v", err)
	}
}

func TestVerifySignaturesSequence(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	pub := key.Public().(ed25519.PublicKey)
	signed := func(to int64) Anchor { a := testAnchor(to); SignAnchor(&a, key); return a }
	for name, tc := range map[string]struct {
		anchors []Anchor
		intact  bool
	}{
		"all signed":                  {[]Anchor{signed(10), signed(20)}, true},
		"unsigned before signing":     {[]Anchor{testAnchor(10), signed(20)}, true},
		"unsigned after a signed one": {[]Anchor{signed(10), testAnchor(20)}, false},
		"none signed yet":             {[]Anchor{testAnchor(10)}, true},
	} {
		rep := Report{Intact: true}
		VerifySignatures(&rep, tc.anchors, pub)
		if rep.Intact != tc.intact {
			t.Errorf("%s: intact=%v, want %v (%v)", name, rep.Intact, tc.intact, rep.Problems)
		}
	}
}
