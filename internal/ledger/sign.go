// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Anchor signatures (audit v2 G17). An anchor proves the rows it covers only
// as long as the anchor itself is genuine, and an anchor is a file: whoever can
// write the anchor directory could write a new one to match rewritten rows. A
// signature by a key the database cannot reach — kept in the engine's state
// directory, or wherever FOX_ANCHOR_KEY points — lets anyone holding the
// public key tell a genuine anchor from a forged one, wherever the anchor is
// copied. It does not help against someone who holds the private key too: on
// one machine, that is its administrator. Keep the key elsewhere (a mounted
// secret) and the public key with whoever verifies.

// SigningPayload is exactly what an anchor's signature covers: every field but
// the signature, in a fixed order, one per line. Defined here once so the
// writer and every verifier agree; documented in docs/ledger-anchor-format.md.
func SigningPayload(a Anchor) []byte {
	fields := []string{
		"ledger-anchor-signature/1",
		a.Format, a.Algorithm, a.Branch,
		strconv.FormatInt(a.CheckpointID, 10),
		strconv.FormatInt(a.FromID, 10),
		strconv.FormatInt(a.ToID, 10),
		strconv.Itoa(a.EntryCount),
		a.LastRowHash, a.MerkleRoot, a.PrevRoot,
		a.CreatedAt.UTC().Format(time.RFC3339Nano),
		a.KeyID,
	}
	return []byte(strings.Join(fields, "\n") + "\n")
}

// KeyID names a public key: the first 16 bytes of its SHA-256, in hex.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:16])
}

// SignAnchor fills in a's key id and signature.
func SignAnchor(a *Anchor, key ed25519.PrivateKey) {
	a.KeyID = KeyID(key.Public().(ed25519.PublicKey))
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, SigningPayload(*a)))
}

// CheckSignature reports whether a is signed by pub.
func CheckSignature(a Anchor, pub ed25519.PublicKey) error {
	if a.Signature == "" {
		return errors.New("not signed")
	}
	if a.KeyID != KeyID(pub) {
		return fmt.Errorf("signed by key %s, not %s", a.KeyID, KeyID(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil || !ed25519.Verify(pub, SigningPayload(a), sig) {
		return errors.New("the signature does not match its contents")
	}
	return nil
}

// VerifySignatures checks a branch's anchors against the public key a verifier
// trusts, and adds what it finds to the report. Anchors written before signing
// existed are unsigned; they are accepted only before the first signed one —
// an unsigned anchor after it can only be a forgery or a downgrade.
func VerifySignatures(rep *Report, anchors []Anchor, pub ed25519.PublicKey) {
	anchors = append([]Anchor(nil), anchors...)
	sort.Slice(anchors, func(i, j int) bool { return anchors[i].ToID < anchors[j].ToID })
	signedSeen, unsignedEarly := false, 0
	for _, a := range anchors {
		if a.Signature == "" && !signedSeen {
			unsignedEarly++
			continue
		}
		if err := CheckSignature(a, pub); err != nil {
			rep.Intact = false
			rep.problem("anchor %s (entries %d–%d): %v", AnchorFileName(a.ToID), a.FromID, a.ToID, err)
			continue
		}
		signedSeen = true
	}
	switch {
	case len(anchors) == 0:
	case unsignedEarly == len(anchors):
		rep.Notes = append(rep.Notes, "no anchor is signed yet (they were written before anchor signing existed)")
	case unsignedEarly > 0:
		rep.Notes = append(rep.Notes, fmt.Sprintf("%d early anchor(s) predate signing; every later one is signed by key %s", unsignedEarly, KeyID(pub)))
	default:
		rep.Notes = append(rep.Notes, fmt.Sprintf("every anchor is signed by key %s", KeyID(pub)))
	}
}

// ---- key files ----

const (
	privPEM = "FOXBYTE ANCHOR SIGNING KEY"
	pubPEM  = "FOXBYTE ANCHOR PUBLIC KEY"
)

// LoadOrCreateSigningKey reads the Ed25519 signing key at path, creating it
// (0600) with its public key beside it (path + ".pub", 0644) when there is none.
func LoadOrCreateSigningKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != privPEM || len(blk.Bytes) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s is not an anchor signing key", path)
		}
		return ed25519.NewKeyFromSeed(blk.Bytes), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) { // another process made it first
			return LoadOrCreateSigningKey(path)
		}
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: privPEM, Bytes: key.Seed()}); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path+".pub", EncodePublicKey(pub), 0o644); err != nil {
		return nil, err
	}
	return key, nil
}

// EncodePublicKey writes a public key in the form fox-verify --pubkey reads.
func EncodePublicKey(pub ed25519.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pubPEM, Headers: map[string]string{"Key-ID": KeyID(pub)}, Bytes: pub})
}

// ReadPublicKey reads a public key written by EncodePublicKey.
func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != pubPEM || len(blk.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is not an anchor public key", path)
	}
	return ed25519.PublicKey(blk.Bytes), nil
}
