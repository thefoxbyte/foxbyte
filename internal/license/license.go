// SPDX-License-Identifier: AGPL-3.0-or-later

// Package license reads and checks the file that unlocks the paid edition.
//
// A licence is JSON plus an Ed25519 signature over a canonical rendering of its
// own fields. Only the public half ships, built into fox the way the release
// key is (internal/update/signing.go), so a licence cannot be minted from this
// source — the private half exists in one place and never in CI.
//
// Three things this deliberately is not:
//
//   - It is not copy protection. The binary is source-available and the check
//     can be removed by anyone willing to. A hard lock would stop none of them
//     and would stop honest users whose VM was rebuilt, so the fingerprint
//     warns and only expiry refuses.
//   - It never gates the engine. A lapsed licence may stop new paid work; it
//     may not stop a database, and it may not stop reading or verifying
//     anything already recorded. A billing event is not an outage.
//   - It is not a server. There is no call home, by design, which is also why
//     the rebind counter below is a deterrent with evidence rather than a
//     proof.
package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Format is the only licence format there is, named in the signing payload so a
// later one cannot be passed off as this one.
const Format = "foxbyte-license/1"

// Grace is how long a licence keeps working past something being wrong with it.
// A cliff on a weekend is how a billing mistake becomes an outage, so expiry
// warns for this long before paid features refuse, and a fingerprint that no
// longer matches only ever warns.
const Grace = 14 * 24 * time.Hour

// A License is what a customer is given. Every field below is signed; the
// signature is not, because it cannot cover itself.
type License struct {
	Format   string    `json:"format"`
	ID       string    `json:"id"`       // ours, for support and for the audit trail
	Customer string    `json:"customer"` // who it was issued to, shown by `fox license show`
	Edition  string    `json:"edition"`  // "enterprise"
	Features []string  `json:"features"`
	IssuedAt time.Time `json:"issued_at"`
	NotAfter time.Time `json:"not_after"`
	// Fingerprint is the machine this was activated for, hashed. Empty means a
	// licence not tied to one at all, which is what a site licence is.
	Fingerprint string `json:"fingerprint"`
	// RebindsAllowed is how many times the fingerprint may change. The count of
	// how many have been used lives beside the licence, not in it: it cannot,
	// because the licence is signed and we are not re-signing one per rebind.
	RebindsAllowed int `json:"rebinds_allowed"`
	// KeyID names the key that signed this, so a key can be rotated without
	// invalidating every licence already issued. It is inside the payload: a
	// key id a forger could edit would name whichever key they liked.
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// SigningPayload is exactly what a signature covers: every field but the
// signature, in a fixed order, one per line, after a line naming the format.
// Defined here once so the signer and every verifier agree — the same shape as
// an anchor's payload (internal/ledger/sign.go), for the same reason.
//
// Times are RFC3339 in UTC and features are sorted, so two renderings of the
// same licence cannot differ by a timezone or a map's iteration order.
func SigningPayload(l License) []byte {
	features := append([]string(nil), l.Features...)
	sort.Strings(features)
	fields := []string{
		Format,
		l.ID,
		l.Customer,
		l.Edition,
		strings.Join(features, ","),
		l.IssuedAt.UTC().Format(time.RFC3339),
		l.NotAfter.UTC().Format(time.RFC3339),
		l.Fingerprint,
		strconv.Itoa(l.RebindsAllowed),
		l.KeyID,
	}
	return []byte(strings.Join(fields, "\n") + "\n")
}

// KeyID names a public key: the first 16 bytes of its SHA-256, in hex. Same
// definition as the anchor format's, so one tool can print either.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:16])
}

// Sign fills in the key id and the signature. Used by cmd/licensesign; nothing
// in the shipped binary calls it, because nothing in the shipped binary has a
// private key.
func Sign(l *License, key ed25519.PrivateKey) {
	l.Format = Format
	l.KeyID = KeyID(key.Public().(ed25519.PublicKey))
	l.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, SigningPayload(*l)))
}

// ErrNoKey means this build has no licence public key to check against.
var ErrNoKey = errors.New("this build of fox has no licence public key, so it cannot check a licence")

// licensePublicKey is the licence key's public half, base64. Written by
// `go run ./cmd/licensesign generate --write`; a variable only so a test build
// can be given a test key with -ldflags -X, exactly as the release key is.
//
// Empty until the first key is generated: a build with no key refuses every
// licence, which is the right answer — it cannot tell a real one from a forged
// one.
var licensePublicKey = ""

// PublicKey returns the key licences must be signed with.
func PublicKey() (ed25519.PublicKey, error) {
	if licensePublicKey == "" {
		return nil, ErrNoKey
	}
	b, err := base64.StdEncoding.DecodeString(licensePublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("the licence public key built into fox is malformed")
	}
	return ed25519.PublicKey(b), nil
}

// CheckSignature reports whether l was signed by pub and has not been edited
// since. It says nothing about expiry or fingerprints — those are States, not
// forgeries, and the difference matters to what the product does about them.
func CheckSignature(l License, pub ed25519.PublicKey) error {
	if l.Format != Format {
		return fmt.Errorf("licence format %q, want %q", l.Format, Format)
	}
	if l.Signature == "" {
		return errors.New("the licence is not signed")
	}
	if l.KeyID != KeyID(pub) {
		return fmt.Errorf("the licence is signed by key %s, not %s — it was issued for a different FoxByte", l.KeyID, KeyID(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(l.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("the licence's signature is not an Ed25519 signature")
	}
	if !ed25519.Verify(pub, SigningPayload(l), sig) {
		return errors.New("the licence's signature does not match its contents — it has been edited")
	}
	return nil
}

// Has reports whether l names a feature. A licence listing something this build
// has never heard of is not an error: a newer licence on an older binary should
// unlock what that binary knows about and ignore the rest.
func (l License) Has(f edition.Feature) bool {
	for _, name := range l.Features {
		if name == string(f) {
			return true
		}
	}
	return false
}
