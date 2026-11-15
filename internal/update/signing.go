// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Release signatures (audit v2 G22). A release's SHA256SUMS proves each file
// arrived whole, but it is published by the same account as the files, so
// anyone who can publish a release can replace a binary and its checksum
// together. SigAsset is an Ed25519 signature over SHA256SUMS by the project's
// release key, which lives only in the release workflow's secrets; its public
// half is built into fox (releasePublicKey) and into deploy/install.sh, so a
// release that was not signed with that key is never installed.
//
// The signature is the raw 64 bytes, so `openssl pkeyutl -verify -rawin` can
// check it as well as Go.
//
// SigP256Asset is a second signature over the same bytes, ECDSA P-256 over
// SHA-256, by a second release key. It exists for the installers: macOS ships
// LibreSSL, which cannot check Ed25519, and Windows PowerShell has no Ed25519
// at all, so on those machines the Ed25519 signature went unchecked and the
// install trusted a checksum from the very release it was checking. Both can
// check P-256 (`openssl dgst -sha256 -verify`, and .NET's ECDsaCng). fox checks
// Ed25519 always, and P-256 too whenever it carries that key and the release
// has the signature.

// SigAsset is the Ed25519 signature of SumsAsset.
const SigAsset = "SHA256SUMS.sig"

// SigP256Asset is the ECDSA P-256 signature of SumsAsset: ASN.1 DER, as
// `openssl dgst -sign` writes it.
const SigP256Asset = "SHA256SUMS.p256.sig"

// releasePublicKey is the release key's public half, base64. Written by
// `go run ./cmd/releasesign generate --write` (with install.sh's copy); a
// variable only so a test build can be given a test key with -ldflags -X.
var releasePublicKey = "aTn8b2xj53r7QjOK+K2//RBU+4OBHoxzuclxGK04WZc="

// releaseP256PublicKey is the P-256 release key's public half: base64 of the
// 65-byte uncompressed point (0x04, X, Y). Written by `go run ./cmd/releasesign
// generate-p256 --write`, which also writes install.sh's and install.ps1's
// copies.
//
// Empty until the maintainer generates the key (README, "Verifying a release").
// While it is empty the installers keep warning, as they always have, where
// they cannot check Ed25519; once it is set they refuse instead.
var releaseP256PublicKey = ""

// ErrNoReleaseKey means this build has no release key to check against.
var ErrNoReleaseKey = errors.New("this build of fox has no release public key, so it cannot check release signatures")

// ReleasePublicKey returns the key releases must be signed with.
func ReleasePublicKey() (ed25519.PublicKey, error) {
	if releasePublicKey == "" {
		return nil, ErrNoReleaseKey
	}
	b, err := base64.StdEncoding.DecodeString(releasePublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the release public key built into fox is malformed")
	}
	return ed25519.PublicKey(b), nil
}

// ReleaseP256PublicKey returns the P-256 release key, or nil (and no error)
// when this build carries none yet.
func ReleaseP256PublicKey() (*ecdsa.PublicKey, error) {
	if releaseP256PublicKey == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(releaseP256PublicKey)
	if err != nil {
		return nil, fmt.Errorf("the P-256 release public key built into fox is malformed")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
	if err != nil {
		return nil, fmt.Errorf("the P-256 release public key built into fox is malformed: %v", err)
	}
	return pub, nil
}

// VerifySums checks a SHA256SUMS against its Ed25519 signature.
func VerifySums(sums, sig []byte) error {
	pub, err := ReleasePublicKey()
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%s is not an Ed25519 signature (%d bytes)", SigAsset, len(sig))
	}
	if !ed25519.Verify(pub, sums, sig) {
		return fmt.Errorf("%s does not match SHA256SUMS: the release was not signed with the FoxByte release key", SigAsset)
	}
	return nil
}

// VerifySumsP256 checks a SHA256SUMS against its P-256 signature. A build with
// no P-256 key returns ErrNoReleaseKey: it has nothing to check against.
func VerifySumsP256(sums, sig []byte) error {
	pub, err := ReleaseP256PublicKey()
	if err != nil {
		return err
	}
	if pub == nil {
		return ErrNoReleaseKey
	}
	h := sha256.Sum256(sums)
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		return fmt.Errorf("%s does not match SHA256SUMS: the release was not signed with the FoxByte P-256 release key", SigP256Asset)
	}
	return nil
}

// VerifyRelease is the check fox makes on a release: the Ed25519 signature
// always, and the P-256 one as well when the release has it (p256Sig non-nil)
// and this build carries the P-256 key. A P-256 signature that is there and
// does not match is refused even though Ed25519 passed: a release whose two
// signatures disagree has been tampered with, whichever one is genuine.
func VerifyRelease(sums, sig, p256Sig []byte) error {
	if err := VerifySums(sums, sig); err != nil {
		return err
	}
	if p256Sig == nil {
		return nil
	}
	if pub, err := ReleaseP256PublicKey(); err != nil {
		return err
	} else if pub == nil {
		return nil // a build from before the P-256 key existed
	}
	return VerifySumsP256(sums, p256Sig)
}

// TrustReleaseKeyForTest makes this process accept releases signed by pub, and
// returns a function that restores the built-in key. For tests of packages
// that drive an update against a fake release server; release builds never
// call it.
func TrustReleaseKeyForTest(pub ed25519.PublicKey) (restore func()) {
	old := releasePublicKey
	releasePublicKey = base64.StdEncoding.EncodeToString(pub)
	return func() { releasePublicKey = old }
}

// TrustReleaseP256KeyForTest is TrustReleaseKeyForTest for the P-256 key; nil
// makes the build carry none.
func TrustReleaseP256KeyForTest(pub *ecdsa.PublicKey) (restore func()) {
	old := releaseP256PublicKey
	releaseP256PublicKey = ""
	if pub != nil {
		b, err := pub.Bytes()
		if err != nil {
			panic(err)
		}
		releaseP256PublicKey = base64.StdEncoding.EncodeToString(b)
	}
	return func() { releaseP256PublicKey = old }
}
