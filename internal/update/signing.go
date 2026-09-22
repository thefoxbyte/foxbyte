// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"crypto/ed25519"
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

// SigAsset is the signature of SumsAsset.
const SigAsset = "SHA256SUMS.sig"

// releasePublicKey is the release key's public half, base64. Written by
// `go run ./cmd/releasesign generate --write` (with install.sh's copy); a
// variable only so a test build can be given a test key with -ldflags -X.
var releasePublicKey = "aTn8b2xj53r7QjOK+K2//RBU+4OBHoxzuclxGK04WZc="

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

// VerifySums checks a SHA256SUMS against its signature.
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

// TrustReleaseKeyForTest makes this process accept releases signed by pub, and
// returns a function that restores the built-in key. For tests of packages
// that drive an update against a fake release server; release builds never
// call it.
func TrustReleaseKeyForTest(pub ed25519.PublicKey) (restore func()) {
	old := releasePublicKey
	releasePublicKey = base64.StdEncoding.EncodeToString(pub)
	return func() { releasePublicKey = old }
}
