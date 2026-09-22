// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

// fox and deploy/install.sh must carry the release key, and the same one:
// without it fox can install no release at all, and a mismatch would let one
// of them accept what the other refuses. `go run ./cmd/releasesign generate
// --write` writes both.
func TestReleaseKeyIsSetAndTheSameEverywhere(t *testing.T) {
	src, err := os.ReadFile("signing.go")
	if err != nil {
		t.Fatal(err)
	}
	const decl = `var releasePublicKey = "`
	i := strings.Index(string(src), decl)
	if i < 0 {
		t.Fatal("signing.go has no releasePublicKey declaration")
	}
	b64, _, _ := strings.Cut(string(src)[i+len(decl):], `"`)
	if b64 == "" {
		t.Fatal("no release key: run `go run ./cmd/releasesign generate --write` and put the private key in the FOX_RELEASE_SIGNING_KEY secret")
	}
	pub, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("releasePublicKey is not a base64 Ed25519 public key: %q", b64)
	}
	der := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, pub...)
	want := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	install, err := os.ReadFile("../../deploy/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(install), "RELEASE_PUBLIC_KEY='"+want+"'") {
		t.Error("deploy/install.sh carries a different release key from fox's (or none)")
	}
}
