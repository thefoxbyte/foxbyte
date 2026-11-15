// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
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

// The P-256 key (finding SUP-5) is pinned in three places, each in the form
// its checker reads, and they must agree: all empty until the maintainer
// makes the key, then all the same key. A mismatch would have one installer
// refuse every release the others accept. `go run ./cmd/releasesign
// generate-p256 --write` writes all three.
func TestP256ReleaseKeyIsTheSameEverywhere(t *testing.T) {
	src, err := os.ReadFile("signing.go")
	if err != nil {
		t.Fatal(err)
	}
	goKey := quoted(t, string(src), `var releaseP256PublicKey = "`, `"`)
	sh, err := os.ReadFile("../../deploy/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	shKey := quoted(t, string(sh), "RELEASE_P256_PUBLIC_KEY='", "'")
	ps, err := os.ReadFile("../../deploy/install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	psKey := quoted(t, string(ps), "$ReleaseP256PublicKey = '", "'")
	if goKey == "" {
		if shKey != "" || psKey != "" {
			t.Fatalf("fox has no P-256 key, but install.sh has %q and install.ps1 %q", shKey, psKey)
		}
		return
	}
	point, err := base64.StdEncoding.DecodeString(goKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		t.Fatalf("releaseP256PublicKey is not a P-256 point: %v", err)
	}
	if psKey != goKey {
		t.Errorf("install.ps1 carries P-256 key %q, fox %q", psKey, goKey)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	if shKey != want {
		t.Errorf("install.sh carries a different P-256 key from fox's")
	}
}

func quoted(t *testing.T, s, open, close string) string {
	t.Helper()
	i := strings.Index(s, open)
	if i < 0 {
		t.Fatalf("no %s…%s assignment", open, close)
	}
	v, _, _ := strings.Cut(s[i+len(open):], close)
	return v
}
