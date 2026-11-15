// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/update"
)

// copyInto copies the repository's real key-holding files into dir, so
// generate-p256 --write is tried against what it will really edit.
func copyInto(t *testing.T, dir string) {
	t.Helper()
	for _, f := range []string{goKeyFile, installScript, installPS1} {
		b, err := os.ReadFile(filepath.Join("..", "..", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// generate-p256 --write puts one throwaway key into all three places, in the
// form each reads, and changes nothing else in them.
func TestGenerateP256WritesEveryCopy(t *testing.T) {
	dir := t.TempDir()
	copyInto(t, dir)
	before := map[string]string{}
	for _, f := range []string{goKeyFile, installScript, installPS1} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		before[f] = string(b)
	}
	t.Chdir(dir)
	t.Cleanup(update.TrustReleaseP256KeyForTest(nil))
	if err := generateP256(true, false); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(p256KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p256KeyFile); fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("%s is readable by others (%v)", p256KeyFile, fi.Mode())
	}
	scalar, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	point, _ := key.PublicKey.Bytes()
	b64 := base64.StdEncoding.EncodeToString(point)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemKey := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))

	want := map[string]string{
		goKeyFile:     `var releaseP256PublicKey = "` + b64 + `"`,
		installScript: "RELEASE_P256_PUBLIC_KEY='" + pemKey + "'",
		installPS1:    "$ReleaseP256PublicKey = '" + b64 + "'",
	}
	blank := map[string]*regexp.Regexp{goKeyFile: goP256KeyLine, installScript: installP256KeyBlock, installPS1: ps1P256KeyBlock}
	for f, line := range want {
		b, _ := os.ReadFile(f)
		if !strings.Contains(string(b), line) {
			t.Errorf("%s does not carry the new key", f)
		}
		// Everything else is untouched: put the old assignment back and
		// compare with the file as it was.
		restored := blank[f].ReplaceAllLiteralString(string(b), blank[f].FindString(before[f]))
		if restored != before[f] {
			t.Errorf("%s changed beyond its P-256 key", f)
		}
	}
	// The Ed25519 key is left as it was.
	if b, _ := os.ReadFile(installScript); !strings.Contains(string(b), installKeyBlock.FindString(before[installScript])) {
		t.Error("install.sh's Ed25519 key changed")
	}

	// Once a key is there, generating again is refused without --force.
	t.Cleanup(update.TrustReleaseP256KeyForTest(&key.PublicKey))
	if err := generateP256(false, false); err == nil {
		t.Error("replacing the P-256 key was not refused")
	}
}

// sign-p256 signs with the secret only when it is the key fox trusts, and what
// it writes is what verify-p256 and fox accept.
func TestSignP256(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := key.Bytes()
	if err := os.WriteFile("SHA256SUMS", []byte(update.VersionLine("v2.3.0")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FOX_RELEASE_SIGNING_KEY_P256", base64.StdEncoding.EncodeToString(raw))
	t.Cleanup(update.TrustReleaseP256KeyForTest(nil))
	if err := signP256("SHA256SUMS", "SHA256SUMS.p256.sig"); err == nil {
		t.Error("signed although fox carries no P-256 key")
	}
	restore := update.TrustReleaseP256KeyForTest(&other.PublicKey)
	if err := signP256("SHA256SUMS", "SHA256SUMS.p256.sig"); err == nil {
		t.Error("signed with a key fox does not trust")
	}
	restore()

	t.Cleanup(update.TrustReleaseP256KeyForTest(&key.PublicKey))
	if err := signP256("SHA256SUMS", "SHA256SUMS.p256.sig"); err != nil {
		t.Fatal(err)
	}
	if err := verifyP256("SHA256SUMS", "SHA256SUMS.p256.sig"); err != nil {
		t.Errorf("verify-p256: %v", err)
	}
	if err := os.WriteFile("SHA256SUMS", []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyP256("SHA256SUMS", "SHA256SUMS.p256.sig"); err == nil {
		t.Error("verify-p256 accepted an altered file")
	}

	t.Setenv("FOX_RELEASE_SIGNING_KEY_P256", "not a key")
	if err := signP256("SHA256SUMS", "x.sig"); err == nil {
		t.Error("signed with a malformed secret")
	}
}
