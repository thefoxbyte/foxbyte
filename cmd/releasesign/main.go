// SPDX-License-Identifier: AGPL-3.0-or-later

// Command releasesign makes and uses the FoxByte release keys (audit v2 G22).
// It is a maintainer's and the release workflow's tool; it is not shipped.
//
//	go run ./cmd/releasesign generate --write        a new Ed25519 key pair: the
//	                                                 private key to
//	                                                 release-signing.key (0600),
//	                                                 the public key into fox and
//	                                                 deploy/install.sh
//	go run ./cmd/releasesign generate-p256 --write   a new P-256 key pair: the
//	                                                 private key to
//	                                                 release-signing-p256.key
//	                                                 (0600), the public key into
//	                                                 fox, install.sh and install.ps1
//	releasesign sign <file> <file.sig>               sign with $FOX_RELEASE_SIGNING_KEY
//	releasesign sign-p256 <file> <file.p256.sig>     sign with $FOX_RELEASE_SIGNING_KEY_P256
//	releasesign verify <file> <file.sig>             check against the key built in
//	releasesign verify-p256 <file> <file.p256.sig>   the same, for the P-256 key
//
// Why two keys: Ed25519 is what fox has always checked, but macOS's LibreSSL
// and Windows PowerShell cannot check it, so the installers there could only
// trust the checksums of the release they were installing. Both can check
// ECDSA P-256 over SHA-256, so releases carry that signature too.
//
// The Ed25519 private key is the base64 of the 32-byte seed; the P-256 one is
// the base64 of the 32-byte private scalar. They belong in the Actions secrets
// FOX_RELEASE_SIGNING_KEY and FOX_RELEASE_SIGNING_KEY_P256 (in the `release`
// environment) and in the maintainers' password manager, and nowhere else.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/update"
)

const (
	keyFile       = "release-signing.key"
	p256KeyFile   = "release-signing-p256.key"
	goKeyFile     = "internal/update/signing.go"
	installScript = "deploy/install.sh"
	installPS1    = "deploy/install.ps1"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = generate(len(os.Args) > 2 && os.Args[2] == "--write", has("--force"))
	case "generate-p256":
		err = generateP256(len(os.Args) > 2 && os.Args[2] == "--write", has("--force"))
	case "sign", "sign-p256", "verify", "verify-p256":
		if len(os.Args) != 4 {
			usage()
		}
		switch os.Args[1] {
		case "sign":
			err = sign(os.Args[2], os.Args[3])
		case "sign-p256":
			err = signP256(os.Args[2], os.Args[3])
		case "verify":
			err = verify(os.Args[2], os.Args[3])
		default:
			err = verifyP256(os.Args[2], os.Args[3])
		}
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasesign:", err)
		os.Exit(1)
	}
}

func has(flag string) bool {
	for _, a := range os.Args[2:] {
		if a == flag {
			return true
		}
	}
	return false
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: releasesign generate|generate-p256 --write [--force] | sign|sign-p256 <file> <sig> | verify|verify-p256 <file> <sig>")
	os.Exit(2)
}

func generate(write, force bool) error {
	if cur, _ := update.ReleasePublicKey(); cur != nil && !force {
		return fmt.Errorf("fox already has a release key (%s). Replacing it means fox builds released so far can no longer update, because they only trust the old key; pass --force if that is really what you want", base64.StdEncoding.EncodeToString(cur))
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := base64.StdEncoding.EncodeToString(key.Seed())
	if err := os.WriteFile(keyFile, []byte(seed+"\n"), 0o600); err != nil {
		return err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if write {
		if err := writeGoKey(goKeyLine, "releasePublicKey", pubB64); err != nil {
			return err
		}
		if err := writeQuoted(installScript, installKeyBlock, "RELEASE_PUBLIC_KEY='", pemPublicKey(pub), 0o755); err != nil {
			return err
		}
	}
	fmt.Printf(`A new release key.

  public key  %s
  private key %s (mode 0600)

Next:
  1. gh secret set FOX_RELEASE_SIGNING_KEY --env release < %s
  2. Put the private key in the maintainers' password manager, then delete %s.
  3. Commit %s and %s, which now carry the public key.
`, pubB64, keyFile, keyFile, keyFile, goKeyFile, installScript)
	return nil
}

// generateP256 makes the second release key. Setting it the first time breaks
// nothing already released: builds and installers that predate it ignore
// SHA256SUMS.p256.sig. Replacing it once set does, hence --force.
func generateP256(write, force bool) error {
	if cur, _ := update.ReleaseP256PublicKey(); cur != nil && !force {
		b, _ := cur.Bytes()
		return fmt.Errorf("fox already has a P-256 release key (%s). Replacing it means installers and fox builds released so far refuse every new release; pass --force if that is really what you want", base64.StdEncoding.EncodeToString(b))
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	raw, err := key.Bytes()
	if err != nil {
		return err
	}
	if err := os.WriteFile(p256KeyFile, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
		return err
	}
	point, err := key.PublicKey.Bytes()
	if err != nil {
		return err
	}
	if write {
		if err := writeP256Keys(&key.PublicKey); err != nil {
			return err
		}
	}
	fmt.Printf(`A new P-256 release key.

  public key  %s
  private key %s (mode 0600)

Next:
  1. gh secret set FOX_RELEASE_SIGNING_KEY_P256 --env release < %s
  2. Put the private key in the maintainers' password manager, then delete %s.
  3. Commit %s, %s and %s, which now carry the public key. Installers from
     that commit on refuse a release they cannot check.
`, base64.StdEncoding.EncodeToString(point), p256KeyFile, p256KeyFile, p256KeyFile, goKeyFile, installScript, installPS1)
	return nil
}

// writeP256Keys writes pub into the three places that pin it, each in the form
// its checker reads: the raw point for Go and for .NET (which imports X and Y),
// and a PEM SubjectPublicKeyInfo for OpenSSL and LibreSSL.
func writeP256Keys(pub *ecdsa.PublicKey) error {
	point, err := pub.Bytes()
	if err != nil {
		return err
	}
	pointB64 := base64.StdEncoding.EncodeToString(point)
	pemKey, err := pemP256PublicKey(pub)
	if err != nil {
		return err
	}
	if err := writeGoKey(goP256KeyLine, "releaseP256PublicKey", pointB64); err != nil {
		return err
	}
	if err := writeQuoted(installScript, installP256KeyBlock, "RELEASE_P256_PUBLIC_KEY='", pemKey, 0o755); err != nil {
		return err
	}
	return writeQuoted(installPS1, ps1P256KeyBlock, "$ReleaseP256PublicKey = '", pointB64, 0o644)
}

// pemPublicKey is the key as OpenSSL reads it (SubjectPublicKeyInfo).
func pemPublicKey(pub ed25519.PublicKey) string {
	der := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, pub...)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func pemP256PublicKey(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

var (
	goKeyLine           = regexp.MustCompile(`(?m)^var releasePublicKey = ".*"$`)
	goP256KeyLine       = regexp.MustCompile(`(?m)^var releaseP256PublicKey = ".*"$`)
	installKeyBlock     = regexp.MustCompile(`(?s)RELEASE_PUBLIC_KEY='[^']*'`)
	installP256KeyBlock = regexp.MustCompile(`(?s)RELEASE_P256_PUBLIC_KEY='[^']*'`)
	ps1P256KeyBlock     = regexp.MustCompile(`(?m)^\$ReleaseP256PublicKey = '[^']*'`)
)

func writeGoKey(line *regexp.Regexp, name, value string) error {
	b, err := os.ReadFile(goKeyFile)
	if err != nil {
		return err
	}
	if !line.Match(b) {
		return fmt.Errorf("%s has no `var %s = \"…\"` line", goKeyFile, name)
	}
	return os.WriteFile(goKeyFile, line.ReplaceAllLiteral(b, []byte(`var `+name+` = "`+value+`"`)), 0o644)
}

// writeQuoted replaces the single-quoted assignment that block matches in path
// (prefix runs up to and including the opening quote) with value.
func writeQuoted(path string, block *regexp.Regexp, prefix, value string, mode os.FileMode) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !block.Match(b) {
		return fmt.Errorf("%s has no %s…' assignment", path, prefix)
	}
	repl := prefix + strings.TrimSpace(value) + "'"
	return os.WriteFile(path, block.ReplaceAllLiteral(b, []byte(repl)), mode)
}

func sign(in, out string) error {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("FOX_RELEASE_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("FOX_RELEASE_SIGNING_KEY is not set to a release key (base64 of a 32-byte seed)")
	}
	key := ed25519.NewKeyFromSeed(seed)
	// Refuse to sign with a key fox would not accept: a release signed that way
	// could never be installed or updated to.
	if pub, err := update.ReleasePublicKey(); err != nil || !pub.Equal(key.Public()) {
		return fmt.Errorf("FOX_RELEASE_SIGNING_KEY is not the key whose public half is built into fox (%v)", err)
	}
	msg, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	return os.WriteFile(out, ed25519.Sign(key, msg), 0o644)
}

func signP256(in, out string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("FOX_RELEASE_SIGNING_KEY_P256")))
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("FOX_RELEASE_SIGNING_KEY_P256 is not set to a P-256 release key (base64 of a 32-byte private scalar)")
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return fmt.Errorf("FOX_RELEASE_SIGNING_KEY_P256 is not a P-256 private key: %v", err)
	}
	// As with Ed25519: a signature nothing would accept is worse than none,
	// because once the key is pinned the installers refuse on it.
	if pub, err := update.ReleaseP256PublicKey(); err != nil || pub == nil || !pub.Equal(&key.PublicKey) {
		return fmt.Errorf("FOX_RELEASE_SIGNING_KEY_P256 is not the key whose public half is built into fox (%v)", err)
	}
	msg, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		return err
	}
	return os.WriteFile(out, sig, 0o644)
}

func verify(in, sigPath string) error {
	msg, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	if err := update.VerifySums(msg, sig); err != nil {
		return err
	}
	fmt.Printf("%s: signed with the FoxByte release key\n", in)
	return nil
}

func verifyP256(in, sigPath string) error {
	msg, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	if err := update.VerifySumsP256(msg, sig); err != nil {
		return err
	}
	fmt.Printf("%s: signed with the FoxByte P-256 release key\n", in)
	return nil
}
