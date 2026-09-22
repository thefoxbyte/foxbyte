// SPDX-License-Identifier: AGPL-3.0-or-later

// Command releasesign makes and uses the FoxByte release key (audit v2 G22).
// It is a maintainer's and the release workflow's tool; it is not shipped.
//
//	go run ./cmd/releasesign generate --write   a new key pair: the private key
//	                                            to release-signing.key (0600),
//	                                            the public key into fox and
//	                                            deploy/install.sh
//	releasesign sign <file> <file.sig>          sign with $FOX_RELEASE_SIGNING_KEY
//	releasesign verify <file> <file.sig>        check against the key built in
//
// The private key is the base64 of the 32-byte Ed25519 seed. It belongs in the
// repository's Actions secret FOX_RELEASE_SIGNING_KEY and in the maintainers'
// password manager, and nowhere else.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
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
	goKeyFile     = "internal/update/signing.go"
	installScript = "deploy/install.sh"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = generate(len(os.Args) > 2 && os.Args[2] == "--write", has("--force"))
	case "sign":
		if len(os.Args) != 4 {
			usage()
		}
		err = sign(os.Args[2], os.Args[3])
	case "verify":
		if len(os.Args) != 4 {
			usage()
		}
		err = verify(os.Args[2], os.Args[3])
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
	fmt.Fprintln(os.Stderr, "usage: releasesign generate --write [--force] | sign <file> <file.sig> | verify <file> <file.sig>")
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
		if err := writeGoKey(pubB64); err != nil {
			return err
		}
		if err := writeInstallKey(pemPublicKey(pub)); err != nil {
			return err
		}
	}
	fmt.Printf(`A new release key.

  public key  %s
  private key %s (mode 0600)

Next:
  1. gh secret set FOX_RELEASE_SIGNING_KEY < %s
  2. Put the private key in the maintainers' password manager, then delete %s.
  3. Commit %s and %s, which now carry the public key.
`, pubB64, keyFile, keyFile, keyFile, goKeyFile, installScript)
	return nil
}

// pemPublicKey is the key as OpenSSL reads it (SubjectPublicKeyInfo).
func pemPublicKey(pub ed25519.PublicKey) string {
	der := append([]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}, pub...)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

var goKeyLine = regexp.MustCompile(`(?m)^var releasePublicKey = ".*"$`)

func writeGoKey(pubB64 string) error {
	b, err := os.ReadFile(goKeyFile)
	if err != nil {
		return err
	}
	if !goKeyLine.Match(b) {
		return fmt.Errorf("%s has no `var releasePublicKey = \"…\"` line", goKeyFile)
	}
	return os.WriteFile(goKeyFile, goKeyLine.ReplaceAll(b, []byte(`var releasePublicKey = "`+pubB64+`"`)), 0o644)
}

var installKeyBlock = regexp.MustCompile(`(?s)RELEASE_PUBLIC_KEY='[^']*'`)

func writeInstallKey(pemKey string) error {
	b, err := os.ReadFile(installScript)
	if err != nil {
		return err
	}
	if !installKeyBlock.Match(b) {
		return fmt.Errorf("%s has no RELEASE_PUBLIC_KEY='…' assignment", installScript)
	}
	repl := "RELEASE_PUBLIC_KEY='" + strings.TrimSpace(pemKey) + "'"
	return os.WriteFile(installScript, installKeyBlock.ReplaceAllLiteral(b, []byte(repl)), 0o755)
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
