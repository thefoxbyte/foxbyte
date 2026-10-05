// SPDX-License-Identifier: AGPL-3.0-or-later

// Command licensesign mints the licences that unlock the paid edition.
//
//	go run ./cmd/licensesign generate --write
//	go run ./cmd/licensesign issue --customer "Acme Ltd" --features anchors --months 12 > acme.json
//	go run ./cmd/licensesign verify acme.json
//
// It mirrors cmd/releasesign, with one difference that is deliberate: the
// release key has to live in CI, because every tag is signed there. This one
// must not. Licences are minted rarely and by hand, a leaked licence key mints
// Enterprise for anyone, and — unlike a forged release, which gets noticed —
// nobody would ever find out. It is read from FOX_LICENSE_SIGNING_KEY, which
// should come from a password manager and never from a repository secret.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/license"
)

const (
	keyFile   = "license-signing.key"
	goKeyFile = "internal/license/license.go"
	envKey    = "FOX_LICENSE_SIGNING_KEY"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = generate(has("--write"), has("--force"))
	case "issue":
		err = issue(os.Args[2:])
	case "verify":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		err = verify(os.Args[2])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "licensesign:", err)
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
	fmt.Fprint(os.Stderr, `licensesign — mint the licences that unlock the paid edition

  generate [--write] [--force]   make a licence signing key
  issue --customer NAME ...      sign a licence, to stdout
  verify FILE                    check a licence against this build's key

issue flags:
  --customer NAME        who it is for                    (required)
  --features a,b         which features it unlocks         (required)
  --months N             how long it runs                  (default 12)
  --id ID                our reference                     (default from the date)
  --fingerprint HASH     tie it to one machine; omit for a site licence
  --rebinds N            how many times that may change    (default 3)

The private key is read from `+envKey+` and never from a file in the
repository. It must not be a CI secret: a leaked licence key mints Enterprise
for anyone, silently.
`)
}

func generate(write, force bool) error {
	if cur, _ := license.PublicKey(); cur != nil && !force {
		return fmt.Errorf("fox already has a licence key (%s). Replacing it means every licence issued so far stops verifying, because this build would only trust the new one; pass --force if that is really what you want",
			base64.StdEncoding.EncodeToString(cur))
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
	}
	fmt.Printf(`A new licence key.

  public key  %s
  key id      %s
  private key %s (mode 0600)

Next:
  1. Put the private key in your password manager.
  2. Delete %s.
  3. Commit %s, which now carries the public half.

Do NOT put this key in CI. The release key lives there because every tag is
signed there; this one is used by hand, a few times a year, and a copy in CI
is a copy that mints Enterprise for anyone who reaches it — silently, because
nothing calls home.
`, pubB64, license.KeyID(pub), keyFile, keyFile, goKeyFile)
	return nil
}

var goKeyLine = regexp.MustCompile(`(?m)^var licensePublicKey = ".*"$`)

func writeGoKey(pubB64 string) error {
	b, err := os.ReadFile(goKeyFile)
	if err != nil {
		return err
	}
	if !goKeyLine.Match(b) {
		return fmt.Errorf("%s has no `var licensePublicKey = \"…\"` line", goKeyFile)
	}
	return os.WriteFile(goKeyFile, goKeyLine.ReplaceAll(b, []byte(`var licensePublicKey = "`+pubB64+`"`)), 0o644)
}

func issue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	customer := fs.String("customer", "", "who the licence is for")
	features := fs.String("features", "", "comma-separated feature names")
	months := fs.Int("months", 12, "how long it runs")
	id := fs.String("id", "", "our reference")
	fingerprint := fs.String("fingerprint", "", "machine fingerprint; omit for a site licence")
	rebinds := fs.Int("rebinds", 3, "how many times the machine may change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *customer == "" || *features == "" {
		return fmt.Errorf("--customer and --features are both required")
	}
	key, err := privateKey()
	if err != nil {
		return err
	}
	// Refuse to sign with a key this build would not accept. Otherwise the
	// first anyone hears of a mismatch is a customer whose licence is refused.
	if pub, perr := license.PublicKey(); perr == nil {
		if license.KeyID(pub) != license.KeyID(key.Public().(ed25519.PublicKey)) {
			return fmt.Errorf("%s is not the key this build trusts (%s) — a licence signed with it would be refused by every fox in the field",
				envKey, license.KeyID(pub))
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	ref := *id
	if ref == "" {
		ref = "FB-" + now.Format("20060102-150405")
	}
	l := license.License{
		ID: ref, Customer: *customer, Edition: "enterprise",
		Features: split(*features), IssuedAt: now,
		NotAfter:    now.AddDate(0, *months, 0),
		Fingerprint: *fingerprint, RebindsAllowed: *rebinds,
	}
	license.Sign(&l, key)
	out, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func verify(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var l license.License
	if err := json.Unmarshal(b, &l); err != nil {
		return fmt.Errorf("%s is not a licence: %w", path, err)
	}
	pub, err := license.PublicKey()
	if err != nil {
		return err
	}
	if err := license.CheckSignature(l, pub); err != nil {
		return err
	}
	st := license.Evaluate(l, pub, l.Fingerprint, time.Now())
	fmt.Printf("%s — %s, %s\n  features %s\n  issued %s, runs to %s\n",
		l.ID, l.Customer, st.State,
		strings.Join(l.Features, ", "),
		l.IssuedAt.UTC().Format("2 January 2006"),
		l.NotAfter.UTC().Format("2 January 2006"))
	return nil
}

func privateKey() (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv(envKey)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("set %s to the base64 seed of the licence signing key", envKey)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
