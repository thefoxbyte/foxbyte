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
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/edition"
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
  --features a,b|all     which features it unlocks         (required; "all" = every one)
  --months N             how long it runs                  (default 12)
  --id ID                our reference                     (default from the date)
  --fingerprint HASH     tie it to one machine; omit for a site licence
  --rebinds N            how many times that may change    (default 3)
  --count N              mint N of them; --id becomes a prefix  (default 1)
  --out DIR              write <id>.json into DIR instead of printing (required above 1)

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
	// And the private half, separately.
	//
	// The check above is about the key this build *trusts*; this is about the
	// key that can *sign*, and they go missing in different ways. Running
	// `generate` without --write leaves the private key on disk and the build
	// with no public key at all — and in that state the check above passes, so
	// a second run would overwrite the only copy of a key that may already have
	// signed licences. There is no recovering it: the file is gitignored by
	// design, and every licence it signed would have to be reissued.
	if _, err := os.Stat(keyFile); err == nil && !force {
		return fmt.Errorf("%s already exists. If it has signed any licence, replacing it makes that licence unverifiable for good — move it somewhere safe first, then pass --force", keyFile)
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
  1. Commit %[4]s, which now carries the public half.
     A licence only verifies against builds made from that commit onwards.
  2. Mint what you need now, while the key is still here: make license-samples,
     or docs/evaluation-licences.md for a batch of your own.
  3. Put the private key in your password manager, and only then delete
     %[3]s. Signing reads that file, and there is no second copy.

Do NOT put this key in CI. The release key lives there because every tag is
signed there; this one is used by hand, a few times a year, and a copy in CI
is a copy that mints Enterprise for anyone who reaches it — silently, because
nothing calls home.
`, pubB64, license.KeyID(pub), keyFile, goKeyFile)
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
	count := fs.Int("count", 1, "how many to mint; above one, --id becomes a prefix and --out is required")
	outDir := fs.String("out", "", "directory to write <id>.json into, instead of printing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *customer == "" || *features == "" {
		return fmt.Errorf("--customer and --features are both required")
	}
	if *count < 1 {
		return fmt.Errorf("--count must be at least 1")
	}
	// Fifty licences on a terminal are fifty licences nobody can tell apart.
	if *count > 1 && *outDir == "" {
		return fmt.Errorf("--out <dir> is required with --count above 1")
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
	wanted, err := featureList(*features)
	if err != nil {
		return err
	}
	if *outDir != "" {
		// 0700: a licence is not a secret, but a directory of fifty of them
		// names a customer fifty times.
		if err := os.MkdirAll(*outDir, 0o700); err != nil {
			return err
		}
	}
	for i := 1; i <= *count; i++ {
		ref := *id
		switch {
		case ref == "" && *count == 1:
			ref = "FB-" + now.Format("20060102-150405")
		case ref == "":
			ref = "FB-" + now.Format("20060102-150405")
			fallthrough
		case *count > 1:
			// A prefix, so every licence has an id of its own. Issuing fifty
			// that all answer to the same reference would make the record
			// useless the first time one had to be found.
			ref = fmt.Sprintf("%s-%03d", ref, i)
		}
		l := license.License{
			ID: ref, Customer: *customer, Edition: "enterprise",
			Features: wanted, IssuedAt: now,
			NotAfter:    now.AddDate(0, *months, 0),
			Fingerprint: *fingerprint, RebindsAllowed: *rebinds,
		}
		license.Sign(&l, key)
		out, err := json.MarshalIndent(l, "", "  ")
		if err != nil {
			return err
		}
		if *outDir == "" {
			fmt.Println(string(out))
			continue
		}
		path := filepath.Join(*outDir, ref+".json")
		if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Println(path)
	}
	return nil
}

// featureList turns --features into the names to sign. "all" is every feature
// this build knows about, which is what an evaluation licence wants and what
// nobody should have to keep in step by hand.
func featureList(spec string) ([]string, error) {
	if strings.TrimSpace(spec) != "all" {
		names := split(spec)
		if len(names) == 0 {
			return nil, fmt.Errorf("--features named nothing")
		}
		return names, nil
	}
	var all []string
	for _, f := range edition.Features() {
		all = append(all, string(f))
	}
	return all, nil
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
