// SPDX-License-Identifier: AGPL-3.0-or-later

package gen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// root is the repository root, from this package's directory.
const root = "../../.."

// Everything generated from brand.json must match what is on disk. Without
// this, a hand-edit to a generated file survives until someone regenerates and
// silently reverts it — or worse, the product is renamed in brand.json and the
// shell library the suites source still says the old name.
func TestGeneratedFilesAreInStep(t *testing.T) {
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Files(root, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no generated files declared")
	}
	for rel, want := range files {
		got, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("%s: %v — run `make brand`", rel, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("%s is out of step with brand.json — run `make brand`", rel)
		}
	}
}

// The installers carry literals, because they are fetched standalone from
// GitHub. PowerShell names its variables with a $, which Go's regexp replacement
// reads as a capture-group reference -- it once ate "$Product" and left an
// assignment with no variable, which would have shipped a broken installer.
func TestInstallerBlocksKeepTheirVariables(t *testing.T) {
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Files(root, b)
	if err != nil {
		t.Fatal(err)
	}
	ps := string(files[filepath.Join("deploy", "install.ps1")])
	for _, want := range []string{`$Product = "` + b.Product + `"`, `$Cli = "` + b.CLI + `"`, `$DefaultRepo = "` + b.Repo + `"`} {
		if !strings.Contains(ps, want) {
			t.Errorf("install.ps1 is missing %s", want)
		}
	}
	sh := string(files[filepath.Join("deploy", "install.sh")])
	for _, want := range []string{`PRODUCT="` + b.Product + `"`, `CLI="` + b.CLI + `"`, `DEFAULT_REPO="` + b.Repo + `"`} {
		if !strings.Contains(sh, want) {
			t.Errorf("install.sh is missing %s", want)
		}
	}
}

// brand.json is the only place the product is named, so the fields everything
// else is built from must be present and consistent.
func TestBrandJSONIsUsable(t *testing.T) {
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.EnvPrefix[len(b.EnvPrefix)-1] != '_' {
		t.Errorf("env_prefix %q should end in an underscore", b.EnvPrefix)
	}
	if b.StateDir[0] != '.' {
		t.Errorf("state_dir %q should start with a dot (it sits in the home directory)", b.StateDir)
	}
	if want := "github.com/" + b.Repo; b.Module != want {
		t.Errorf("module is %q but the repository is %q, so it should be %q — the Go module path is case-sensitive and must match the repository", b.Module, b.Repo, want)
	}
	for _, p := range b.Previous {
		if p.Slug == b.Slug || p.CLI == b.CLI {
			t.Errorf("retired name %q reuses the current slug or command", p.Product)
		}
	}
}

// A missing or malformed brand.json must fail loudly rather than generate files
// naming a product called "".
func TestLoadRejectsIncompleteBrand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "brand.json"), []byte(`{"product":"X"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("a brand.json with only a product should be rejected")
	}
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("a missing brand.json should be rejected")
	}
}

// Every generated TEXT file needs a line-ending rule in .gitattributes, or the
// test above fails on Windows and nowhere else.
//
// Git checks a text file out with CRLF on Windows unless told otherwise. The
// generator writes LF. So a generated file whose extension is not pinned is
// byte-for-byte different the moment CI clones it there — which is exactly what
// happened the first time a .css file was generated: green on Linux and macOS,
// red on windows-ci, with a message about brand.json that said nothing about
// line endings.
//
// Every other generated file was already covered, by *.go, *.sh and *.ts. This
// makes the next one a failure here, on any platform, rather than a surprise on
// one.
func TestGeneratedTextFilesHaveALineEndingRule(t *testing.T) {
	attrs, err := os.ReadFile(filepath.Join(root, ".gitattributes"))
	if err != nil {
		t.Fatal(err)
	}
	// The extensions .gitattributes pins, and to what.
	pinned := map[string]bool{}
	for _, line := range strings.Split(string(attrs), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "eol=") {
			continue
		}
		pattern := strings.Fields(line)[0]
		if ext := strings.TrimPrefix(pattern, "*"); strings.HasPrefix(pattern, "*.") {
			pinned[ext] = true
		} else {
			pinned[pattern] = true // a whole filename, e.g. Makefile
		}
	}

	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Files(root, b)
	if err != nil {
		t.Fatal(err)
	}
	// Images carry their own bytes and git leaves them alone.
	binary := map[string]bool{".png": true, ".jpg": true, ".webp": true, ".ico": true}
	for rel := range files {
		ext := filepath.Ext(rel)
		if binary[ext] {
			continue
		}
		if pinned[ext] || pinned[filepath.Base(rel)] {
			continue
		}
		t.Errorf("%s is generated but %q has no `eol=` rule in .gitattributes — "+
			"Windows will check it out with CRLF, the generator writes LF, and "+
			"TestGeneratedFilesAreInStep will fail there and only there", rel, ext)
	}
}
