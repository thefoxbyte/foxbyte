// SPDX-License-Identifier: AGPL-3.0-or-later

package gen

import (
	"os"
	"path/filepath"
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
