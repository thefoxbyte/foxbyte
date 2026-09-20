// SPDX-License-Identifier: AGPL-3.0-or-later

// Package gen turns brand.json into the files that cannot read it at runtime:
// Go constants, the shell library the test suites source, the web UI's
// constants, and the generated block inside each installer (those are fetched
// standalone from GitHub, so they must carry literals).
//
// cmd/brandgen runs it (`make brand`), and TestGeneratedFilesAreInStep fails the
// build when what is on disk differs from what it would write, so the generated
// files can never drift from brand.json.
package gen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Brand is brand.json. Only the fields the generators use are listed.
type Brand struct {
	Product    string `json:"product"`
	Tagline    string `json:"tagline"`
	CLI        string `json:"cli"`
	Slug       string `json:"slug"`
	EnvPrefix  string `json:"env_prefix"`
	StateDir   string `json:"state_dir"`
	DocsPrefix string `json:"docs_prefix"`
	Repo       string `json:"repo"`
	Module     string `json:"module"`
	ImageRepo  string `json:"image_repo"`
	VMInstance string `json:"vm_instance"`
	TestVM     string `json:"test_vm"`
	Previous   []struct {
		Product   string `json:"product"`
		CLI       string `json:"cli"`
		Slug      string `json:"slug"`
		EnvPrefix string `json:"env_prefix"`
		StateDir  string `json:"state_dir"`
	} `json:"previous"`
}

// Load reads brand.json from the repository root.
func Load(root string) (Brand, error) {
	var b Brand
	raw, err := os.ReadFile(filepath.Join(root, "brand.json"))
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, fmt.Errorf("brand.json: %w", err)
	}
	for _, field := range []struct{ name, value string }{
		{"product", b.Product}, {"cli", b.CLI}, {"slug", b.Slug}, {"env_prefix", b.EnvPrefix},
		{"state_dir", b.StateDir}, {"repo", b.Repo}, {"module", b.Module},
	} {
		if field.value == "" {
			return b, fmt.Errorf("brand.json: %q is required", field.name)
		}
	}
	return b, nil
}

// Files returns every generated file, as path -> contents.
func Files(root string, b Brand) (map[string][]byte, error) {
	out := map[string][]byte{
		filepath.Join("internal", "brand", "brand_gen.go"): []byte(goFile(b)),
		filepath.Join("scripts", "lib", "brand.sh"):        []byte(shellFile(b)),
		filepath.Join("web", "src", "brand.ts"):            []byte(tsFile(b)),
	}
	// The installers keep their own shape; only the marked block is generated.
	for path, block := range map[string]string{
		filepath.Join("deploy", "install.sh"):  shellBlock(b),
		filepath.Join("deploy", "install.ps1"): powershellBlock(b),
	} {
		cur, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return nil, err
		}
		next, err := replaceBlock(cur, block)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out[path] = next
	}
	return out, nil
}

const blockStart = "generated from brand.json -- do not edit by hand, run `make brand`"
const blockEnd = "end generated"

var blockRe = regexp.MustCompile(`(?s)# ` + regexp.QuoteMeta(blockStart) + `\n.*?# ` + regexp.QuoteMeta(blockEnd))

func replaceBlock(cur []byte, block string) ([]byte, error) {
	if !blockRe.Match(cur) {
		return nil, fmt.Errorf("no generated block found (expected a line containing %q)", blockStart)
	}
	// ReplaceAllLiteral, not ReplaceAll: PowerShell's variables start with $,
	// which ReplaceAll reads as a capture-group reference -- it silently ate
	// "$Product" and left " = \"FoxByte\"" behind.
	return blockRe.ReplaceAllLiteral(cur, []byte("# "+blockStart+"\n"+block+"# "+blockEnd)), nil
}

func goFile(b Brand) string {
	var prev strings.Builder
	for _, p := range b.Previous {
		fmt.Fprintf(&prev, "\t{Product: %q, CLI: %q, Slug: %q, EnvPrefix: %q, StateDir: %q},\n",
			p.Product, p.CLI, p.Slug, p.EnvPrefix, p.StateDir)
	}
	return fmt.Sprintf(`// SPDX-License-Identifier: AGPL-3.0-or-later

// Code generated from brand.json by cmd/brandgen. DO NOT EDIT.

package brand

const (
	// Product is the name people read.
	Product = %q
	// Tagline follows the product name in titles.
	Tagline = %q
	// CLI is the command, and the name of the binary.
	CLI = %q
	// Slug is the product name in lowercase, for identifiers that are not
	// written into a database or onto disk.
	Slug = %q
	// EnvPrefix begins every environment variable this engine reads.
	EnvPrefix = %q
	// StateDirName is the per-user state directory, under the home directory.
	StateDirName = %q
	// DocsPrefix begins the file names of the living documents.
	DocsPrefix = %q
	// Repo is the GitHub repository, owner and name, exactly as GitHub spells it.
	Repo = %q
	// Module is the Go module path.
	Module = %q
	// ImageRepo is the registry namespace the engine image is published under.
	ImageRepo = %q
	// VMInstance is the engine VM (Lima on macOS, WSL on Windows).
	VMInstance = %q
	// TestVM is the throwaway VM the integration suites run in.
	TestVM = %q
)

// Retired is a name the product used to have. Kept so the engine can still read
// an older install's environment variables and state directory, and so the
// repository can be checked for names that should be gone.
type Retired struct {
	Product, CLI, Slug, EnvPrefix, StateDir string
}

// Previous lists retired names, newest first.
var Previous = []Retired{
%s}
`, b.Product, b.Tagline, b.CLI, b.Slug, b.EnvPrefix, b.StateDir, b.DocsPrefix,
		b.Repo, b.Module, b.ImageRepo, b.VMInstance, b.TestVM, prev.String())
}

func shellFile(b Brand) string {
	var prev strings.Builder
	for _, p := range b.Previous {
		fmt.Fprintf(&prev, " %s", p.CLI)
	}
	return fmt.Sprintf(`# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Generated from brand.json by cmd/brandgen. DO NOT EDIT -- run `+"`make brand`"+`.
#
# Sourced by the integration suites so they name the product in one place:
#   . "$(dirname "$0")/lib/brand.sh"

BRAND_PRODUCT=%q
BRAND_CLI=%q
BRAND_SLUG=%q
BRAND_ENV_PREFIX=%q
BRAND_STATE_DIR=%q
BRAND_REPO=%q
BRAND_TEST_VM=%q
BRAND_PREVIOUS_CLIS=%q

# Names that are deliberately brand-free, so a rename never touches an install.
# Taken from the packages that create them, not written out again.
DB_SCHEMA=%s
DB_CLIENT_ROLE=%s
DB_ADMIN_ROLE=%s
DB_SUPERUSER=%s
DB_DATABASE=%s
DB_POOL=%s
DB_NETWORK=%s
DB_CONTAINER_PREFIX=%s
DB_OBJECT_STORE=%s
DB_OBJECT_STORE_VOLUME=%s
DB_WAL_BUCKET=%s
DB_MANAGED_LABEL=%s
DB_KEY_PREFIX=%s
`, b.Product, b.CLI, b.Slug, b.EnvPrefix, b.StateDir, b.Repo, b.TestVM,
		strings.TrimSpace(prev.String()),
		ledger.SchemaName, branch.ClientRole, branch.AdminRole, branch.Superuser, branch.Database,
		branch.Pool, branch.Network, branch.ContainerPrefix, branch.ObjStore, branch.ObjStoreVolume,
		branch.WALBucket, strings.TrimSuffix(branch.ManagedLabel, "=1"), auth.KeyPrefix)
}

func tsFile(b Brand) string {
	return fmt.Sprintf(`// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Code generated from brand.json by cmd/brandgen. DO NOT EDIT -- run `+"`make brand`"+`.

export const BRAND = {
  product: %q,
  tagline: %q,
  cli: %q,
  slug: %q,
  envPrefix: %q,
  stateDir: %q,
  repo: %q,
  repoUrl: %q,
} as const
`, b.Product, b.Tagline, b.CLI, b.Slug, b.EnvPrefix, b.StateDir, b.Repo,
		"https://github.com/"+b.Repo)
}

func shellBlock(b Brand) string {
	return fmt.Sprintf("PRODUCT=%q\nCLI=%q\nSLUG=%q\nENV_PREFIX=%q\nSTATE_DIR=%q\nDEFAULT_REPO=%q\n",
		b.Product, b.CLI, b.Slug, b.EnvPrefix, b.StateDir, b.Repo)
}

func powershellBlock(b Brand) string {
	return fmt.Sprintf("$Product = %q\n$Cli = %q\n$Slug = %q\n$EnvPrefix = %q\n$StateDir = %q\n$DefaultRepo = %q\n",
		b.Product, b.CLI, b.Slug, b.EnvPrefix, b.StateDir, b.Repo)
}
