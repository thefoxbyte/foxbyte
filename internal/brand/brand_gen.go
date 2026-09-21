// SPDX-License-Identifier: AGPL-3.0-or-later

// Code generated from brand.json by cmd/brandgen. DO NOT EDIT.

package brand

const (
	// Product is the name people read.
	Product = "FoxByte"
	// Tagline follows the product name in titles.
	Tagline = "the database that branches like code"
	// CLI is the command, and the name of the binary.
	CLI = "fox"
	// Slug is the product name in lowercase, for identifiers that are not
	// written into a database or onto disk.
	Slug = "foxbyte"
	// EnvPrefix begins every environment variable this engine reads.
	EnvPrefix = "FOX_"
	// StateDirName is the per-user state directory, under the home directory.
	StateDirName = ".fox"
	// DocsPrefix begins the file names of the living documents.
	DocsPrefix = "FOX_"
	// Repo is the GitHub repository, owner and name, exactly as GitHub spells it.
	Repo = "thefoxbyte/foxbyte"
	// Module is the Go module path.
	Module = "github.com/thefoxbyte/foxbyte"
	// ImageRepo is the registry namespace the engine image is published under.
	ImageRepo = "ghcr.io/thefoxbyte"
	// VMInstance is the engine VM (Lima on macOS, WSL on Windows).
	VMInstance = "fox"
	// TestVM is the throwaway VM the integration suites run in.
	TestVM = "fox-test"
)

// Retired is a name the product used to have. Kept so the engine can still read
// an older install's environment variables and state directory, and so the
// repository can be checked for names that should be gone.
type Retired struct {
	Product, CLI, Slug, EnvPrefix, StateDir string
}

// Previous lists retired names, newest first.
var Previous = []Retired{
	{Product: "OxynDB", CLI: "odb", Slug: "oxyndb", EnvPrefix: "OXYNDB_", StateDir: ".oxyndb"},
	{Product: "VectoraDB", CLI: "vdb", Slug: "vectoradb", EnvPrefix: "VECTORADB_", StateDir: ".vectoradb"},
}
