// SPDX-License-Identifier: AGPL-3.0-or-later

// Package brand holds the product's name, and nothing else.
//
// Everything a user reads comes from here: the product name, the command, the
// environment variables, the state directory, the repository. The constants are
// generated from brand.json at the repository root (see cmd/brandgen), so
// renaming the product is editing one file and running `make brand`.
//
// What is deliberately NOT here: the names written into a database or onto disk
// — the SQL schema, the roles, the ZFS pool, the containers, the object store's
// bucket, the API-key prefix, the policy SQLSTATEs, the anchor format. Those
// carry no product name, so a rename never touches an existing install. They
// live next to the code that creates them, marked as frozen.
//
// This package has no dependencies beyond the standard library, so anything can
// import it.
package brand

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Getenv reads one of this engine's environment variables. name is given
// without the prefix: Getenv("API_KEY") reads FOX_API_KEY.
//
// A variable set under a retired prefix is still honoured, so a rename does not
// break the scripts and shell profiles people already have.
func Getenv(name string) string { return GetenvFull(EnvPrefix + name) }

// GetenvFull is Getenv for a variable named in full ("FOX_API_KEY"), for code
// that keeps the whole name in a constant. A retired prefix still works.
func GetenvFull(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	suffix, ok := strings.CutPrefix(name, EnvPrefix)
	if !ok {
		return ""
	}
	for _, p := range Previous {
		if v := os.Getenv(p.EnvPrefix + suffix); v != "" {
			return v
		}
	}
	return ""
}

// GetenvOr is Getenv with a fallback for when nothing is set.
func GetenvOr(name, def string) string {
	if v := Getenv(name); v != "" {
		return v
	}
	return def
}

// EnvName is the full name of one of this engine's environment variables, for
// messages that tell someone what to set.
func EnvName(name string) string { return EnvPrefix + name }

var (
	stateDirOnce sync.Once
	stateDirPath string
)

// StateDir is the per-user directory holding secrets, the account database, TLS
// certificates, Blackbox anchors and the update cache (~/.fox).
//
// If it does not exist but a retired one does, the old directory is renamed
// rather than abandoned: after a rename, an install keeps its accounts, keys
// and anchors instead of coming up empty with credentials that no longer match
// the data.
func StateDir() string {
	stateDirOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			stateDirPath = StateDirName
			return
		}
		stateDirPath = resolveStateDir(home)
	})
	return stateDirPath
}

// resolveStateDir is StateDir for one home directory, without the caching, so
// it can be tested.
func resolveStateDir(home string) string {
	dir := filepath.Join(home, StateDirName)
	if _, err := os.Stat(dir); err == nil {
		return dir
	}
	for _, p := range Previous {
		if p.StateDir == "" {
			continue
		}
		old := filepath.Join(home, p.StateDir)
		if _, err := os.Stat(old); err != nil {
			continue
		}
		if err := os.Rename(old, dir); err != nil {
			log.Printf("could not move %s to %s: %v", old, dir, err)
			return old // keep using it where it is
		}
		log.Printf("moved %s to %s (%s was renamed from %s)", old, dir, Product, p.Product)
		return dir
	}
	return dir
}

// StatePath joins elements onto the state directory.
func StatePath(elem ...string) string {
	return filepath.Join(append([]string{StateDir()}, elem...)...)
}

// Title is the product name with its tagline, for page and document titles.
func Title() string { return Product + " — " + Tagline }

// RepoURL is the repository's web address.
func RepoURL() string { return "https://github.com/" + Repo }
