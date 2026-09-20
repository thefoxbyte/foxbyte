// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/foxbyte/foxbyte/internal/brand"
)

// The product has been renamed twice. A stray old name is a real defect, not a
// cosmetic one — a script calling a command that no longer exists, a query
// against a schema that was renamed, a key checked against the wrong prefix —
// so the repository is kept free of the names in brand.json's "previous" list.
//
// Two escapes, both deliberate and narrow:
//   - a line that records history and says so ("renamed from"), such as the
//     change log;
//   - a line marked "legacy:", for code that must still recognise an older
//     install (an old state directory to migrate, an old container to clean up).
//
// brand.json itself is skipped: it is the register of retired names.
func TestNoRetiredProductNames(t *testing.T) {
	if len(brand.Previous) == 0 {
		t.Skip("no retired names to check for")
	}
	var parts []string
	for _, p := range brand.Previous {
		// Slug and product name anywhere; the command and its prefixes only as
		// a whole word, so "odbc" or a hash containing "vdb" is not a match.
		parts = append(parts,
			regexp.QuoteMeta(p.Slug),
			regexp.QuoteMeta(p.Product),
			regexp.QuoteMeta(strings.ToUpper(p.Slug)),
			`(^|[^A-Za-z0-9])`+regexp.QuoteMeta(p.CLI)+`([^A-Za-z0-9]|$)`,
			`(^|[^A-Za-z0-9])`+regexp.QuoteMeta(strings.ToUpper(p.CLI))+`([^A-Za-z0-9]|$)`,
		)
	}
	retired := regexp.MustCompile("(?i)" + strings.Join(parts, "|"))

	// The repository is named in brand.json. GitHub resolves any casing, so a
	// wrong one works in a browser and slips through review, while the Go module
	// path is case-sensitive and must match exactly. Registry names are the
	// exception: they must be lowercase.
	owner, _, _ := strings.Cut(brand.Repo, "/")
	wrongRepo := regexp.MustCompile(`(github\.com|githubusercontent\.com|repos)/(?i:` + regexp.QuoteMeta(owner) + `)/`)

	for _, f := range repoFiles(t) {
		scanFile(t, f, func(n int, line string) {
			low := strings.ToLower(line)
			if strings.Contains(low, "renamed from") || strings.Contains(low, "legacy:") {
				return
			}
			if m := retired.FindString(line); m != "" {
				t.Errorf("%s:%d uses the retired name %q: %s", f, n, m, trim(line))
			}
			if m := wrongRepo.FindString(line); m != "" && !strings.Contains(m, "/"+owner+"/") {
				t.Errorf("%s:%d names the repository with the wrong casing (it is %s): %s", f, n, brand.Repo, trim(line))
			}
		})
	}
}

// Names written into a database or onto disk must not carry the product's name,
// or the next rename breaks every install again. This is the rule that lets
// brand.json be the only thing a rename touches.
func TestStoredNamesAreBrandFree(t *testing.T) {
	branded := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(brand.Slug) + `|` + regexp.QuoteMeta(brand.CLI) + `_`)
	// Every schema the engine installs: what these create, and the messages they
	// raise, outlive any product name.
	sqlFiles, err := filepath.Glob("../../internal/ledger/*.sql")
	if err != nil || len(sqlFiles) == 0 {
		t.Fatalf("no SQL schema files found: %v", err)
	}
	for _, f := range sqlFiles {
		scanFile(t, f, func(n int, line string) {
			if strings.Contains(strings.ToLower(line), "legacy:") {
				return
			}
			// Comments may name the product; SQL must not.
			if code, _, _ := strings.Cut(line, "--"); branded.MatchString(code) {
				t.Errorf("%s:%d names the product in SQL, which is written into the database: %s", f, n, trim(line))
			}
		})
	}
}

func repoFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	skipDir := map[string]bool{".git": true, "node_modules": true, "dist": true, "bin": true, ".claude": true}
	binary := regexp.MustCompile(`\.(pdf|png|jpe?g|webp|ico|gif|woff2?|ttf|exe|tar|gz|zip)$`)
	self, _ := filepath.Abs("oldnames_test.go")

	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case binary.MatchString(path),
			d.Name() == "go.sum", d.Name() == "package-lock.json",
			d.Name() == "brand.json", // the register of retired names
			generatedFromBrand(path): // …and what is generated from it
			return nil
		}
		if abs, _ := filepath.Abs(path); abs == self {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// generatedFromBrand reports whether a file is written by cmd/brandgen. Those
// carry the retired names on purpose: that is what brand.json is for.
func generatedFromBrand(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 0; n < 6 && sc.Scan(); n++ {
		if strings.Contains(sc.Text(), "from brand.json") {
			return true
		}
	}
	return false
}

func scanFile(t *testing.T, path string, check func(n int, line string)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Errorf("%s: %v", path, err)
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024) // the living documents have long lines
	for n := 1; sc.Scan(); n++ {
		check(n, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Errorf("%s: %v", path, err)
	}
}

func trim(line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 160 {
		line = line[:160] + "…"
	}
	return fmt.Sprint(line)
}
