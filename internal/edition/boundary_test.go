// SPDX-License-Identifier: AGPL-3.0-or-later

package edition

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	agplHeader       = "SPDX-License-Identifier: AGPL-3.0-or-later"
	enterpriseHeader = "SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0"
	enterpriseDir    = "enterprise"
	enterpriseImport = `"github.com/thefoxbyte/foxbyte/enterprise`
)

// skipDirs are not source: generated output, vendored packages, and the
// repository's own metadata.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "dist": true, "bin": true, "coverage": true,
}

// sourceFiles walks the repository from its root, calling fn with each source
// file's repo-relative path and contents.
func sourceFiles(t *testing.T, fn func(rel string, body string)) {
	t.Helper()
	root := "../.."
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".ts", ".tsx", ".sql", ".sh", ".ps1", ".py":
		default:
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		fn(filepath.ToSlash(rel), string(b))
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
}

func inEnterprise(rel string) bool {
	return rel == enterpriseDir || strings.HasPrefix(rel, enterpriseDir+"/")
}

// thisTest spells out the headers and the import path it searches for, so it
// matches its own patterns. It is the one file both checks skip.
const thisTest = "internal/edition/boundary_test.go"

// The licence boundary is a directory boundary, and it only works if it is
// exact. A paid file carrying the AGPL header would publish it; a free file
// carrying the enterprise header would claim rights over code that is already
// open. Both directions are checked.
func TestLicenceHeadersMatchTheDirectory(t *testing.T) {
	var paid, free int
	sourceFiles(t, func(rel, body string) {
		if rel == thisTest {
			return
		}
		switch {
		case inEnterprise(rel):
			paid++
			if !strings.Contains(body, enterpriseHeader) {
				t.Errorf("%s: every file under %s/ must carry %q", rel, enterpriseDir, enterpriseHeader)
			}
			if strings.Contains(body, agplHeader) {
				t.Errorf("%s: carries the AGPL header inside %s/ — that would publish paid code "+
					"under a licence that cannot be revoked", rel, enterpriseDir)
			}
		default:
			free++
			if strings.Contains(body, enterpriseHeader) {
				t.Errorf("%s: carries the enterprise header but lives outside %s/", rel, enterpriseDir)
			}
		}
	})
	if paid == 0 {
		t.Fatalf("no files found under %s/ — this test is not checking anything", enterpriseDir)
	}
	if free == 0 {
		t.Fatal("no files found outside the enterprise directory")
	}
}

// The core must never import the paid code. Only the `_on.go` half of a
// build-tag pair may, because that file is itself compiled out of a Standard
// build — which is what makes "the Standard binary contains no enterprise code"
// true rather than aspirational.
func TestOnlyTaggedFilesImportTheEnterpriseCode(t *testing.T) {
	sourceFiles(t, func(rel, body string) {
		if inEnterprise(rel) || filepath.Ext(rel) != ".go" || !strings.Contains(body, enterpriseImport) {
			return
		}
		if rel == thisTest {
			return
		}
		if !strings.Contains(body, "//go:build enterprise") {
			t.Errorf("%s: imports the enterprise code without a `//go:build enterprise` tag, "+
				"so it would be compiled into the Standard binary", rel)
		}
	})
}

// `go build ./...` and `go vet ./...` run without the tag (Makefile: vet), so a
// package whose every file is tagged would be an empty package and break them.
// One untagged file per package keeps the tree buildable — the same reason
// web/embed_stub.go exists.
func TestEveryEnterprisePackageHasAnUntaggedFile(t *testing.T) {
	tagged := map[string]bool{}   // package dir -> has at least one tagged .go file
	untagged := map[string]bool{} // package dir -> has at least one untagged .go file
	sourceFiles(t, func(rel, body string) {
		if !inEnterprise(rel) || filepath.Ext(rel) != ".go" {
			return
		}
		dir := filepath.Dir(rel)
		if strings.Contains(body, "//go:build") {
			tagged[dir] = true
		} else {
			untagged[dir] = true
		}
	})
	for dir := range tagged {
		if !untagged[dir] {
			t.Errorf("%s: every file is build-tagged, so the package is empty without the tag and "+
				"`go build ./...` breaks — give it one untagged file", dir)
		}
	}
}
