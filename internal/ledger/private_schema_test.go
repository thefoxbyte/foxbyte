// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Wherever the engine leaves its own schema out of a user's tables (counting,
// guarding, tracking, scanning, listing), it leaves the private one out too.
// A filter that forgot it counted application identity's two tables as the
// user's: a continuous import's cutover reported 3 tables for 1.
func TestFiltersLeaveOutThePrivateSchema(t *testing.T) {
	// A list of schema names, quoted, that names the Blackbox's.
	list := regexp.MustCompile(`(?i)(NOT IN|<>|IN)\s*\(?([^)\n]*'` + SchemaName + `'[^)\n]*)\)?`)
	for _, root := range []string{"../../internal", "../../enterprise"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if !(strings.HasSuffix(p, ".go") || strings.HasSuffix(p, ".sql")) || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(b), "\n") {
				code, _, _ := strings.Cut(line, "--")
				if strings.HasSuffix(p, ".go") {
					code, _, _ = strings.Cut(line, "//")
				}
				// Go that builds the list from the constants.
				if strings.Contains(code, "ledger.SchemaName") && strings.Contains(code, "information_schema") &&
					!strings.Contains(code, "ledger.PrivateSchemaName") {
					t.Errorf("%s:%d leaves ledger.SchemaName out of a user's schemas but not ledger.PrivateSchemaName: %s",
						p, i+1, strings.TrimSpace(line))
				}
				m := list.FindStringSubmatch(code)
				if m == nil || !strings.Contains(strings.ToLower(code), "nspname") && !strings.Contains(code, "schema") {
					continue
				}
				// A filter of user schemas (several names, the system ones among
				// them) must name the private schema as well.
				if strings.Contains(m[2], "pg_catalog") || strings.Contains(m[2], "information_schema") {
					if !strings.Contains(m[2], "'"+PrivateSchemaName+"'") {
						t.Errorf("%s:%d leaves the Blackbox's schema out of a user's but not %s: %s",
							p, i+1, PrivateSchemaName, strings.TrimSpace(line))
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
