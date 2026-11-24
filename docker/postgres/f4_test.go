// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres_test

import (
	"strings"
	"testing"
)

// The Blackbox's placeholders (F4 design, section 9) arrive whichever way the
// extension does, at 0.3 or updated to it, and are the same function both ways.
func TestPlaceholdersArriveBothWays(t *testing.T) {
	const fn = "CREATE FUNCTION bbid_placeholders(statement text)\nRETURNS text\nAS 'MODULE_PATHNAME'\nLANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;"
	for _, f := range []string{"bb_identity/bb_identity--0.3.sql", "bb_identity/bb_identity--0.2--0.3.sql"} {
		if !strings.Contains(readLF(t, f), fn) {
			t.Errorf("%s does not make bbid_placeholders as the other script does", f)
		}
	}
	if strings.Contains(readLF(t, "bb_identity/bb_identity--0.2.sql"), "bbid_placeholders") {
		t.Error("0.2 must stay as it shipped")
	}
}

// Placeholders read tokens from PostgreSQL's own lexer, never a regular
// expression, and leave parameters already there alone.
func TestPlaceholdersUseTheServersLexer(t *testing.T) {
	c := readLF(t, "bb_identity/bb_identity.c")
	start := strings.Index(c, "/* ---- placeholders (F4)")
	if start < 0 {
		t.Fatal("the placeholders section was not found")
	}
	sec := c[start:]
	for _, want := range []string{`#include "parser/scanner.h"`, "scanner_init(src, &extra, &ScanKeywords, ScanKeywordTokens)", "core_yylex(", "placeholder_param("} {
		if !strings.Contains(c, want) {
			t.Errorf("bb_identity.c: missing %s", want)
		}
	}
	if strings.Contains(sec, "regcomp") || strings.Contains(sec, "regexp") {
		t.Error("placeholders must not be found with a regular expression")
	}
}
