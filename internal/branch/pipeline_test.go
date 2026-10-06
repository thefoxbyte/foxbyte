// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
)

// sqlIdent preserves the source identifier verbatim (case + punctuation), quoted,
// truncating only to Postgres's 63-byte limit — so a migration never renames the
// source schema.
func TestSQLIdent(t *testing.T) {
	cases := map[string]string{
		"createdAt":    `"createdAt"`,
		"userId":       `"userId"`,
		"leaseAiChats": `"leaseAiChats"`,
		"my.field":     `"my.field"`, // punctuation preserved
		`he"llo`:       `"he""llo"`,  // internal quote doubled
		"":             `"col"`,      // empty fallback
	}
	for in, want := range cases {
		if got := sqlIdent(in); got != want {
			t.Errorf("sqlIdent(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("a", 70)
	if got := sqlIdent(long); got != `"`+strings.Repeat("a", 63)+`"` {
		t.Errorf("sqlIdent(70 chars) not truncated to 63: %q", got)
	}
}

// jsonColumn maps a document key's observed JSON types to a Postgres column.
func TestJSONColumn(t *testing.T) {
	cases := []struct {
		name     string
		key      string
		kinds    map[string]bool
		wantType string
		wantExpr string
	}{
		{"id unwraps oid", "_id", map[string]bool{"object": true}, "text", `coalesce(doc->'_id'->>'$oid', doc->>'_id')`},
		{"string", "name", map[string]bool{"string": true}, "text", `doc->>'name'`},
		{"number", "age", map[string]bool{"number": true}, "numeric", `(doc->>'age')::numeric`},
		{"boolean", "ok", map[string]bool{"boolean": true}, "boolean", `(doc->>'ok')::boolean`},
		{"nested object", "addr", map[string]bool{"object": true}, "jsonb", `doc->'addr'`},
		{"array", "tags", map[string]bool{"array": true}, "jsonb", `doc->'tags'`},
		{"mixed → jsonb", "v", map[string]bool{"string": true, "number": true}, "jsonb", `doc->'v'`},
		{"all null → text", "x", map[string]bool{"null": true}, "text", `doc->>'x'`},
		{"number with nulls → numeric", "n", map[string]bool{"number": true, "null": true}, "numeric", `(doc->>'n')::numeric`},
	}
	for _, c := range cases {
		gotType, gotExpr := jsonColumn(c.key, c.kinds)
		if gotType != c.wantType || gotExpr != c.wantExpr {
			t.Errorf("%s: jsonColumn = (%q, %q), want (%q, %q)", c.name, gotType, gotExpr, c.wantType, c.wantExpr)
		}
	}
}
