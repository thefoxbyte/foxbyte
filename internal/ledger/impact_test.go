// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"regexp"
	"strings"
	"testing"
)

func TestSchemaImpact(t *testing.T) {
	s := lf(SchemaImpact)
	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION bb.blast_radius(target text, target_column text DEFAULT NULL, max_depth integer DEFAULT 5)",
		"LANGUAGE plpgsql STABLE AS $$",                  // read-only; the caller's search_path resolves the target
		"least(greatest(coalesce(max_depth, 5), 1), 10)", // depth is capped
		"dep.deptype IN ('n', 'a')",
		"'pg_rewrite'::regclass", "'pg_constraint'::regclass", "'pg_trigger'::regclass", "'pg_policy'::regclass",
		"SELECT x.indrelid FROM pg_index x", // an index is reported against the table it indexes
		"GRANT EXECUTE ON FUNCTION bb.blast_radius(text, text, integer) TO db_client;",
		"SET session_replication_role = replica;", "SET session_replication_role = DEFAULT;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("impact.sql is missing %q", want)
		}
	}
	if strings.Contains(s, "SECURITY DEFINER") {
		t.Error("blast_radius must run with the caller's rights")
	}
	// A pinned search_path would hide the caller's schemas from to_regclass, so an
	// unqualified table name would never be found.
	if strings.Contains(s, "SET search_path") {
		t.Error("blast_radius must resolve names with the caller's search_path")
	}
	// Reported names come from pg_identify_object (always schema-qualified), not
	// from regclass text, which depends on the caller's search_path.
	if strings.Contains(s, "::regclass::text") {
		t.Error("report schema-qualified identities, not regclass text")
	}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(insert|update|delete)\s+(into|from)?\s*bb\.`),
		regexp.MustCompile(`(?i)alter\s+table`),
		regexp.MustCompile(`(?i)drop\s+(table|trigger|function|event\s+trigger|index)`),
	} {
		if loc := re.FindStringIndex(s); loc != nil {
			t.Errorf("impact.sql must only read: found %q", s[loc[0]:loc[1]])
		}
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		sql  string
		want Target
		ok   bool
	}{
		{"DROP TABLE orders", Target{Object: "orders", Action: "drop"}, true},
		{"drop table if exists public.orders, items cascade", Target{Object: "public.orders", Action: "drop"}, true},
		{"DROP INDEX CONCURRENTLY IF EXISTS orders_note_idx", Target{Object: "orders_note_idx", Action: "drop"}, true},
		{"DROP MATERIALIZED VIEW mv", Target{Object: "mv", Action: "drop"}, true},
		{"TRUNCATE TABLE ONLY orders", Target{Object: "orders", Action: "truncate"}, true},
		{"ALTER TABLE orders DROP COLUMN total", Target{Object: "orders", Column: "total", Action: "drop-column"}, true},
		{"ALTER TABLE IF EXISTS ONLY orders DROP COLUMN IF EXISTS total CASCADE", Target{Object: "orders", Column: "total", Action: "drop-column"}, true},
		{"alter table orders drop note", Target{Object: "orders", Column: "note", Action: "drop-column"}, true},
		{"ALTER TABLE orders DROP CONSTRAINT orders_pkey", Target{Object: "orders", Action: "alter"}, true},
		{`ALTER TABLE public."Orders" ALTER COLUMN "Total" TYPE bigint`, Target{Object: `public."Orders"`, Column: "Total", Action: "alter-column-type"}, true},
		{"ALTER TABLE orders ALTER total SET DATA TYPE numeric", Target{Object: "orders", Column: "total", Action: "alter-column-type"}, true},
		{"ALTER TABLE orders ALTER COLUMN total SET DEFAULT 0", Target{Object: "orders", Column: "total", Action: "alter-column"}, true},
		{"ALTER TABLE orders ALTER COLUMN total DROP DEFAULT", Target{Object: "orders", Column: "total", Action: "alter-column"}, true},
		{"ALTER TABLE orders RENAME TO purchases", Target{Object: "orders", Action: "rename"}, true},
		{"ALTER TABLE orders RENAME COLUMN note TO memo", Target{Object: "orders", Column: "note", Action: "rename-column"}, true},
		{"ALTER TABLE orders ADD COLUMN memo text", Target{Object: "orders", Action: "alter"}, true},
		{`ALTER TABLE "we""ird" DROP COLUMN "a b"`, Target{Object: `"we""ird"`, Column: "a b", Action: "drop-column"}, true},
		{"ALTER VIEW v RENAME TO w", Target{Object: "v", Action: "rename"}, true},
		{"CREATE UNIQUE INDEX CONCURRENTLY i ON ONLY public.orders (total)", Target{Object: "public.orders", Action: "create-index"}, true},
		{"GRANT SELECT ON TABLE orders TO PUBLIC", Target{Object: "orders", Action: "grant"}, true},
		{"revoke all on orders from public", Target{Object: "orders", Action: "revoke"}, true},
		{"-- note\nDROP TABLE /* old */ orders; DROP TABLE other", Target{Object: "orders", Action: "drop"}, true},
		{"GRANT SELECT ON ALL TABLES IN SCHEMA public TO r", Target{}, false},
		{"CREATE TABLE t (x int)", Target{}, false},
		{"SELECT 1", Target{}, false},
		{"DROP FUNCTION f()", Target{}, false},
		{"", Target{}, false},
	}
	for _, c := range cases {
		got, ok := ParseTarget(c.sql)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseTarget(%q) = %+v, %v; want %+v, %v", c.sql, got, ok, c.want, c.ok)
		}
	}
}

func TestTargetDestructive(t *testing.T) {
	for _, a := range []string{"drop", "drop-column", "alter-column-type", "truncate", "rename", "rename-column"} {
		if !(Target{Action: a}).Destructive() {
			t.Errorf("%s should be destructive", a)
		}
	}
	for _, a := range []string{"alter", "alter-column", "create-index", "grant", "revoke", ""} {
		if (Target{Action: a}).Destructive() {
			t.Errorf("%s should not be destructive", a)
		}
	}
}
