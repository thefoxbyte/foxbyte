// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"testing"
)

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
