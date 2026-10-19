// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// A table's CREATE script, put together as pg_dump would: columns, then its
// constraints, then the indexes and triggers that are the user's own.
func TestTableDDL(t *testing.T) {
	d := ObjectDetail{
		CatalogObject: CatalogObject{Kind: "table", Schema: "shop", Name: "Orders"},
		Columns: []CatalogCol{
			{Name: "id", Type: "bigint", NotNull: true, Identity: "always"},
			{Name: "qty", Type: "integer", NotNull: true, Default: "1"},
			{Name: "total", Type: "numeric", Generated: "(qty * 2)"},
			{Name: "Note", Type: "text", Comment: "it's free"},
		},
		Constraints: []CatalogPart{{Name: "orders_pkey", Kind: "primary key", Def: "PRIMARY KEY (id)"}},
		Indexes: []CatalogPart{
			{Name: "orders_pkey", Def: "CREATE UNIQUE INDEX orders_pkey ON shop.\"Orders\" USING btree (id)", Constraint: true},
			{Name: "orders_qty", Def: "CREATE INDEX orders_qty ON shop.\"Orders\" USING btree (qty)"},
		},
		Triggers: []CatalogPart{
			{Name: "bb_record_dml", Def: "CREATE TRIGGER bb_record_dml …", System: true},
			{Name: "mine", Def: "CREATE TRIGGER mine …", Disabled: true},
		},
	}
	got := tableDDL(d, "", "")
	want := `CREATE TABLE shop."Orders" (
    id bigint GENERATED ALWAYS AS IDENTITY,
    qty integer DEFAULT 1 NOT NULL,
    total numeric GENERATED ALWAYS AS ((qty * 2)) STORED,
    "Note" text,
    CONSTRAINT orders_pkey PRIMARY KEY (id)
);

CREATE INDEX orders_qty ON shop."Orders" USING btree (qty);

CREATE TRIGGER mine …;
ALTER TABLE shop."Orders" DISABLE TRIGGER mine;

COMMENT ON COLUMN shop."Orders"."Note" IS 'it''s free';
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, "bb_record_dml") {
		t.Fatal("FoxByte's own trigger is in the script")
	}
	if p := tableDDL(ObjectDetail{CatalogObject: CatalogObject{Schema: "s", Name: "e", Sub: "partitioned"},
		Columns: []CatalogCol{{Name: "at", Type: "date"}}}, "RANGE (at)", ""); !strings.Contains(p, ") PARTITION BY RANGE (at);") {
		t.Fatalf("%s", p)
	}
}

func TestRelKind(t *testing.T) {
	for k, want := range map[string][2]string{
		"r": {"table", ""}, "p": {"table", "partitioned"}, "f": {"table", "foreign"},
		"v": {"view", ""}, "m": {"view", "materialized"}, "S": {"sequence", ""},
	} {
		if kind, sub := relKind(k); kind != want[0] || sub != want[1] {
			t.Errorf("%s: %s %s", k, kind, sub)
		}
	}
}

func TestCommentDDL(t *testing.T) {
	for _, c := range []struct {
		d    ObjectDetail
		want string
	}{
		{ObjectDetail{CatalogObject: CatalogObject{Kind: "view", Sub: "materialized", Schema: "s", Name: "v"}, Comment: "x"}, "COMMENT ON MATERIALIZED VIEW s.v IS 'x';"},
		{ObjectDetail{CatalogObject: CatalogObject{Kind: "function", Schema: "s", Name: "f", Args: "a integer"}, Comment: "x"}, "COMMENT ON FUNCTION s.f(a integer) IS 'x';"},
		{ObjectDetail{CatalogObject: CatalogObject{Kind: "type", Sub: "domain", Schema: "s", Name: "d"}, Comment: "x"}, "COMMENT ON DOMAIN s.d IS 'x';"},
		{ObjectDetail{CatalogObject: CatalogObject{Kind: "schema", Name: "Shop"}, Comment: "x"}, `COMMENT ON SCHEMA "Shop" IS 'x';`},
	} {
		if got := strings.TrimSpace(commentDDL(c.d)); got != c.want {
			t.Errorf("%s, want %s", got, c.want)
		}
	}
}

// The object route refuses what is not an object before it opens anything.
func TestCatalogObjectRouteRefusesABadOID(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/branches/main/schema/table/abc", nil)
	r.SetPathValue("name", "main")
	r.SetPathValue("kind", "table")
	r.SetPathValue("oid", "abc")
	w := httptest.NewRecorder()
	handleCatalogObject(w, r)
	if w.Code != 400 {
		t.Fatalf("%d", w.Code)
	}
}
