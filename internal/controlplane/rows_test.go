// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func sp(s string) *string { return &s }

var editCols = map[string]editCol{
	"id":    {typ: "integer"},
	"name":  {typ: "text"},
	"Price": {typ: "numeric(10,2)"},
	"total": {typ: "numeric", generated: true},
	"seq":   {typ: "bigint", identity: "a"},
	"code":  {typ: "integer", identity: "d"},
}

const qt = `"public"."orders"`

func TestRowStatementInsert(t *testing.T) {
	stmt, args, err := rowStatement(qt, editCols, []string{"id"}, RowChange{Op: "insert", Values: map[string]*string{"name": sp("Ada'); DROP TABLE x; --"), "Price": nil, "id": sp("7")}})
	if err != nil {
		t.Fatal(err)
	}
	want := `INSERT INTO "public"."orders" ("Price", "id", "name") VALUES (CAST($1::text AS numeric(10,2)), CAST($2::text AS integer), CAST($3::text AS text))`
	if stmt != want {
		t.Fatalf("%s\nwant %s", stmt, want)
	}
	// Values only ever travel as parameters.
	if !reflect.DeepEqual(args, []any{nil, "7", "Ada'); DROP TABLE x; --"}) {
		t.Fatalf("%#v", args)
	}
	if s, a, _ := rowStatement(qt, editCols, []string{"id"}, RowChange{Op: "insert"}); s != `INSERT INTO "public"."orders" DEFAULT VALUES` || a != nil {
		t.Fatalf("%s %v", s, a)
	}
	// An identity BY DEFAULT column may be given a value.
	if _, _, err := rowStatement(qt, editCols, []string{"id"}, RowChange{Op: "insert", Values: map[string]*string{"code": sp("1")}}); err != nil {
		t.Fatal(err)
	}
}

func TestRowStatementUpdateAndDelete(t *testing.T) {
	stmt, args, err := rowStatement(qt, editCols, []string{"id"}, RowChange{
		Op: "update", Key: map[string]*string{"id": sp("7")},
		Values: map[string]*string{"name": sp("Bea")}, Old: map[string]*string{"name": nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `UPDATE "public"."orders" SET "name" = CAST($1::text AS text) WHERE "id" = CAST($2::text AS integer) AND "name" IS NOT DISTINCT FROM CAST($3::text AS text)`
	if stmt != want || !reflect.DeepEqual(args, []any{"Bea", "7", nil}) {
		t.Fatalf("%s %#v", stmt, args)
	}
	stmt, args, err = rowStatement(qt, editCols, []string{"id", "name"}, RowChange{Op: "delete", Key: map[string]*string{"name": sp("x"), "id": sp("1")}})
	if err != nil || stmt != `DELETE FROM "public"."orders" WHERE "id" = CAST($1::text AS integer) AND "name" = CAST($2::text AS text)` || !reflect.DeepEqual(args, []any{"1", "x"}) {
		t.Fatalf("%s %#v %v", stmt, args, err)
	}
}

// What a save refuses, before anything runs.
func TestRowStatementRefuses(t *testing.T) {
	for _, c := range []struct {
		name string
		ch   RowChange
		want string
	}{
		{"no such column", RowChange{Op: "insert", Values: map[string]*string{"nope": sp("1")}}, `no column "nope"`},
		{"generated", RowChange{Op: "update", Key: map[string]*string{"id": sp("1")}, Values: map[string]*string{"total": sp("1")}}, "generated"},
		{"identity always", RowChange{Op: "insert", Values: map[string]*string{"seq": sp("1")}}, "GENERATED ALWAYS"},
		{"no key", RowChange{Op: "delete"}, "primary key (id)"},
		{"a NULL key", RowChange{Op: "delete", Key: map[string]*string{"id": nil}}, "primary key"},
		{"the wrong key", RowChange{Op: "delete", Key: map[string]*string{"name": sp("x")}}, "primary key"},
		{"nothing to change", RowChange{Op: "update", Key: map[string]*string{"id": sp("1")}}, "at least one column"},
		{"an unknown op", RowChange{Op: "upsert"}, `not "upsert"`},
	} {
		if _, _, err := rowStatement(qt, editCols, []string{"id"}, c.ch); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestHandleRowEditsRefusesABadBody(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/branches/main/rows", strings.NewReader("not json"))
	r.SetPathValue("name", "main")
	w := httptest.NewRecorder()
	handleRowEdits(w, r)
	if w.Code != 400 {
		t.Fatalf("%d", w.Code)
	}
}
