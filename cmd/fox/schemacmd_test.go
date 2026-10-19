// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/controlplane"
)

func TestObjectNamed(t *testing.T) {
	o := controlplane.CatalogObject{Kind: "table", Schema: "shop", Name: "orders"}
	for want, ok := range map[string]bool{"orders": true, "ORDERS": true, "shop.orders": true, `"orders"`: true, "public.orders": false, "order": false} {
		if objectNamed(o, want) != ok {
			t.Errorf("%s: %v", want, !ok)
		}
	}
	if !objectNamed(controlplane.CatalogObject{Kind: "extension", Schema: "public", Name: "dblink"}, "dblink") {
		t.Error("an extension by its name")
	}
}

func TestPrintCatalog(t *testing.T) {
	objs := []controlplane.CatalogObject{
		{Kind: "schema", Name: "shop"},
		{Kind: "schema", Name: "empty"},
		{Kind: "table", Schema: "shop", Name: "orders"},
		{Kind: "table", Schema: "shop", Name: "events", Sub: "partitioned"},
		{Kind: "function", Schema: "shop", Name: "total", Args: "o_id integer"},
		{Kind: "extension", Schema: "public", Name: "dblink", Sub: "1.2"},
	}
	var b bytes.Buffer
	printCatalog(&b, objs, false)
	out := b.String()
	for _, want := range []string{"shop\n  tables (2)\n    orders\n    events [partitioned]\n  functions (1)\n    total(o_id integer)", "empty\n  (empty)", "extensions (1)\n  dblink 1.2"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	b.Reset()
	printCatalog(&b, objs[2:3], true)
	if !strings.Contains(b.String(), "table  shop.orders") {
		t.Errorf("%q", b.String())
	}
}

func TestPrintObject(t *testing.T) {
	var b bytes.Buffer
	printObject(&b, controlplane.ObjectDetail{
		CatalogObject: controlplane.CatalogObject{Kind: "table", Schema: "shop", Name: "orders"},
		Columns:       []controlplane.CatalogCol{{Name: "id", Type: "integer", NotNull: true}},
		Triggers:      []controlplane.CatalogPart{{Name: "bb_record_dml", Def: "CREATE TRIGGER …", System: true}},
		DDL:           "CREATE TABLE shop.orders (\n    id integer NOT NULL\n);\n",
	})
	out := b.String()
	for _, want := range []string{"table shop.orders", "id  integer  not null", "bb_record_dml (FoxByte)", "-- CREATE script\nCREATE TABLE shop.orders"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
