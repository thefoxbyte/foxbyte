//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func rel(identity byte) Relation {
	return Relation{Schema: "public", Name: "orders", ReplicaIdentity: identity,
		Columns: []Column{
			{Name: "id", TypeOID: 20, Key: true},
			{Name: "note", TypeOID: 25},
			{Name: "body", TypeOID: 25}, // the TOASTable one
		}}
}

func text(s string) ColumnValue { return ColumnValue{Kind: KindText, Text: s} }
func null() ColumnValue         { return ColumnValue{Kind: KindNull} }
func untouched() ColumnValue    { return ColumnValue{Kind: KindUnchanged} }
func strp(s string) *string     { return &s }

// The trap that silently corrupts a subscriber's copy. Postgres does not send a
// large column an UPDATE did not touch, so it is absent from the tuple. A
// decoder that wrote null there would overwrite a good value.
func TestAnUnchangedToastedColumnIsNamedNotNulled(t *testing.T) {
	c := BuildChange(rel('d'), "update", "0/1", nil,
		[]ColumnValue{text("7"), text("hi"), untouched()})

	if _, present := c.New["body"]; present {
		t.Error("an unchanged TOASTed column was put in `new`; absent is the only honest answer")
	}
	if !reflect.DeepEqual(c.Unchanged, []string{"body"}) {
		t.Errorf("Unchanged = %v, want [body]", c.Unchanged)
	}
	// And it marshals as absent, not as null.
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), `"body":null`) {
		t.Errorf("an unchanged column marshalled as null: %s", b)
	}
}

// NULL and the empty string are different things, and a map[string]string could
// not say so.
func TestNullAndEmptyStringStayDistinct(t *testing.T) {
	c := BuildChange(rel('d'), "insert", "0/1", nil,
		[]ColumnValue{text("1"), null(), text("")})

	if v, ok := c.New["note"]; !ok || v != nil {
		t.Errorf("a SQL NULL did not come through as null: %#v", v)
	}
	if v, ok := c.New["body"]; !ok || v == nil || *v != "" {
		t.Errorf("an empty string did not come through as \"\": %#v", v)
	}
	b, _ := json.Marshal(c.New)
	if !strings.Contains(string(b), `"note":null`) || !strings.Contains(string(b), `"body":""`) {
		t.Errorf("JSON does not distinguish them: %s", b)
	}
}

// Values are Postgres text as JSON strings. A bigint does not survive a
// JavaScript number, and money in a numeric survives it even less.
func TestValuesAreStringsNotNumbers(t *testing.T) {
	c := BuildChange(rel('d'), "insert", "0/1", nil,
		[]ColumnValue{text("9007199254740993"), text("1"), text("0.1")})
	b, _ := json.Marshal(c.New)
	if !strings.Contains(string(b), `"id":"9007199254740993"`) {
		t.Errorf("a bigint was not carried as a string: %s", b)
	}
}

// A delete under the default identity carries the key and nothing else: that is
// all Postgres sent. Under FULL it carries the whole old row.
func TestDeleteCarriesWhatItCan(t *testing.T) {
	old := []ColumnValue{text("7"), text("hi"), text("big")}

	d := BuildChange(rel('d'), "delete", "0/9", old, nil)
	if got := d.Identity["id"]; got == nil || *got != "7" {
		t.Errorf("identity = %#v, want the key", d.Identity)
	}
	if d.Old != nil {
		t.Errorf("a delete under the default identity carried an old row: %#v", d.Old)
	}
	if d.New != nil {
		t.Errorf("a delete carried a new row: %#v", d.New)
	}

	f := BuildChange(rel('f'), "delete", "0/9", old, nil)
	if f.Old == nil || *f.Old["note"] != "hi" {
		t.Errorf("under FULL a delete must carry the whole old row: %#v", f.Old)
	}
}

// `changed` can only be computed where there is an old row to compare against.
// Under the default identity a guess would be worse than silence.
func TestChangedOnlyUnderFullIdentity(t *testing.T) {
	old := []ColumnValue{text("7"), text("before"), text("same")}
	new_ := []ColumnValue{text("7"), text("after"), text("same")}

	full := BuildChange(rel('f'), "update", "0/2", old, new_)
	if !reflect.DeepEqual(full.Changed, []string{"note"}) {
		t.Errorf("Changed = %v, want [note]", full.Changed)
	}
	plain := BuildChange(rel('d'), "update", "0/2", nil, new_)
	if plain.Changed != nil {
		t.Errorf("Changed was computed without an old row: %v", plain.Changed)
	}
	if plain.Old != nil {
		t.Errorf("an old row appeared without FULL: %#v", plain.Old)
	}
}

// A column Postgres did not send is never called changed — it is unchanged by
// definition, and claiming otherwise would send a subscriber looking for a
// value that was never transmitted.
func TestAnUnsentColumnIsNeverCalledChanged(t *testing.T) {
	old := []ColumnValue{text("7"), text("a"), text("big-old")}
	new_ := []ColumnValue{text("7"), text("b"), untouched()}
	c := BuildChange(rel('f'), "update", "0/3", old, new_)
	for _, n := range c.Changed {
		if n == "body" {
			t.Error("an unchanged TOASTed column was reported as changed")
		}
	}
	if !reflect.DeepEqual(c.Unchanged, []string{"body"}) {
		t.Errorf("Unchanged = %v", c.Unchanged)
	}
}

// An update that changes the key itself must identify the row the subscriber
// already knows about — the old one.
func TestIdentityComesFromTheOldRowWhenThereIsOne(t *testing.T) {
	old := []ColumnValue{text("7"), text("x"), text("y")}
	new_ := []ColumnValue{text("8"), text("x"), text("y")}
	c := BuildChange(rel('f'), "update", "0/4", old, new_)
	if got := c.Identity["id"]; got == nil || *got != "7" {
		t.Errorf("identity = %#v, want the row the subscriber knew", c.Identity)
	}
}

// Identity is always present, whatever the action, because it is the only row
// locator promisable across every identity setting.
func TestIdentityIsAlwaysPresent(t *testing.T) {
	for _, c := range []Change{
		BuildChange(rel('d'), "insert", "0/1", nil, []ColumnValue{text("1"), null(), null()}),
		BuildChange(rel('d'), "update", "0/2", nil, []ColumnValue{text("1"), null(), null()}),
		BuildChange(rel('d'), "delete", "0/3", []ColumnValue{text("1"), null(), null()}, nil),
	} {
		if len(c.Identity) == 0 {
			t.Errorf("%s has no identity", c.Action)
		}
	}
}

// A relation that gained a column mid-stream must not panic the decoder; the
// next schema event corrects it.
func TestATupleWiderThanTheRelationDoesNotPanic(t *testing.T) {
	c := BuildChange(rel('d'), "insert", "0/1", nil,
		[]ColumnValue{text("1"), text("a"), text("b"), text("surprise")})
	if len(c.New) != 3 {
		t.Errorf("New = %v, want only the columns the relation describes", c.New)
	}
}
