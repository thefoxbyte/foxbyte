//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"testing"

	"github.com/jackc/pglogrepl"
)

// pgoutput marks the replica-identity columns with flag 1, and those are the
// only row locator a subscriber can rely on. Reading that flag wrongly would
// produce an identity that looks right and locates nothing.
func TestRelationKeepsTheKeyFlag(t *testing.T) {
	rel := relationFrom(&pglogrepl.RelationMessage{
		Namespace: "public", RelationName: "orders", ReplicaIdentity: 'd',
		Columns: []*pglogrepl.RelationMessageColumn{
			{Name: "id", DataType: 20, Flags: 1},
			{Name: "note", DataType: 25, Flags: 0},
		},
	})
	if rel.Qualified() != "public.orders" {
		t.Errorf("Qualified = %q", rel.Qualified())
	}
	if !rel.Columns[0].Key {
		t.Error("the key column lost its flag")
	}
	if rel.Columns[1].Key {
		t.Error("a non-key column was marked as part of the identity")
	}
}

// The three column kinds have to survive the conversion, because the whole wire
// format is built on telling them apart.
func TestTupleKeepsNullUnchangedAndValue(t *testing.T) {
	got := tupleFrom(&pglogrepl.TupleData{Columns: []*pglogrepl.TupleDataColumn{
		{DataType: KindText, Data: []byte("7")},
		{DataType: KindNull},
		{DataType: KindUnchanged},
	}})
	want := []ColumnValue{{Kind: KindText, Text: "7"}, {Kind: KindNull}, {Kind: KindUnchanged}}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("column %d = %#v, want %#v", i, got[i], want[i])
		}
	}
	if tupleFrom(nil) != nil {
		t.Error("a missing tuple must convert to nothing, not an empty row")
	}
}

// A schema event is worth sending when the shape changed and noise otherwise.
func TestSameShape(t *testing.T) {
	a := Relation{Schema: "public", Name: "t", Columns: []Column{{Name: "id", TypeOID: 20, Key: true}}}
	same := a
	if !sameShape(a, same) {
		t.Error("an identical relation was reported as changed")
	}
	for name, b := range map[string]Relation{
		"a renamed column": {Schema: "public", Name: "t", Columns: []Column{{Name: "pk", TypeOID: 20, Key: true}}},
		"a changed type":   {Schema: "public", Name: "t", Columns: []Column{{Name: "id", TypeOID: 23, Key: true}}},
		"a lost key":       {Schema: "public", Name: "t", Columns: []Column{{Name: "id", TypeOID: 20}}},
		"an added column":  {Schema: "public", Name: "t", Columns: []Column{{Name: "id", TypeOID: 20, Key: true}, {Name: "x"}}},
		"another table":    {Schema: "public", Name: "u", Columns: []Column{{Name: "id", TypeOID: 20, Key: true}}},
	} {
		if sameShape(a, b) {
			t.Errorf("%s was not noticed", name)
		}
	}
}

// The position reported to Postgres advances on commit, never on receipt.
// Acknowledging early is how a subscriber that drops at the wrong moment comes
// back to find the feed moved on without it, with no error anywhere.
func TestThePositionAdvancesOnCommitOnly(t *testing.T) {
	h := NewHub()
	d := &Decoder{hub: h, relations: map[uint32]Relation{}}
	s := h.Subscribe()
	defer s.Close()

	d.relations[1] = Relation{Schema: "public", Name: "t", ReplicaIdentity: 'd',
		Columns: []Column{{Name: "id", TypeOID: 20, Key: true}}}

	// A row arrives: subscribers see it, but the position has not moved.
	if err := d.handleMessage(&pglogrepl.InsertMessage{RelationID: 1,
		Tuple: &pglogrepl.TupleData{Columns: []*pglogrepl.TupleDataColumn{
			{DataType: KindText, Data: []byte("1")}}}}, "0/10"); err != nil {
		t.Fatal(err)
	}
	if d.acked != 0 {
		t.Errorf("the position advanced on a row, before the transaction committed: %v", d.acked)
	}
	// The transaction commits, and only now is it safe to acknowledge.
	if err := d.handleMessage(&pglogrepl.CommitMessage{CommitLSN: 42}, "0/10"); err != nil {
		t.Fatal(err)
	}
	if d.acked != 42 {
		t.Errorf("acked = %v, want the commit's LSN", d.acked)
	}
}
