//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"fmt"
	"testing"
	"time"

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

// Transaction framing: what a subscriber sees around a commit.
//
// The case this exists for is an application moving money between two rows in
// one transaction. Without frames a subscriber sees two independent changes and
// cannot tell they belong together, so anything derived from the feed passes
// through a state where one side moved and the other had not — a glitch in a
// cache, a wrong answer in a ledger.
//
// These assert the sequence a decoder produces, because that is the contract:
// the order of events, the boundary stamped on each change, and the two cases
// where a frame must not appear at all.

// decodeInto runs a sequence of messages through a decoder and returns what the
// hub received, in order.
func decodeInto(t *testing.T, msgs ...pglogrepl.Message) []any {
	t.Helper()
	h := NewHub()
	sub := h.Subscribe()
	defer sub.Close()
	d := &Decoder{hub: h, relations: map[uint32]Relation{}}
	for i, m := range msgs {
		// The record position: distinct per message, so a test can tell the
		// per-record LSN from the transaction's commit LSN.
		if err := d.handleMessage(m, fmt.Sprintf("0/%d", 100+i)); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	var got []any
	for {
		select {
		case ev := <-sub.Events():
			got = append(got, ev)
		default:
			return got
		}
	}
}

func ordersRelation() *pglogrepl.RelationMessage {
	return &pglogrepl.RelationMessage{
		RelationID: 1, Namespace: "public", RelationName: "orders", ReplicaIdentity: 'd',
		Columns: []*pglogrepl.RelationMessageColumn{
			{Name: "id", DataType: 20, Flags: 1},
			{Name: "note", DataType: 25, Flags: 0},
		},
	}
}

func insertOf(id, note string) *pglogrepl.InsertMessage {
	return &pglogrepl.InsertMessage{RelationID: 1, Tuple: &pglogrepl.TupleData{
		Columns: []*pglogrepl.TupleDataColumn{
			{DataType: KindText, Data: []byte(id)},
			{DataType: KindText, Data: []byte(note)},
		}}}
}

const txCommitLSN = "0/ABCDEF"

func beginAt(xid uint32) *pglogrepl.BeginMessage {
	lsn, err := pglogrepl.ParseLSN(txCommitLSN)
	if err != nil {
		panic(err)
	}
	return &pglogrepl.BeginMessage{Xid: xid, FinalLSN: lsn,
		CommitTime: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
}

func commitOf() *pglogrepl.CommitMessage {
	lsn, _ := pglogrepl.ParseLSN(txCommitLSN)
	return &pglogrepl.CommitMessage{CommitLSN: lsn,
		CommitTime: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
}

func TestTransactionFraming(t *testing.T) {
	got := decodeInto(t, ordersRelation(), beginAt(4242),
		insertOf("1", "from"), insertOf("2", "to"), commitOf())

	// schema, begin, change, change, commit — in that order.
	if len(got) != 5 {
		t.Fatalf("got %d events, want 5: %#v", len(got), got)
	}
	if _, ok := got[0].(Schema); !ok {
		t.Fatalf("event 0 is %T, want the schema", got[0])
	}

	b, ok := got[1].(Begin)
	if !ok {
		t.Fatalf("event 1 is %T, want a begin", got[1])
	}
	if b.Xid != 4242 {
		t.Errorf("begin xid = %d, want 4242", b.Xid)
	}
	// Known at BEGIN, from pgoutput's FinalLSN: a subscriber can record the
	// boundary before it applies anything.
	if b.CommitLSN != txCommitLSN {
		t.Errorf("begin commit_lsn = %q, want %q", b.CommitLSN, txCommitLSN)
	}
	if b.At != "2026-10-09T12:00:00Z" {
		t.Errorf("begin at = %q, want the commit timestamp Postgres recorded", b.At)
	}

	for i, idx := range []int{2, 3} {
		c, ok := got[idx].(Change)
		if !ok {
			t.Fatalf("event %d is %T, want a change", idx, got[idx])
		}
		if c.Xid != 4242 {
			t.Errorf("change %d xid = %d, want 4242", i, c.Xid)
		}
		// Every change in a transaction carries the same boundary, which is
		// what makes it safe to resume from.
		if c.CommitLSN != txCommitLSN {
			t.Errorf("change %d commit_lsn = %q, want the transaction's %q", i, c.CommitLSN, txCommitLSN)
		}
		// And its own position, which is a different number.
		if c.LSN == "" || c.LSN == txCommitLSN {
			t.Errorf("change %d lsn = %q, want its own record position", i, c.LSN)
		}
	}

	cm, ok := got[4].(Commit)
	if !ok {
		t.Fatalf("event 4 is %T, want a commit", got[4])
	}
	if cm.Xid != 4242 {
		t.Errorf("commit xid = %d, want 4242", cm.Xid)
	}
	if cm.Changes != 2 {
		t.Errorf("commit changes = %d, want 2 — a subscriber uses this to tell a whole frame from a partial one", cm.Changes)
	}
	if cm.CommitLSN != txCommitLSN {
		t.Errorf("commit commit_lsn = %q, want %q", cm.CommitLSN, txCommitLSN)
	}
}

// A transaction that touched only tables nobody subscribed to must produce
// nothing at all. Postgres reports those — pgoutput sends BEGIN and COMMIT for
// a transaction whose changes were all filtered out by the publication — and a
// frame around no changes is noise every subscriber would have to learn to
// ignore.
func TestEmptyTransactionProducesNoFrame(t *testing.T) {
	got := decodeInto(t, beginAt(7), commitOf())
	if len(got) != 0 {
		t.Fatalf("an empty transaction produced %d event(s): %#v", len(got), got)
	}
}

// And a transaction whose only changes were on an unknown relation likewise:
// the decoder drops those (it has no shape for them), so the frame would be
// empty for the same reason.
func TestTransactionWithOnlyUnknownRelationsProducesNoFrame(t *testing.T) {
	// No RelationMessage first, so relation 1 is unknown.
	got := decodeInto(t, beginAt(8), insertOf("1", "x"), commitOf())
	if len(got) != 0 {
		t.Fatalf("produced %d event(s) for an unknown relation: %#v", len(got), got)
	}
}

// Two transactions in a row must not leak state into each other: the second
// one's changes carry its own xid and its own boundary, and the counts restart.
func TestConsecutiveTransactionsDoNotShareState(t *testing.T) {
	h := NewHub()
	sub := h.Subscribe()
	defer sub.Close()
	d := &Decoder{hub: h, relations: map[uint32]Relation{}}

	second, err := pglogrepl.ParseLSN("0/BBBBBB")
	if err != nil {
		t.Fatal(err)
	}
	msgs := []pglogrepl.Message{
		ordersRelation(),
		beginAt(1), insertOf("1", "a"), commitOf(),
		&pglogrepl.BeginMessage{Xid: 2, FinalLSN: second,
			CommitTime: time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC)},
		insertOf("2", "b"), insertOf("3", "c"),
		&pglogrepl.CommitMessage{CommitLSN: second,
			CommitTime: time.Date(2026, 10, 9, 13, 0, 0, 0, time.UTC)},
	}
	for i, m := range msgs {
		if err := d.handleMessage(m, fmt.Sprintf("0/%d", 200+i)); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	var commits []Commit
	var changes []Change
	for {
		done := false
		select {
		case ev := <-sub.Events():
			switch e := ev.(type) {
			case Commit:
				commits = append(commits, e)
			case Change:
				changes = append(changes, e)
			}
		default:
			done = true
		}
		if done {
			break
		}
	}
	if len(commits) != 2 {
		t.Fatalf("got %d commits, want 2", len(commits))
	}
	if commits[0].Changes != 1 || commits[1].Changes != 2 {
		t.Errorf("counts are %d and %d, want 1 and 2 — the count did not restart", commits[0].Changes, commits[1].Changes)
	}
	if commits[0].Xid != 1 || commits[1].Xid != 2 {
		t.Errorf("xids are %d and %d, want 1 and 2", commits[0].Xid, commits[1].Xid)
	}
	if len(changes) != 3 {
		t.Fatalf("got %d changes, want 3", len(changes))
	}
	if changes[0].Xid != 1 {
		t.Errorf("the first transaction's change has xid %d", changes[0].Xid)
	}
	for _, c := range changes[1:] {
		if c.Xid != 2 || c.CommitLSN != "0/BBBBBB" {
			t.Errorf("a second-transaction change carries xid %d and boundary %q", c.Xid, c.CommitLSN)
		}
	}
}

// A change arriving with no transaction open should never happen — pgoutput
// wraps every DML message in BEGIN and COMMIT — but it must not produce a
// change with no resume position, which would leave a subscriber unable to
// resume at all. The record's own position is used instead.
func TestChangeOutsideATransactionStillCarriesAPosition(t *testing.T) {
	got := decodeInto(t, ordersRelation(), insertOf("1", "orphan"))
	if len(got) != 2 {
		t.Fatalf("got %d events, want the schema and the change: %#v", len(got), got)
	}
	c, ok := got[1].(Change)
	if !ok {
		t.Fatalf("event 1 is %T, want a change", got[1])
	}
	if c.CommitLSN == "" {
		t.Error("the change has no resume position at all")
	}
	if c.CommitLSN != c.LSN {
		t.Errorf("commit_lsn = %q and lsn = %q; with no transaction open they should be the same record position", c.CommitLSN, c.LSN)
	}
}
