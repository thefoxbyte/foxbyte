//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"
)

// fakeCatalog answers the decoder's checks from a table of facts by OID. An
// OID it has no entry for is an ordinary readable table, so the decoding tests
// that are not about the guard see the feed as it always was.
type fakeCatalog struct {
	tables map[uint32]Table
	asked  int
	err    error
}

func (f *fakeCatalog) facts(oid uint32) Table {
	if t, ok := f.tables[oid]; ok {
		return t
	}
	return app()
}

func (f *fakeCatalog) Published(context.Context) ([]Table, error) {
	f.asked++
	if f.err != nil {
		return nil, f.err
	}
	out := []Table{}
	for oid := range f.tables {
		out = append(out, f.facts(oid))
	}
	return out, nil
}

func (f *fakeCatalog) Relation(_ context.Context, oid uint32) (Table, bool, error) {
	f.asked++
	if f.err != nil {
		return Table{}, false, f.err
	}
	return f.facts(oid), true, nil
}

// received returns what a subscriber has been sent so far.
func received(s *Subscriber) []any {
	var got []any
	for {
		select {
		case ev := <-s.Events():
			got = append(got, ev)
		default:
			return got
		}
	}
}

func changesIn(evs []any) int {
	n := 0
	for _, ev := range evs {
		if _, ok := ev.(Change); ok {
			n++
		}
	}
	return n
}

func guardedDecoder(cat *fakeCatalog) (*Decoder, *Subscriber) {
	h := NewHub()
	return &Decoder{hub: h, slot: "test_slot", relations: map[uint32]Relation{}, catalog: cat}, h.Subscribe()
}

func feed(t *testing.T, d *Decoder, msgs ...pglogrepl.Message) {
	t.Helper()
	for _, m := range msgs {
		if err := d.handleMessage(m, "0/10"); err != nil {
			t.Fatal(err)
		}
	}
}

// What blocks a table that is already streaming: the read-access rules
// Enable refuses on, and not the replica-identity ones.
func TestWhatStopsAStreamingTable(t *testing.T) {
	for name, c := range map[string]struct {
		mutate func(*Table)
		want   string
	}{
		"nothing":            {func(*Table) {}, ""},
		"no identity":        {func(t *Table) { t.HasPrimaryKey = false }, ""},
		"row-level security": {func(t *Table) { t.RLSEnabled = true }, "row-level security"},
		"no SELECT":          {func(t *Table) { t.ClientCanSelect = false }, "can no longer read"},
		"no schema USAGE":    {func(t *Table) { t.ClientCanUseSchema = false }, "schema"},
		"a hidden column":    {func(t *Table) { t.ColumnsHidden = []string{"secret"} }, "secret"},
	} {
		tb := app()
		c.mutate(&tb)
		got := streamBlock(tb)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: streamBlock = %q, want %q", name, got, c.want)
		}
	}
}

// A table described again after it gained RLS stops streaming at once: no
// schema event, and none of the changes that follow.
func TestARelationMessageForATableThatNowHasRLSStopsItsChanges(t *testing.T) {
	cat := &fakeCatalog{tables: map[uint32]Table{1: app()}}
	d, sub := guardedDecoder(cat)
	defer sub.Close()

	feed(t, d, ordersRelation(), beginAt(1), insertOf("1", "before"), commitOf())
	if n := changesIn(received(sub)); n != 1 {
		t.Fatalf("before RLS: %d changes, want 1", n)
	}

	rls := app()
	rls.RLSEnabled = true
	cat.tables[1] = rls
	feed(t, d, ordersRelation(), beginAt(2), insertOf("2", "after"), commitOf())
	if evs := received(sub); len(evs) != 0 {
		t.Fatalf("after RLS the feed still sent %d event(s): %#v", len(evs), evs)
	}
	if d.verdicts["public.orders"] == "" {
		t.Fatal("the table is not marked as blocked")
	}

	// A column added for other roles is the same: not even the shape leaks.
	hidden := app()
	hidden.ColumnsHidden = []string{"ssn"}
	cat.tables[1] = hidden
	withColumn := ordersRelation()
	withColumn.Columns = append(withColumn.Columns, &pglogrepl.RelationMessageColumn{Name: "ssn", DataType: 25})
	feed(t, d, withColumn, beginAt(3), insertOf("3", "x"), commitOf())
	if evs := received(sub); len(evs) != 0 {
		t.Fatalf("a hidden column still streamed: %#v", evs)
	}
}

// ENABLE ROW LEVEL SECURITY may reach the catalog with no Relation message
// after it, so the periodic re-check has to catch it on its own; and a table
// that is fixed streams again, with its shape announced first.
func TestThePeriodicRecheckCatchesRLS(t *testing.T) {
	cat := &fakeCatalog{tables: map[uint32]Table{1: app()}}
	d, sub := guardedDecoder(cat)
	defer sub.Close()
	feed(t, d, ordersRelation())
	received(sub)

	rls := app()
	rls.RLSEnabled = true
	cat.tables[1] = rls
	if err := d.recheckAll(); err != nil {
		t.Fatal(err)
	}
	feed(t, d, beginAt(1), insertOf("1", "x"), commitOf())
	if evs := received(sub); len(evs) != 0 {
		t.Fatalf("the re-check did not stop the table: %#v", evs)
	}

	cat.tables[1] = app()
	if err := d.recheckAll(); err != nil {
		t.Fatal(err)
	}
	feed(t, d, beginAt(2), insertOf("2", "y"), commitOf())
	evs := received(sub)
	if len(evs) == 0 {
		t.Fatal("a table that may stream again stayed blocked")
	}
	if _, ok := evs[0].(Schema); !ok {
		t.Fatalf("the shape was not announced before the first change: %#v", evs[0])
	}
	if changesIn(evs) != 1 {
		t.Fatalf("got %d changes, want 1", changesIn(evs))
	}
}

// The decoder re-checks on its own clock while streaming, not only when a
// test calls it.
func TestTheRecheckIntervalIsShort(t *testing.T) {
	if RecheckInterval <= 0 || RecheckInterval > time.Minute {
		t.Fatalf("RecheckInterval = %s; a table that gained RLS would stream for too long", RecheckInterval)
	}
}

// When the catalog cannot be asked, nothing is assumed: the check fails the
// decoder, which reconnects, rather than streaming a table unchecked.
func TestAnUnanswerableCheckSendsNothing(t *testing.T) {
	cat := &fakeCatalog{err: errors.New("connection reset")}
	d, sub := guardedDecoder(cat)
	defer sub.Close()
	if err := d.handleMessage(ordersRelation(), "0/10"); err == nil {
		t.Fatal("a failed check was not reported")
	}
	if err := d.recheckAll(); err == nil {
		t.Fatal("a failed periodic check was not reported")
	}
	if evs := received(sub); len(evs) != 0 {
		t.Fatalf("sent %#v without an answer", evs)
	}

	// And a decoder with no catalog at all streams nothing.
	none, sub2 := guardedDecoder(nil)
	none.catalog = nil
	defer sub2.Close()
	feed(t, none, ordersRelation(), beginAt(1), insertOf("1", "x"), commitOf())
	if evs := received(sub2); len(evs) != 0 {
		t.Fatalf("a decoder with no catalog sent %#v", evs)
	}
}
