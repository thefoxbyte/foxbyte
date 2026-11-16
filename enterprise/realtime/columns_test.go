//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pglogrepl"
)

// Choosing which columns stream: the plan Enable runs, and the decoder's cut.

func ordersColumns(major int) TableColumns {
	return TableColumns{Names: []string{"id", "note", "email"}, PrimaryKey: []string{"id"}, ServerMajor: major}
}

func mustPlan(t *testing.T, tb Table, cols TableColumns, pii []PIIColumn, req Request) enablePlan {
	t.Helper()
	p, err := planEnable(tb, cols, pii, req)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// On a major with column lists, the publication carries exactly the chosen
// columns, and the key stays in even when it was not named.
func TestThePublicationCarriesTheColumnListAndTheKey(t *testing.T) {
	p := mustPlan(t, app(), ordersColumns(18), nil, Request{Columns: []string{"note"}})
	want := `ALTER PUBLICATION "fox_rt_pub_delete_insert_update" ADD TABLE "public"."orders" ("id", "note")`
	if !strings.Contains(p.SQL, want) {
		t.Fatalf("the publication statement is not narrowed to the key and the chosen column:\n%s", p.SQL)
	}
	if p.Filter != FilterPublication {
		t.Errorf("filter = %q, want publication", p.Filter)
	}
	if strings.Join(p.Columns, ",") != "id,note" || strings.Join(p.KeyColumnsAdded, ",") != "id" {
		t.Errorf("columns = %v, key added = %v", p.Columns, p.KeyColumnsAdded)
	}
	// The record the decoder enforces says the same.
	if !strings.Contains(p.SQL, `ARRAY['id', 'note']::text[]`) {
		t.Errorf("the column choice is not recorded:\n%s", p.SQL)
	}
	// A table with a key does not pay for FULL, so its old image is the key.
	if strings.Contains(p.SQL, "REPLICA IDENTITY FULL") || p.OldValues || p.Identity != "primary key" {
		t.Errorf("a keyed table was given FULL: identity %q, old values %v", p.Identity, p.OldValues)
	}
	// One transaction, with the table moved out of every feed publication
	// before it goes into this one.
	if !strings.HasPrefix(p.SQL, "BEGIN;") || !strings.HasSuffix(p.SQL, "COMMIT;") ||
		strings.Index(p.SQL, "DROP TABLE") > strings.Index(p.SQL, "ADD TABLE") {
		t.Errorf("not one transaction that drops before it adds:\n%s", p.SQL)
	}
}

// Inserts only: nothing is located by the key, so it is not added.
func TestAnInsertOnlyFeedDoesNotAddTheKey(t *testing.T) {
	p := mustPlan(t, app(), ordersColumns(18), nil, Request{Events: []string{"insert"}, Columns: []string{"note"}})
	if strings.Join(p.Columns, ",") != "note" || len(p.KeyColumnsAdded) != 0 {
		t.Errorf("columns = %v, key added = %v", p.Columns, p.KeyColumnsAdded)
	}
}

// A major without column lists gets no list in the statement (it would not
// parse) and the decoder does the filtering on its own.
func TestAnOldMajorFallsBackToTheDecoder(t *testing.T) {
	for _, major := range []int{14, 0} {
		p := mustPlan(t, app(), ordersColumns(major), nil, Request{Columns: []string{"note"}})
		if !strings.Contains(p.SQL, `ADD TABLE "public"."orders";`) {
			t.Errorf("PostgreSQL %d was sent a column list:\n%s", major, p.SQL)
		}
		if p.Filter != FilterDecoder {
			t.Errorf("PostgreSQL %d: filter = %q, want decoder", major, p.Filter)
		}
		if !strings.Contains(p.SQL, `ARRAY['id', 'note']::text[]`) {
			t.Errorf("PostgreSQL %d: the decoder has nothing to enforce:\n%s", major, p.SQL)
		}
	}
}

// Old values are asked for by name. Under FULL a publication that carries
// updates cannot leave columns out without breaking the application's UPDATEs,
// so the decoder filters instead.
func TestOldValuesTakeFullAndTheDecoderFilters(t *testing.T) {
	p := mustPlan(t, app(), ordersColumns(18), nil, Request{Columns: []string{"note"}, OldValues: true})
	if !strings.Contains(p.SQL, `ALTER TABLE "public"."orders" REPLICA IDENTITY FULL`) || !p.OldValues {
		t.Fatalf("old values were asked for and FULL was not set:\n%s", p.SQL)
	}
	if strings.Contains(p.SQL, `"orders" ("id"`) || p.Filter != FilterDecoder {
		t.Errorf("a FULL table publishing updates was given a column list (filter %q):\n%s", p.Filter, p.SQL)
	}

	// --replica-identity=full sets FULL even when the table already has a key.
	// That is the flag's name, and it is how a subscriber is given the row as
	// it was. A keyed table left at its default identity made the flag a no-op.
	q := mustPlan(t, app(), ordersColumns(18), nil, Request{FullIdentity: true})
	if !strings.Contains(q.SQL, `ALTER TABLE "public"."orders" REPLICA IDENTITY FULL`) || !q.OldValues {
		t.Errorf("--replica-identity=full did not set FULL on a keyed table:\n%s", q.SQL)
	}
}

// A table with nothing to name its rows by keeps FULL, and the result says so.
func TestAKeylessTableSaysItStreamsUnderFull(t *testing.T) {
	keyless := app()
	keyless.HasPrimaryKey = false
	cols := ordersColumns(18)
	cols.PrimaryKey = nil
	p := mustPlan(t, keyless, cols, nil, Request{FullIdentity: true})
	if p.Identity != "full" || !p.OldValues {
		t.Fatalf("identity %q, old values %v", p.Identity, p.OldValues)
	}
	if !strings.Contains(strings.Join(p.Notes, " "), "no primary key") {
		t.Errorf("the result does not say FULL was kept for a table without a key: %v", p.Notes)
	}
}

func TestAnUnknownColumnIsRefused(t *testing.T) {
	_, err := planEnable(app(), ordersColumns(18), nil, Request{Columns: []string{"nope"}})
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v", err)
	}
}

// Confirmed personal data is refused by default, by name, with both ways
// forward; leaving it out or opting in each lets the table stream.
func TestPersonalDataIsRefusedUnlessLeftOutOrAllowed(t *testing.T) {
	pii := []PIIColumn{{Name: "email", Category: "email", Mask: "hash"}}

	_, err := planEnable(app(), ordersColumns(18), pii, Request{})
	if err == nil {
		t.Fatal("a table with confirmed personal data was enabled with every column")
	}
	for _, want := range []string{"email", "--columns", "--allow-pii", "masked"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	left := mustPlan(t, app(), ordersColumns(18), pii, Request{Columns: []string{"note"}})
	if len(left.PIIAllowed) != 0 {
		t.Errorf("a column left out was recorded as allowed: %v", left.PIIAllowed)
	}

	in := mustPlan(t, app(), ordersColumns(18), pii, Request{AllowPII: true})
	if strings.Join(in.PIIAllowed, ",") != "email" || !strings.Contains(in.SQL, `ARRAY['email']::text[]`) {
		t.Errorf("the opt-in was not recorded: %v\n%s", in.PIIAllowed, in.SQL)
	}
	if d := AuditDetail(in.Result); !strings.Contains(d, "personal data allowed: email") {
		t.Errorf("the security-log line does not carry the opt-in: %q", d)
	}

	// A key column cannot be left out, and the refusal says so.
	_, err = planEnable(app(), ordersColumns(18), []PIIColumn{{Name: "id"}}, Request{Columns: []string{"note"}})
	if err == nil || !strings.Contains(err.Error(), "key column") {
		t.Errorf("a personal-data key was not explained: %v", err)
	}
}

// A column db_client cannot read is no reason to refuse a table it is left
// out of.
func TestAHiddenColumnLeftOutDoesNotBlock(t *testing.T) {
	tb := app()
	tb.ColumnsHidden = []string{"email"}
	if streamBlock(tb) == "" {
		t.Fatal("a hidden column that streams did not block")
	}
	tb.StreamColumns = []string{"id", "note"}
	if r := streamBlock(tb); r != "" {
		t.Errorf("a hidden column left out still blocks: %s", r)
	}
	if v := Assess(tb, nil, false); v.State != Ready {
		t.Errorf("verdict = %s, want ready", v.State)
	}
}

// fullOrders is orders under REPLICA IDENTITY FULL, with a third column, so
// old tuples carry the whole row.
func fullOrders() *pglogrepl.RelationMessage {
	return &pglogrepl.RelationMessage{
		RelationID: 1, Namespace: "public", RelationName: "orders", ReplicaIdentity: 'f',
		Columns: []*pglogrepl.RelationMessageColumn{
			{Name: "id", DataType: 20, Flags: 1},
			{Name: "note", DataType: 25, Flags: 1},
			{Name: "email", DataType: 25, Flags: 1},
		},
	}
}

func row(vals ...string) *pglogrepl.TupleData {
	t := &pglogrepl.TupleData{}
	for _, v := range vals {
		t.Columns = append(t.Columns, &pglogrepl.TupleDataColumn{DataType: KindText, Data: []byte(v)})
	}
	return t
}

// The decoder drops a column that is not allowed from everything it sends:
// the shape, the new row, the old row, the identity and the change list. This
// is the path taken when the publication could not filter.
func TestTheDecoderDropsDisallowedColumnsFromNewAndOldRows(t *testing.T) {
	narrow := app()
	narrow.StreamColumns = []string{"id", "note"}
	cat := &fakeCatalog{tables: map[uint32]Table{1: narrow}}
	d, sub := guardedDecoder(cat)
	defer sub.Close()

	feed(t, d, fullOrders(), beginAt(1),
		&pglogrepl.InsertMessage{RelationID: 1, Tuple: row("1", "a", "x@example.com")},
		&pglogrepl.UpdateMessage{RelationID: 1, OldTupleType: 'O',
			OldTuple: row("1", "a", "x@example.com"), NewTuple: row("1", "b", "y@example.com")},
		&pglogrepl.DeleteMessage{RelationID: 1, OldTupleType: 'O', OldTuple: row("1", "b", "y@example.com")},
		commitOf())

	evs := received(sub)
	if changesIn(evs) != 3 {
		t.Fatalf("got %d changes, want 3: %#v", changesIn(evs), evs)
	}
	for _, ev := range evs {
		b, _ := json.Marshal(ev)
		if strings.Contains(string(b), "email") || strings.Contains(string(b), "example.com") {
			t.Errorf("a disallowed column reached a subscriber: %s", b)
		}
	}
	var update Change
	for _, ev := range evs {
		if c, ok := ev.(Change); ok && c.Action == "update" {
			update = c
		}
	}
	if update.Old["note"] == nil || *update.Old["note"] != "a" || update.New["note"] == nil {
		t.Errorf("the allowed columns did not survive the cut: %#v", update)
	}
}

// After an upgrade a table with no recorded choice streams every column, as
// it always did.
func TestAnExistingTableKeepsStreamingEveryColumn(t *testing.T) {
	cat := &fakeCatalog{tables: map[uint32]Table{1: app()}}
	d, sub := guardedDecoder(cat)
	defer sub.Close()
	feed(t, d, fullOrders(), beginAt(1),
		&pglogrepl.InsertMessage{RelationID: 1, Tuple: row("1", "a", "x@example.com")}, commitOf())
	var got Change
	for _, ev := range received(sub) {
		if c, ok := ev.(Change); ok {
			got = c
		}
	}
	if got.New["email"] == nil || *got.New["email"] != "x@example.com" {
		t.Fatalf("an existing table lost a column after the upgrade: %#v", got)
	}

	// No record at all reads as every column for every table.
	stream, err := decodeStreamColumns(nil)
	if err != nil || stream["public.orders"] != nil {
		t.Errorf("an empty record = %v, %v", stream, err)
	}
	// And a record written by enable without --columns is NULL, which is the
	// same answer.
	p := mustPlan(t, app(), ordersColumns(18), nil, Request{})
	if !strings.Contains(p.SQL, `ADD TABLE "public"."orders";`) || p.Filter != FilterNone {
		t.Errorf("enable without --columns narrowed the table:\n%s", p.SQL)
	}
	stream, err = decodeStreamColumns([]string{`{"schema":"public","table":"orders","columns":null}`})
	if err != nil || stream["public.orders"] != nil {
		t.Errorf("a NULL choice = %v, %v", stream, err)
	}
}

// Narrowing a table that is already streaming announces its new shape before
// the next change, so a subscriber is not left expecting a column it will no
// longer receive.
func TestNarrowingAStreamingTableReannouncesItsShape(t *testing.T) {
	cat := &fakeCatalog{tables: map[uint32]Table{1: app()}}
	d, sub := guardedDecoder(cat)
	defer sub.Close()
	feed(t, d, fullOrders())
	received(sub)

	narrow := app()
	narrow.StreamColumns = []string{"id"}
	cat.tables[1] = narrow
	if err := d.recheckAll(); err != nil {
		t.Fatal(err)
	}
	evs := received(sub)
	if len(evs) != 1 {
		t.Fatalf("got %#v, want one schema event", evs)
	}
	s, ok := evs[0].(Schema)
	if !ok || len(s.Columns) != 1 || s.Columns[0].Name != "id" {
		t.Errorf("the new shape is %#v", evs[0])
	}
}

// The personal data a streaming table sends, for the warning.
func TestStreamedPII(t *testing.T) {
	pii := []PIIColumn{{Name: "email"}, {Name: "phone"}}
	if got := piiNames(streamedPII(pii, nil)); strings.Join(got, ",") != "email,phone" {
		t.Errorf("every column = %v", got)
	}
	if got := piiNames(streamedPII(pii, []string{"id", "phone"})); strings.Join(got, ",") != "phone" {
		t.Errorf("narrowed = %v", got)
	}
	v := Verdict{Table: app(), StreamingPII: []string{"email"}}
	if w := v.PIIWarning(); !strings.Contains(w, "email") || !strings.Contains(w, "--columns") {
		t.Errorf("warning = %q", w)
	}
}
