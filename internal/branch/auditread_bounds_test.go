// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// oldReadAudit is ReadAudit before it stopped re-joining everything per day,
// kept to prove the new one returns the same answers.
func oldReadAudit(q AuditQuery) ([]AuditEntry, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	days := storedDays()
	var all []AuditRecord
	var out []AuditEntry
	for i := len(days) - 1; i >= 0 && len(out) < q.Limit; i-- {
		if !q.Since.IsZero() && days[i] < q.Since.UTC().Format("2006-01-02") {
			break
		}
		recs, err := readDay(days[i])
		if err != nil {
			return nil, err
		}
		all = append(recs, all...)
		out = joinAudit(all, q)
	}
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	attachTexts(out)
	return out, nil
}

// oldAuditRecordsBetween is AuditRecordsBetween before it stopped at until.
func oldAuditRecordsBetween(since, until time.Time) ([]AuditRecord, error) {
	var out []AuditRecord
	for _, day := range storedDays() {
		if day < since.UTC().AddDate(0, 0, -1).Format("2006-01-02") {
			continue
		}
		recs, err := readDay(day)
		if err != nil {
			return nil, fmt.Errorf("the records of %s cannot all be read (%v)", day, err)
		}
		for _, r := range recs {
			at, err := time.Parse(time.RFC3339Nano, r.Time)
			if err != nil || at.Before(since) || !at.Before(until) {
				continue
			}
			r.Text = ""
			out = append(out, r)
		}
	}
	return out, nil
}

func stmtLine(at, session, vxid, user, table string) string {
	return fmt.Sprintf(`{"timestamp":"%s UTC","user":"%s","dbname":"appdb","pid":7,"session_id":"%s","line_num":1,"ps":"INSERT","vxid":"%s","error_severity":"LOG","message":"AUDIT: OBJECT,1,1,WRITE,INSERT,TABLE,%s,<not logged>,<not logged>"}`,
		at, user, session, vxid, table)
}

func txnLine(at, session, vxid, outcome string) string {
	return fmt.Sprintf(`{"timestamp":"%s UTC","user":"alice@x.in","session_id":"%s","vxid":"4/0","error_severity":"LOG","message":"AUDIT: TXN,%s,%s,asserted,shop,\"o'brien, p\""}`,
		at, session, vxid, outcome)
}

func errorLine(at, session, vxid, state string) string {
	return fmt.Sprintf(`{"timestamp":"%s UTC","user":"alice@x.in","session_id":"%s","vxid":"%s","error_severity":"ERROR","state_code":"%s","message":"AUDIT: OUTCOME,ERROR,%s"}`,
		at, session, vxid, state, state)
}

// seedAuditFixture is a store with what makes the join and the day boundaries
// interesting: transactions spanning days, a statement filed after the
// transaction that closed it, one key finished twice, errors, and several
// logins and tables.
func seedAuditFixture(t *testing.T) {
	t.Helper()
	storeIn(t)
	settingsIn(t)
	// A long transaction: the statement on the 1st, its commit on the 4th.
	seed(t, "2026-11-01",
		stmtLine("2026-11-01 09:00:00.000", "s1", "1/1", "alice@x.in", "public.orders"),
		stmtLine("2026-11-01 09:00:01.000", "s2", "2/1", "bob", "public.users"),
		txnLine("2026-11-01 09:00:02.000", "s2", "2/1", "ROLLBACK"),
		errorLine("2026-11-01 09:00:03.000", "s2", "2/2", "23505"),
	)
	// A transaction filed a day before the statement it closes, as a late raw
	// file does; and the same key finished twice, where the last one wins.
	seed(t, "2026-11-02",
		txnLine("2026-11-02 23:59:58.000", "s3", "3/1", "COMMIT"),
		stmtLine("2026-11-02 12:00:00.000", "s4", "4/1", "alice@x.in", "public.orders"),
		txnLine("2026-11-02 12:00:01.000", "s4", "4/1", "ROLLBACK"),
		stmtLine("2026-11-02 12:00:02.000", "s5", "5/1", "bob", "public.users"),
	)
	seed(t, "2026-11-03",
		stmtLine("2026-11-02 23:59:59.000", "s3", "3/1", "alice@x.in", "public.orders"), // filed after its transaction
		stmtLine("2026-11-03 10:00:00.000", "s5", "5/2", "alice@x.in", "public.users"),
		errorLine("2026-11-03 10:00:01.000", "s5", "5/2", "42501"),
		txnLine("2026-11-03 10:00:02.000", "s4", "4/1", "COMMIT"), // the same key again
	)
	seed(t, "2026-11-04",
		txnLine("2026-11-04 08:00:00.000", "s1", "1/1", "COMMIT"), // closes the 1st's statement
		stmtLine("2026-11-04 08:00:01.000", "s6", "6/1", "alice@x.in", "public.orders"),
		txnLine("2026-11-04 08:00:02.000", "s6", "6/1", "COMMIT"),
		errorLine("2026-11-04 08:00:03.000", "s7", "7/1", "22P02"),
		stmtLine("2026-11-04 08:00:04.000", "s7", "7/2", "bob", "public.users"),
	)
}

// The new read against the old one, over filters and limits falling on and
// around every day boundary.
func TestReadAuditMatchesTheOldRead(t *testing.T) {
	seedAuditFixture(t)
	since := time.Date(2026, 11, 2, 12, 0, 1, 0, time.UTC)
	queries := []AuditQuery{
		{}, {Limit: 1}, {Limit: 2}, {Limit: 3}, {Limit: 4}, {Limit: 5}, {Limit: 6}, {Limit: 7}, {Limit: 8},
		{Limit: 9}, {Limit: 10}, {Limit: 1000},
		{Login: "alice@x.in"}, {Login: "alice@x.in", Limit: 2}, {Login: "alice@x.in", Limit: 3},
		{Login: "nobody"},
		{Table: "orders"}, {Table: "orders", Limit: 1}, {Table: "public.users", Limit: 2},
		{Branch: "main", Limit: 3}, {Branch: "other"},
		{Since: since}, {Since: since, Limit: 2}, {Since: since, Table: "users"},
		{Kinds: []string{"outcome"}}, {Kinds: []string{"outcome"}, Limit: 1},
		{Kinds: []string{"transaction"}, Limit: 3}, {Kinds: []string{"statement", "outcome"}, Limit: 5},
	}
	for _, q := range queries {
		old, oldErr := oldReadAudit(q)
		got, err := ReadAudit(q)
		if err != nil || oldErr != nil {
			t.Fatalf("%+v: %v / %v", q, err, oldErr)
		}
		if !reflect.DeepEqual(got, old) {
			t.Errorf("%+v:\n got %+v\nwant %+v", q, got, old)
		}
	}
	// The cases the fixture exists for, stated, so they cannot pass vacuously.
	all, err := ReadAudit(AuditQuery{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	find := func(session, vxid string) AuditEntry {
		for _, e := range all {
			if e.Session == session && e.VXID == vxid && e.Kind == "statement" {
				return e
			}
		}
		t.Fatalf("no statement %s %s", session, vxid)
		return AuditEntry{}
	}
	if e := find("s1", "1/1"); e.TxnOutcome != "COMMIT" {
		t.Errorf("a transaction closed three days later: %+v", e)
	}
	if e := find("s3", "3/1"); e.TxnOutcome != "COMMIT" {
		t.Errorf("a transaction filed before its statement: %+v", e)
	}
	if e := find("s4", "4/1"); e.TxnOutcome != "COMMIT" {
		t.Errorf("the last record of a key did not win: %+v", e)
	}
	if e := find("s5", "5/2"); e.Error != "42501" {
		t.Errorf("an error on a statement: %+v", e)
	}
}

// The records and the counts against the old read, including a period whose
// days are not all before its end.
func TestEvidenceReadMatchesTheOldRead(t *testing.T) {
	seedAuditFixture(t)
	periods := [][2]time.Time{
		{time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 11, 2, 12, 0, 1, 0, time.UTC), time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 3, 10, 0, 1, 0, time.UTC)},
		{time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 9, 0, 2, 0, time.UTC)},
		{time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)},
	}
	for _, p := range periods {
		old, err := oldAuditRecordsBetween(p[0], p[1])
		if err != nil {
			t.Fatal(err)
		}
		got, err := AuditRecordsBetween(p[0], p[1])
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, old) {
			t.Errorf("%v: records differ:\n got %+v\nwant %+v", p, got, old)
		}
		want := NewAuditActivity()
		for _, r := range old {
			TallyAuditActivity(&want, r)
		}
		a, none, err := AuditActivityBetween(p[0], p[1], false)
		if err != nil || none != nil {
			t.Fatalf("%v: records came back unasked: %d, %v", p, len(none), err)
		}
		if !reflect.DeepEqual(a, want) {
			t.Errorf("%v: counts differ:\n got %+v\nwant %+v", p, a, want)
		}
		_, kept, err := AuditActivityBetween(p[0], p[1], true)
		if err != nil || len(kept) != len(old) {
			t.Fatalf("%v: asked for the records: %d of %d, %v", p, len(kept), len(old), err)
		}
	}
}

// countScans wraps scanDay, counting the days opened and the records handed
// over, which is the work a read does.
func countScans(t *testing.T) (days, records *int) {
	t.Helper()
	old := scanDay
	days, records = new(int), new(int)
	scanDay = func(day string, fn func(AuditRecord)) error {
		*days++
		return old(day, func(r AuditRecord) { *records++; fn(r) })
	}
	t.Cleanup(func() { scanDay = old })
	return days, records
}

// seedDays is a store of n days, each of perDay statements, with one
// statement a filter can find on the very first day only.
func seedDays(t *testing.T, n, perDay int) {
	t.Helper()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for d := 0; d < n; d++ {
		day := start.AddDate(0, 0, d)
		lines := make([]string, 0, perDay)
		for i := 0; i < perDay; i++ {
			at := day.Add(time.Duration(i) * time.Second).Format("2006-01-02 15:04:05.000")
			table := "public.common"
			if d == 0 && i == 0 {
				table = "public.rare"
			}
			lines = append(lines, stmtLine(at, "s", fmt.Sprintf("%d/%d", d, i), "alice@x.in", table))
		}
		seed(t, day.Format("2006-01-02"), lines...)
	}
}

// Quadratic growth shows up as records handled per record stored rising with
// the number of days. A rare match walks every day, the worst case, and costs
// two passes over them at most; the old read handled each day once per day
// that followed it, and the fixture asserts that really was growth.
func TestReadAuditWorkIsLinearInTheDaysRead(t *testing.T) {
	storeIn(t)
	settingsIn(t)
	const n, perDay = 40, 10
	seedDays(t, n, perDay)
	days, records := countScans(t)
	got, err := ReadAudit(AuditQuery{Table: "rare", Limit: 5})
	if err != nil || len(got) != 1 {
		t.Fatalf("%d, %v", len(got), err)
	}
	if want := 2 * n * perDay; *records > want {
		t.Errorf("handled %d records of %d stored, want at most %d", *records, n*perDay, want)
	}
	if *days > 2*n {
		t.Errorf("opened %d day files of %d", *days, n)
	}
	// What the old read handled, by construction: every day re-joined once per
	// day walked after it.
	if old := perDay * n * (n + 1) / 2; old <= *records {
		t.Errorf("the fixture does not separate the two: old %d, new %d", old, *records)
	}

	// Most of the time nothing goes back further than it must.
	*days, *records = 0, 0
	if _, err := ReadAudit(AuditQuery{Limit: 3}); err != nil {
		t.Fatal(err)
	}
	if *days > 2 {
		t.Errorf("a limit met by the newest day opened %d day files", *days)
	}
}

// Held memory is bounded by Limit, even for matches that fill a whole day.
func TestReadAuditHoldsAtMostLimit(t *testing.T) {
	storeIn(t)
	settingsIn(t)
	seedDays(t, 3, 500)
	got, err := ReadAudit(AuditQuery{Limit: 7})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 || got[0].VXID != "2/499" || got[6].VXID != "2/493" {
		t.Fatalf("the newest seven: %d, %+v", len(got), got)
	}
}

// Stops at until, plus the days a record can be collected late. Days after
// that are not opened at all, but a period's record collected late is found
// however late, as long as the day it arrives in still holds such a record.
func TestEvidenceReadStopsAfterThePeriod(t *testing.T) {
	storeIn(t)
	settingsIn(t)
	seedDays(t, 40, 3)
	since := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)
	days, _ := countScans(t)
	recs, err := AuditRecordsBetween(since, until)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 6 {
		t.Fatalf("records: %d", len(recs))
	}
	// from the day before since, through until and its carry-over, and the one
	// day that shows the period is behind us.
	if want := 2 + 2 + auditCollectedLateDays + 1; *days > want {
		t.Errorf("opened %d day files, want at most %d", *days, want)
	}
}

func TestEvidenceReadFindsRecordsCollectedLate(t *testing.T) {
	storeIn(t)
	settingsIn(t)
	// Nothing was collected for three weeks after the period's end, and then
	// the backlog arrived.
	seed(t, "2026-03-01", stmtLine("2026-03-01 10:00:00.000", "s", "1/1", "alice@x.in", "public.t"))
	seed(t, "2026-03-22", stmtLine("2026-03-01 23:59:59.000", "s", "1/2", "alice@x.in", "public.t"),
		stmtLine("2026-03-21 12:00:00.000", "s", "1/3", "alice@x.in", "public.t"))
	since := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	got, err := AuditRecordsBetween(since, until)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := oldAuditRecordsBetween(since, until)
	if len(got) != 2 || !reflect.DeepEqual(got, old) {
		t.Fatalf("late records:\n got %+v\nwant %+v", got, old)
	}
}

// BenchmarkReadAudit compares the old read with the new on a rare match that
// walks every day: the old grows with the square of the days, the new with
// the days.
func BenchmarkReadAudit(b *testing.B) {
	for _, n := range []int{10, 40, 160} {
		dir := b.TempDir()
		old := AuditStoreDir
		AuditStoreDir = func() string { return dir }
		defer func() { AuditStoreDir = old }()
		seedBenchDays(b, n, 200)
		q := AuditQuery{Table: "rare", Limit: 5}
		b.Run(fmt.Sprintf("new/days=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := ReadAudit(q); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("old/days=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := oldReadAudit(q); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func seedBenchDays(b *testing.B, n, perDay int) {
	b.Helper()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for d := 0; d < n; d++ {
		day := start.AddDate(0, 0, d)
		recs := make([]AuditRecord, 0, perDay)
		for i := 0; i < perDay; i++ {
			r, ok := recordFromLine("main", []byte(stmtLine(day.Add(time.Duration(i)*time.Second).Format("2006-01-02 15:04:05.000"),
				"s", fmt.Sprintf("%d/%d", d, i), "alice@x.in", "public.common")))
			if !ok {
				b.Fatal("not a record")
			}
			if d == 0 && i == 0 {
				r.Object = "public.rare"
			}
			recs = append(recs, r)
		}
		if _, err := appendDay(day.Format("2006-01-02"), recs); err != nil {
			b.Fatal(err)
		}
	}
}
