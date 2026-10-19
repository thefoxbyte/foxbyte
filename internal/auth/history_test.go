// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func entry(actor, branch, sql string) HistoryEntry {
	return HistoryEntry{Actor: actor, Branch: branch, Source: "console", SQL: sql, OK: true, Rows: 1, DurationMS: 3}
}

func record(t *testing.T, s *Store, e HistoryEntry) {
	t.Helper()
	if kept, err := s.RecordQuery(e); err != nil || !kept {
		t.Fatalf("not kept (%v): %+v", err, e)
	}
}

// Each person reads their own history, newest first, and nothing else.
func TestHistoryIsYourOwn(t *testing.T) {
	s := testStore(t)
	record(t, s, entry("ada@x.com", "main", "SELECT 1"))
	record(t, s, entry("bob@x.com", "main", "SELECT 'bob'"))
	record(t, s, entry("ada@x.com", "dev", "SELECT 2"))
	h, err := s.History("ada@x.com", HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 || h[0].SQL != "SELECT 2" || h[1].SQL != "SELECT 1" {
		t.Fatalf("%+v", h)
	}
	for _, e := range h {
		if e.Actor != "ada@x.com" {
			t.Fatalf("ada read someone else's entry: %+v", e)
		}
	}
	if h, _ := s.History("ada@x.com", HistoryQuery{Branch: "dev"}); len(h) != 1 || h[0].Branch != "dev" {
		t.Fatalf("by branch: %+v", h)
	}
	if h, _ := s.History("ada@x.com", HistoryQuery{Limit: 1}); len(h) != 1 {
		t.Fatalf("limit: %+v", h)
	}
	first, _ := s.History("ada@x.com", HistoryQuery{Limit: 1})
	if h, _ := s.History("ada@x.com", HistoryQuery{Before: first[0].ID}); len(h) != 1 || h[0].SQL != "SELECT 1" {
		t.Fatalf("the next page: %+v", h)
	}
	if n, _ := s.HistoryCount("ada@x.com"); n != 2 {
		t.Fatalf("count %d", n)
	}
	// Bob cannot delete Ada's entry, and is not told whether it exists.
	if ok, err := s.DeleteHistoryEntry("bob@x.com", h[0].ID); ok || err != nil {
		t.Fatalf("bob deleted ada's entry (%v, %v)", ok, err)
	}
	if ok, _ := s.DeleteHistoryEntry("ada@x.com", first[0].ID); !ok {
		t.Fatal("ada could not delete her own entry")
	}
}

// An entry holds the statement and what happened, and has no place for a
// result: a row of somebody's data is not history.
func TestHistoryKeepsNoResults(t *testing.T) {
	cols := map[string]bool{}
	for _, f := range strings.Split(`id actor branch source kind sql truncated at duration_ms rows ok error`, " ") {
		cols[f] = true
	}
	s := testStore(t)
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info('query_history')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		rows.Scan(&c)
		if !cols[c] {
			t.Errorf("query_history has a column %q: a new one must be argued for here, not added", c)
		}
		delete(cols, c)
	}
	if len(cols) != 0 {
		t.Errorf("missing columns %v", cols)
	}
	b, _ := json.Marshal(HistoryEntry{})
	for _, k := range []string{"result", "columns", "values"} {
		if strings.Contains(string(b), `"`+k) {
			t.Errorf("an entry carries %q", k)
		}
	}
}

// Off for the install, or off for one person, records nothing; what was kept
// stays until it is deleted or expires.
func TestHistoryCanBeTurnedOff(t *testing.T) {
	s := testStore(t)
	record(t, s, entry("ada@x.com", "main", "SELECT 1"))
	if err := s.SetHistoryOptOut("ada@x.com", true); err != nil {
		t.Fatal(err)
	}
	if kept, _ := s.RecordQuery(entry("ada@x.com", "main", "SELECT 2")); kept {
		t.Fatal("kept after ada turned hers off")
	}
	record(t, s, entry("bob@x.com", "main", "SELECT 3")) // bob's is still on
	if n, _ := s.HistoryCount("ada@x.com"); n != 1 {
		t.Fatalf("turning it off deleted or added: %d", n)
	}
	s.SetHistoryOptOut("ada@x.com", false)
	record(t, s, entry("ada@x.com", "main", "SELECT 4"))

	if err := s.SetHistoryEnabled(false); err != nil {
		t.Fatal(err)
	}
	if set, _ := s.HistorySettings(); set.Enabled {
		t.Fatal("still enabled")
	}
	if kept, _ := s.RecordQuery(entry("bob@x.com", "main", "SELECT 5")); kept {
		t.Fatal("kept with the install's history off")
	}
	s.SetHistoryEnabled(true)
	record(t, s, entry("bob@x.com", "main", "SELECT 6"))
}

// Older than the retention is never shown, and is deleted; shortening the
// retention deletes at once.
func TestHistoryRetention(t *testing.T) {
	s := testStore(t)
	if set, _ := s.HistorySettings(); set.RetentionDays != 90 || !set.Enabled {
		t.Fatalf("defaults %+v", set)
	}
	old := entry("ada@x.com", "main", "SELECT 'old'")
	old.At = time.Now().Add(-100 * 24 * time.Hour).UnixMilli()
	mid := entry("ada@x.com", "main", "SELECT 'mid'")
	mid.At = time.Now().Add(-20 * 24 * time.Hour).UnixMilli()
	record(t, s, old)
	record(t, s, mid)
	record(t, s, entry("ada@x.com", "main", "SELECT 'new'"))
	if h, _ := s.History("ada@x.com", HistoryQuery{}); len(h) != 2 {
		t.Fatalf("an entry past 90 days is shown: %+v", h)
	}
	// Recording runs the trim itself (once a minute), so the old entry is
	// already gone from the table, not only hidden.
	var stored int
	s.db.QueryRow(`SELECT count(*) FROM query_history`).Scan(&stored)
	if stored != 2 {
		t.Fatalf("%d entries stored, want 2: the one past 90 days should be deleted", stored)
	}
	if n, _ := s.TrimHistory(); n != 0 {
		t.Fatalf("a second trim found %d more", n)
	}
	if err := s.SetHistoryRetention(7); err != nil {
		t.Fatal(err)
	}
	var left int
	s.db.QueryRow(`SELECT count(*) FROM query_history`).Scan(&left)
	if left != 1 {
		t.Fatalf("shortening to 7 days left %d entries, want 1", left)
	}
	for _, bad := range []int{0, -1, 3651} {
		if err := s.SetHistoryRetention(bad); err == nil {
			t.Errorf("retention %d accepted", bad)
		}
	}
}

// One person's history is capped, the oldest going first.
func TestHistoryCapPerPerson(t *testing.T) {
	s := testStore(t)
	for i := 0; i < maxHistoryPerActor+5; i++ {
		e := entry("ada@x.com", "main", "SELECT "+string(rune('a'+i%26)))
		if _, err := s.RecordQuery(e); err != nil {
			t.Fatal(err)
		}
	}
	record(t, s, entry("bob@x.com", "main", "SELECT 'bob'"))
	if n, _ := s.HistoryCount("ada@x.com"); n != maxHistoryPerActor {
		t.Fatalf("ada has %d entries, cap %d", n, maxHistoryPerActor)
	}
	if n, _ := s.HistoryCount("bob@x.com"); n != 1 {
		t.Fatalf("ada's cap reached bob: %d", n)
	}
}

// A long statement is kept cut, on a character boundary, and says so.
func TestHistoryCutsLongSQL(t *testing.T) {
	s := testStore(t)
	long := "SELECT '" + strings.Repeat("é", maxHistorySQL) + "'"
	record(t, s, entry("ada@x.com", "main", long))
	h, _ := s.History("ada@x.com", HistoryQuery{})
	if !h[0].Truncated || len(h[0].SQL) > maxHistorySQL || !strings.HasPrefix(long, h[0].SQL) {
		t.Fatalf("truncated=%v len=%d", h[0].Truncated, len(h[0].SQL))
	}
	if !strings.HasSuffix(h[0].SQL, "é") {
		t.Fatal("cut inside a character")
	}
	if _, err := s.RecordQuery(entry("ada@x.com", "main", "  ")); err == nil {
		t.Fatal("an empty statement was kept")
	}
}

// Purging a person, everyone, or an account deleted takes their history.
func TestHistoryPurges(t *testing.T) {
	s := testStore(t)
	u, _ := s.CreateUser("ada@x.com", "password1")
	record(t, s, entry("ada@x.com", "main", "SELECT 1"))
	record(t, s, entry("ada@x.com", "main", "SELECT 2"))
	record(t, s, entry("bob@x.com", "main", "SELECT 3"))
	record(t, s, entry("cli:root", "main", "SELECT 4"))
	if a, _ := s.HistoryActors(); a["ada@x.com"] != 2 || a["bob@x.com"] != 1 || a["cli:root"] != 1 {
		t.Fatalf("%v", a)
	}
	if n, _ := s.PurgeHistory("bob@x.com"); n != 1 {
		t.Fatalf("purged %d", n)
	}
	s.SetHistoryOptOut("ada@x.com", true)
	if err := s.DeleteAccount(u.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.HistoryCount("ada@x.com"); n != 0 {
		t.Fatalf("a deleted account's history stayed: %d", n)
	}
	if s.HistoryOptedOut("ada@x.com") {
		t.Fatal("a deleted account's choice stayed with the address")
	}
	if n, _ := s.PurgeAllHistory(); n != 1 {
		t.Fatalf("purged all %d, want the CLI's one", n)
	}
}

// History is not carried to a second node with the accounts.
func TestHistoryIsNotShared(t *testing.T) {
	s := testStore(t)
	record(t, s, entry("ada@x.com", "main", "SELECT 'secret'"))
	s.SetHistoryOptOut("bob@x.com", true)
	doc, _, err := s.SharedState()
	if err != nil {
		t.Fatal(err)
	}
	for _, t2 := range []string{"query_history", "history_optout", "history_settings", "secret"} {
		if strings.Contains(string(doc), t2) {
			t.Errorf("the shared document carries %s", t2)
		}
	}
}
