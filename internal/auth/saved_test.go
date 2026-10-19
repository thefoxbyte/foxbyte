// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"strings"
	"testing"
)

// Search finds text anywhere in a statement, ignoring case, and treats LIKE's
// wildcards as the characters they are.
func TestHistorySearch(t *testing.T) {
	s := testStore(t)
	for _, q := range []string{"SELECT * FROM Orders", "select 100% AS pct", "SELECT a_b FROM t", "SELECT ab FROM t"} {
		record(t, s, entry("ada@x.com", "main", q))
	}
	bad := entry("ada@x.com", "main", "SELECT * FROM orderz")
	bad.OK, bad.Error = false, "no such table"
	record(t, s, bad)
	record(t, s, entry("bob@x.com", "main", "SELECT * FROM orders"))
	got := func(q HistoryQuery) []string {
		h, err := s.History("ada@x.com", q)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range h {
			out = append(out, e.SQL)
		}
		return out
	}
	if g := got(HistoryQuery{Search: "orders"}); len(g) != 1 || g[0] != "SELECT * FROM Orders" {
		t.Fatalf("case: %q", g)
	}
	if g := got(HistoryQuery{Search: "100%"}); len(g) != 1 {
		t.Fatalf("a literal %%: %q", g)
	}
	if g := got(HistoryQuery{Search: "a_b"}); len(g) != 1 || g[0] != "SELECT a_b FROM t" {
		t.Fatalf("_ matched any character: %q", g)
	}
	if g := got(HistoryQuery{Failed: true}); len(g) != 1 || g[0] != "SELECT * FROM orderz" {
		t.Fatalf("failed: %q", g)
	}
	if g := got(HistoryQuery{Search: "order", Failed: true}); len(g) != 1 {
		t.Fatalf("both: %q", g)
	}
	h, _ := s.History("ada@x.com", HistoryQuery{Limit: 1})
	if e, err := s.HistoryEntryByID("ada@x.com", h[0].ID); err != nil || e.SQL != h[0].SQL {
		t.Fatalf("by id: %+v %v", e, err)
	}
	if _, err := s.HistoryEntryByID("bob@x.com", h[0].ID); err == nil {
		t.Fatal("bob read ada's entry by its id")
	}
}

// Saved queries are each person's own, named uniquely, kept exactly, and go
// with the account.
func TestSavedQueries(t *testing.T) {
	s := testStore(t)
	u, _ := s.CreateUser("ada@x.com", "password1")
	q, err := s.SaveQuery("ada@x.com", " Big orders ", "SELECT * FROM orders WHERE total > 100")
	if err != nil || q.ID == 0 || q.Name != "Big orders" {
		t.Fatalf("%+v %v", q, err)
	}
	if _, err := s.SaveQuery("ada@x.com", "Big orders", "SELECT 2"); !errors.Is(err, ErrSavedNameTaken) {
		t.Fatalf("a second by the same name: %v", err)
	}
	if _, err := s.SaveQuery("bob@x.com", "Big orders", "SELECT 3"); err != nil {
		t.Fatalf("bob may use the same name: %v", err)
	}
	s.SaveQuery("ada@x.com", "all users", "SELECT * FROM users")
	list, _ := s.SavedQueries("ada@x.com", "")
	if len(list) != 2 || list[0].Name != "all users" || list[1].Name != "Big orders" {
		t.Fatalf("by name, ignoring case: %+v", list)
	}
	if l, _ := s.SavedQueries("ada@x.com", "TOTAL"); len(l) != 1 || l[0].Name != "Big orders" {
		t.Fatalf("search the SQL: %+v", l)
	}
	if l, _ := s.SavedQueries("ada@x.com", "users"); len(l) != 1 {
		t.Fatalf("search the name: %+v", l)
	}
	// Bob cannot see, change or delete Ada's.
	if l, _ := s.SavedQueries("bob@x.com", ""); len(l) != 1 || l[0].SQL != "SELECT 3" {
		t.Fatalf("bob's: %+v", l)
	}
	if _, err := s.UpdateSavedQuery("bob@x.com", q.ID, "mine now", ""); !errors.Is(err, ErrNoSavedQuery) {
		t.Fatalf("bob renamed ada's: %v", err)
	}
	if err := s.DeleteSavedQuery("bob@x.com", q.ID); !errors.Is(err, ErrNoSavedQuery) {
		t.Fatalf("bob deleted ada's: %v", err)
	}
	r, err := s.UpdateSavedQuery("ada@x.com", q.ID, "Orders over 100", "")
	if err != nil || r.Name != "Orders over 100" || r.SQL != q.SQL {
		t.Fatalf("rename: %+v %v", r, err)
	}
	if _, err := s.UpdateSavedQuery("ada@x.com", q.ID, "all users", ""); !errors.Is(err, ErrSavedNameTaken) {
		t.Fatalf("renamed onto another: %v", err)
	}
	if b, err := s.SavedQueryByName("ada@x.com", "Orders over 100"); err != nil || b.ID != q.ID {
		t.Fatalf("by name: %+v %v", b, err)
	}
	// Exactly or not at all.
	for _, c := range []struct{ name, sql string }{
		{"", "SELECT 1"}, {"x", "  "}, {strings.Repeat("n", 101), "SELECT 1"},
		{"long", "SELECT '" + strings.Repeat("x", maxHistorySQL) + "'"},
	} {
		if _, err := s.SaveQuery("ada@x.com", c.name, c.sql); err == nil {
			t.Errorf("saved %q / %d bytes", c.name, len(c.sql))
		}
	}
	if err := s.DeleteAccount(u.ID); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.SavedQueries("ada@x.com", ""); len(l) != 0 {
		t.Fatalf("a deleted account's saved queries stayed: %+v", l)
	}
	if n, _ := s.PurgeSavedQueries("bob@x.com"); n != 1 {
		t.Fatalf("purged %d", n)
	}
}

func TestSavedQueriesCap(t *testing.T) {
	s := testStore(t)
	for i := 0; i < maxSavedQueries; i++ {
		if _, err := s.SaveQuery("ada@x.com", "q"+itoa(i), "SELECT 1"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SaveQuery("ada@x.com", "one more", "SELECT 1"); err == nil || !strings.Contains(err.Error(), "delete one first") {
		t.Fatalf("past the cap: %v", err)
	}
}

func itoa(i int) string {
	b := []byte{}
	for {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
		if i == 0 {
			return string(b)
		}
	}
}
