// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestEditDistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{
		{"customers", "customers", 0},
		{"custmers", "customers", 1},  // a letter left out
		{"cusotmers", "customers", 1}, // two swapped
		{"customerz", "customers", 1},
		{"cstmrs", "customers", 3},
		{"", "abc", 3},
	} {
		if d := editDistance(c.a, c.b); d != c.d {
			t.Errorf("%s → %s: %d, want %d", c.a, c.b, d, c.d)
		}
	}
}

// One clear nearest name, near enough, or nothing: a confident wrong guess is
// worse than none.
func TestClosest(t *testing.T) {
	names := []string{"customers", "orders", "order_items", "Products", "events"}
	for _, c := range []struct {
		wrong, want string
		ok          bool
	}{
		{"custmers", "customers", true},
		{"cusotmers", "customers", true},
		{"ordrs", "orders", true},
		{"products", "Products", true}, // only the case differs
		{"evnt", "", false},            // two edits on four letters: too far
		{"xyz", "", false},
		{"orders", "", false}, // exists as typed: something else is wrong
	} {
		got, ok := closest(c.wrong, names)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: %q %v, want %q %v", c.wrong, got, ok, c.want, c.ok)
		}
	}
	// Two equally near is no suggestion.
	if got, ok := closest("cat", []string{"cut", "car"}); ok {
		t.Errorf("a tie suggested %q", got)
	}
}

func TestQuoteIdentIfNeeded(t *testing.T) {
	for in, want := range map[string]string{
		"customers": "customers", "order_items": "order_items",
		"Products": `"Products"`, "user": `"user"`, "my table": `"my table"`, `a"b`: `"a""b"`,
	} {
		if got := quoteIdentIfNeeded(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// What Postgres's messages say, read without a database: the missing name,
// and its own guess for a column when it has exactly one.
func TestSuggestReadsPostgres(t *testing.T) {
	if m := reMissingRelation.FindStringSubmatch(`relation "public.custmers" does not exist`); m == nil || m[1] != "public.custmers" {
		t.Fatalf("%v", m)
	}
	for msg, want := range map[string]string{
		`column "nmae" does not exist`:    "nmae",
		`column c.nmae does not exist`:    "c.nmae",
		`column "Big Col" does not exist`: "Big Col",
	} {
		m := reMissingColumn.FindStringSubmatch(msg)
		if m == nil || m[1]+m[2] != want {
			t.Errorf("%s: %v", msg, m)
		}
	}
	if h := rePgColumnHint.FindStringSubmatch(`Perhaps you meant to reference the column "c.name".`); h == nil || h[1] != "name" {
		t.Fatalf("%v", h)
	}
	if h := rePgColumnHint.FindStringSubmatch(`Perhaps you meant to reference the column "a.x" or the column "b.x".`); h != nil {
		t.Fatalf("two guesses read as one: %v", h)
	}
	// Without a connection, or for another error, nothing is asked.
	if s := suggestFor(t.Context(), nil, "", &pgconn.PgError{Code: "42P01", Message: `relation "x" does not exist`}); s != nil {
		t.Fatalf("%+v", s)
	}
}

func TestNamedIn(t *testing.T) {
	sql := "select c.nmae from customers c join orders o on o.cid = c.id"
	for name, want := range map[string]bool{"customers": true, "orders": true, "order": false, "custom": false, "cid": true} {
		if namedIn(sql, name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}

// fox sql reads a suggestion out of the result, for a statement and for a
// failed script.
func TestSQLOutputCarriesTheSuggestion(t *testing.T) {
	sg := &Suggestion{Kind: "table", Wrong: "custmers", Right: "customers", Insert: "customers"}
	if o := sqlOutput(map[string]any{"error": "relation \"custmers\" does not exist", "suggestion": sg}); o.Suggestion != sg {
		t.Fatalf("%+v", o)
	}
	o := sqlOutput(map[string]any{"error": "x", "suggestion": sg, "results": []map[string]any{{"error": "x", "suggestion": sg}}})
	if o.Suggestion != sg || o.Results[0].Suggestion != sg {
		t.Fatalf("%+v", o)
	}
}
