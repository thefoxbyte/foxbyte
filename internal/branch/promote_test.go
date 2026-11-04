// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func entry(id int64, actor, kind, tag, obj, sql string) RequestEntry {
	return RequestEntry{ID: id, At: "2026-09-28T10:00:00Z", Actor: actor, ActorKind: kind,
		CommandTag: tag, Object: obj, Statement: sql}
}

// The snapshot a reviewer approves has to survive the round trip to the store and
// back, statement for statement.
func TestEntriesRoundTrip(t *testing.T) {
	in := []RequestEntry{
		entry(11, "ada@example.com", "human", "CREATE TABLE", "public.orders", "CREATE TABLE orders (id int)"),
		entry(12, "agent-alice", "agent", "ALTER TABLE", "public.orders", "ALTER TABLE orders ADD COLUMN total numeric"),
	}
	s, err := MarshalEntries(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnmarshalEntries(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("got %d entries, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("entry %d changed:\n got %+v\nwant %+v", i, out[i], in[i])
		}
	}
	if empty, err := UnmarshalEntries(""); err != nil || len(empty) != 0 {
		t.Errorf("an empty snapshot gave %v, %v", empty, err)
	}
}

// What a reviewer is shown: every statement, whose it was, and what it touches.
func TestFormatRequestShowsWhatWillBeApplied(t *testing.T) {
	c := auth.ChangeRequest{ID: 7, Source: "dev", Target: "main", CreatedBy: "ada@example.com",
		Created: "2026-09-28T10:00:00Z", Status: auth.RequestOpen, ForkAfterID: 10}
	entries := []RequestEntry{
		entry(11, "ada@example.com", "human", "CREATE TABLE", "public.orders", "CREATE TABLE orders (id int)"),
		entry(12, "agent-alice", "agent", "ALTER TABLE", "public.orders", "ALTER TABLE orders ADD COLUMN total numeric"),
	}
	entries[1].Risk = "type-change"
	out := FormatRequest(c, entries)
	for _, want := range []string{
		"#7", "dev → main", "ada@example.com", "agent-alice (agent)",
		"CREATE TABLE orders (id int)", "ALTER TABLE orders ADD COLUMN total numeric",
		"type-change", "entry 11", "entry 12", "share history up to entry 10",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the review output does not mention %q:\n%s", want, out)
		}
	}
}

// The one-line summary says enough to decide what to look at.
func TestRequestSummary(t *testing.T) {
	entries := []RequestEntry{entry(11, "ada@example.com", "human", "DROP TABLE", "public.old", "DROP TABLE old")}
	entries[0].Risk = "drop"
	snapshot, _ := MarshalEntries(entries)
	c := auth.ChangeRequest{ID: 3, Source: "dev", Target: "main", CreatedBy: "ada@example.com",
		Status: auth.RequestOpen, Entries: snapshot}
	out := RequestSummary(c)
	for _, want := range []string{"#3", "open", "dev → main", "1 statement(s)", "1 flagged", "ada@example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary does not mention %q: %s", want, out)
		}
	}
}

// riskyEntries is what a reviewer's attention should go to first.
func TestRiskyEntries(t *testing.T) {
	entries := []RequestEntry{
		entry(11, "a", "human", "CREATE TABLE", "public.t", "CREATE TABLE t (id int)"),
		entry(12, "a", "human", "DROP COLUMN", "public.t", "ALTER TABLE t DROP COLUMN x"),
	}
	entries[1].Risk = "drop-column"
	got := riskyEntries(entries)
	if len(got) != 1 || !strings.Contains(got[0], "entry 12") || !strings.Contains(got[0], "drop-column") {
		t.Errorf("riskyEntries = %v", got)
	}
}

// A role named for an email address has to be quoted, and a quote inside one
// doubled, or the script breaks (or worse).
func TestQuoteIdent(t *testing.T) {
	if got := quoteIdent("ada@example.com"); got != `"ada@example.com"` {
		t.Errorf("quoteIdent = %s", got)
	}
	if got := quoteIdent(`we"rd`); got != `"we""rd"` {
		t.Errorf("quoteIdent did not double the quote: %s", got)
	}
}

// Entries share a statement only when they hold the same text and were
// recorded in the same transaction; without a transaction nothing is merged.
func TestReplayOnce(t *testing.T) {
	run := "CREATE TABLE t (id int); CREATE VIEW v AS SELECT * FROM t"
	grant := "GRANT SELECT ON t TO r"
	es := []RequestEntry{
		entry(1, "ada", "human", "CREATE TABLE", "public.t", run),
		entry(2, "ada", "human", "CREATE VIEW", "public.v", run),
		entry(3, "ada", "human", "GRANT", "", grant),
		entry(4, "ada", "human", "GRANT", "", grant),              // the same text again, in another transaction
		entry(5, "ada", "human", "CREATE TABLE", "public.u", run), // no transaction recorded
	}
	ReplayOnce(es, map[int64]int64{1: 77, 2: 77, 3: 78, 4: 79})
	got := []int64{es[0].SameRun, es[1].SameRun, es[2].SameRun, es[3].SameRun, es[4].SameRun}
	if got[0] != 0 || got[1] != 1 || got[2] != 0 || got[3] != 0 || got[4] != 0 {
		t.Fatalf("same_run: %v, want [0 1 0 0 0]", got)
	}
	out := FormatRequest(auth.ChangeRequest{ID: 1, Source: "a", Target: "main"}, es)
	if strings.Count(out, "CREATE VIEW v AS") != 2 || !strings.Contains(out, "entry 2, by ada: made by the same run as entry 1, above") {
		t.Fatalf("the request does not say entry 2 runs with entry 1:\n%s", out)
	}
}
