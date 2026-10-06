// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"github.com/thefoxbyte/foxbyte/internal/edition"
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

// A request with no statements is refused rather than producing an empty
// transaction that reports success.
//
// Enterprise only since promotion was gated: the licence is checked before the
// request is looked at, which is the right order — "you cannot do this at all"
// comes before "your request was empty" — and in a Standard build the feature
// can never be entitled, so there is nothing here to test. The gating itself is
// asserted in edition_test.go.
func TestApplyRequestRefusesNothing(t *testing.T) {
	if !edition.Enterprise {
		t.Skip("promotion cannot be entitled in a Standard build")
	}
	entitle(t, edition.Promotion)
	if _, err := ApplyRequest(1, "main", "someone@example.com", nil); err != ErrNothingToPromote {
		t.Errorf("applying an empty request gave %v, want ErrNothingToPromote", err)
	}
}

// Names are checked before anything reaches a container.
func TestBuildRequestChecksNames(t *testing.T) {
	if _, _, err := BuildRequest("dev", "dev", nil); err == nil {
		t.Error("a branch was allowed to be its own source and target")
	}
	if _, _, err := BuildRequest("../etc", "main", nil); err == nil {
		t.Error("a source that is not a branch name was accepted")
	}
	if _, _, err := BuildRequest("dev", "../etc", nil); err == nil {
		t.Error("a target that is not a branch name was accepted")
	}
}

// What a branch has already had applied elsewhere must not be offered again, and
// must not make its next round look like a conflict.
func TestAlreadyPromoted(t *testing.T) {
	snapshot, err := MarshalEntries([]RequestEntry{entry(11, "a", "human", "CREATE TABLE", "public.t", "CREATE TABLE t (id int)")})
	if err != nil {
		t.Fatal(err)
	}
	history := []auth.ChangeRequest{
		{ID: 3, Source: "dev", Target: "main", Status: auth.RequestApproved, Applied: 1, Entries: snapshot},
		{ID: 4, Source: "dev", Target: "main", Status: auth.RequestRejected, Applied: 0, Entries: snapshot},
		{ID: 5, Source: "other", Target: "main", Status: auth.RequestApproved, Applied: 1, Entries: snapshot},
		{ID: 6, Source: "dev", Target: "staging", Status: auth.RequestApproved, Applied: 1, Entries: snapshot},
	}
	ids, sessions := alreadyPromoted("dev", "main", history)
	if !ids[11] {
		t.Error("an entry applied by an earlier request is not remembered")
	}
	if !sessions["request-3"] {
		t.Error("the session the statements were applied under is not remembered")
	}
	// A rejected request applied nothing; another source's and another target's
	// requests say nothing about this pair.
	for _, no := range []string{"request-4", "request-5", "request-6"} {
		if sessions[no] {
			t.Errorf("%s should not count for dev → main", no)
		}
	}
	if len(sessions) != 1 {
		t.Errorf("sessions = %v, want only request-3", sessions)
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
