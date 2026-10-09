// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"testing"
	"time"
)

// The readings store. Small, but two things here are worth asserting: that a
// range query returns oldest-first (every question asked of it is a subtraction
// between the ends, and a caller should not have to reverse the list), and that
// the trim actually bounds the table — it grows on a timer whether anyone reads
// it or not, in the file that also holds everyone's sessions.
func TestActivityStore(t *testing.T) {
	s := testStore(t)
	now := time.Now().Unix()

	for i, a := range []ActivitySample{
		{Branch: "app", At: now - 7200, WarmSince: now - 7300, Transactions: 100, RowsReturned: 1000},
		{Branch: "app", At: now - 3600, WarmSince: now - 7300, Transactions: 180, RowsReturned: 1800},
		{Branch: "app", At: now, WarmSince: now - 7300, Transactions: 260, RowsReturned: 2600, Subscribers: 2, Events: 42, WALHeld: 1 << 20},
		{Branch: "other", At: now, Transactions: 5},
	} {
		if err := s.RecordActivity(a); err != nil {
			t.Fatalf("reading %d: %v", i, err)
		}
	}

	t.Run("a branch sees only its own readings, oldest first", func(t *testing.T) {
		got, err := s.ActivitySince("app", now-10000, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 {
			t.Fatalf("got %d readings, want 3", len(got))
		}
		if got[0].At >= got[2].At {
			t.Errorf("not oldest-first: %d then %d", got[0].At, got[2].At)
		}
		if got[0].Transactions != 100 || got[2].Transactions != 260 {
			t.Errorf("ends are %d and %d, want 100 and 260", got[0].Transactions, got[2].Transactions)
		}
		// Every field survives the round trip, including the ones only the
		// report reads.
		last := got[2]
		if last.Subscribers != 2 || last.Events != 42 || last.WALHeld != 1<<20 {
			t.Errorf("fields lost in the round trip: %+v", last)
		}
	})

	t.Run("the window excludes what is older", func(t *testing.T) {
		got, err := s.ActivitySince("app", now-1800, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d readings in the last 30 minutes, want 1", len(got))
		}
	})

	t.Run("a reading needs a branch", func(t *testing.T) {
		if err := s.RecordActivity(ActivitySample{At: now}); err == nil {
			t.Error("recorded a reading with no branch")
		}
	})

	t.Run("at defaults to now", func(t *testing.T) {
		if err := s.RecordActivity(ActivitySample{Branch: "dated"}); err != nil {
			t.Fatal(err)
		}
		got, err := s.ActivitySince("dated", now-10, 0)
		if err != nil || len(got) != 1 {
			t.Fatalf("got %d readings (%v), want 1 stamped with now", len(got), err)
		}
	})

	t.Run("trimming bounds the table", func(t *testing.T) {
		n, err := s.TrimActivity(now - 1800)
		if err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Errorf("trimmed %d, want the 2 readings older than 30 minutes", n)
		}
		got, _ := s.ActivitySince("app", 0, 0)
		if len(got) != 1 {
			t.Errorf("%d readings left for app, want 1", len(got))
		}
		// And it did not reach another branch's current reading.
		if other, _ := s.ActivitySince("other", 0, 0); len(other) != 1 {
			t.Errorf("another branch's reading was trimmed: %d left", len(other))
		}
	})

	t.Run("a deleted branch's readings can be forgotten", func(t *testing.T) {
		if err := s.ForgetActivity("app"); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.ActivitySince("app", 0, 0); len(got) != 0 {
			t.Errorf("%d readings left after forgetting the branch", len(got))
		}
		if other, _ := s.ActivitySince("other", 0, 0); len(other) != 1 {
			t.Errorf("forgetting one branch took another's: %d left", len(other))
		}
	})

	// An empty result is an empty slice, not nil: this is served as JSON, and
	// `"samples": null` is a different answer from `"samples": []`.
	t.Run("no readings is an empty list", func(t *testing.T) {
		got, err := s.ActivitySince("never-existed", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Error("nil rather than an empty slice")
		}
	})
}
