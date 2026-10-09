//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Subtracting two readings, and the cases where subtracting would lie.
//
// This is the whole value of the meter and the whole risk of it: a cumulative
// counter read twice gives work done, unless something restarted the counter in
// between — and then the same subtraction gives a negative, or a number that
// looks plausible and is not. Every one of those cases is answered with a note
// instead of a figure, and each is asserted here, because a billing number that
// is quietly wrong is worse than one that is missing.

func sample(at int64, warm int64, xacts int64, opts ...func(*auth.ActivitySample)) auth.ActivitySample {
	s := auth.ActivitySample{Branch: "b", At: at, WarmSince: warm, Transactions: xacts, RowsReturned: xacts * 10}
	for _, o := range opts {
		o(&s)
	}
	return s
}

func TestMeasure(t *testing.T) {
	const hour = 3600

	t.Run("two readings an hour apart", func(t *testing.T) {
		m, notes := measure([]auth.ActivitySample{
			sample(1000, 900, 100),
			sample(1000+hour, 900, 340),
		}, nil)
		if m == nil {
			t.Fatalf("no measurement; notes: %v", notes)
		}
		if m.Transactions != 240 {
			t.Errorf("transactions = %d, want 240", m.Transactions)
		}
		if m.RowsReturned != 2400 {
			t.Errorf("rows = %d, want 2400", m.RowsReturned)
		}
		// 240 in an hour is 5760 a day.
		if m.PerDay < 5759 || m.PerDay > 5761 {
			t.Errorf("per day = %f, want about 5760", m.PerDay)
		}
		if m.Samples != 2 {
			t.Errorf("samples = %d, want 2", m.Samples)
		}
		if len(notes) != 0 {
			t.Errorf("unexpected notes: %v", notes)
		}
	})

	t.Run("one reading cannot be subtracted from itself", func(t *testing.T) {
		m, notes := measure([]auth.ActivitySample{sample(1000, 900, 100)}, nil)
		if m != nil {
			t.Fatalf("measured from a single reading: %+v", m)
		}
		if !hasNote(notes, "not enough readings") {
			t.Errorf("notes do not say why: %v", notes)
		}
	})

	t.Run("no readings at all", func(t *testing.T) {
		if m, _ := measure(nil, nil); m != nil {
			t.Fatalf("measured from nothing: %+v", m)
		}
	})

	// The dangerous one. Postgres discards its statistics when a database comes
	// back from an unclean shutdown, and the counter starts again from zero —
	// so subtracting across that point gives a negative or, worse, a plausible
	// number that is wrong. With only one reading after the restart there is
	// nothing to measure, and that is said rather than computed.
	t.Run("a statistics reset with nothing after it is not subtracted", func(t *testing.T) {
		m, notes := measure([]auth.ActivitySample{
			sample(1000, 900, 5000, func(s *auth.ActivitySample) { s.StatsReset = 500 }),
			sample(1000+hour, 900, 20, func(s *auth.ActivitySample) { s.StatsReset = 1200 }),
		}, nil)
		if m != nil {
			t.Fatalf("subtracted across a statistics reset: %+v", m)
		}
		if !hasNote(notes, "restarted too recently") {
			t.Errorf("notes do not say why: %v", notes)
		}
	})

	// And the same shape without the reset timestamp changing — a counter that
	// went backwards is proof enough on its own.
	t.Run("a counter that went backwards is not subtracted", func(t *testing.T) {
		m, notes := measure([]auth.ActivitySample{
			sample(1000, 900, 5000),
			sample(1000+hour, 900, 20),
		}, nil)
		if m != nil {
			t.Fatalf("reported a negative period: %+v", m)
		}
		if !hasNote(notes, "restarted too recently") {
			t.Errorf("notes do not say why: %v", notes)
		}
	})

	// The reason the run is trimmed rather than the window refused. One restart
	// three hours ago must not throw away two readings from five minutes ago
	// that are perfectly subtractable — the first version of this did exactly
	// that, and the integration suite caught it: a branch that had been
	// restarted earlier in the run could never report a period again.
	t.Run("a restart earlier in the window does not discard what came after", func(t *testing.T) {
		m, notes := measure([]auth.ActivitySample{
			sample(1000, 900, 90000),      // before the restart
			sample(1000+hour, 900, 95000), // still before
			sample(1000+2*hour, 900, 40),  // counters restarted here
			sample(1000+3*hour, 900, 300), // and ran on
			sample(1000+4*hour, 900, 700),
		}, nil)
		if m == nil {
			t.Fatalf("no measurement; notes: %v", notes)
		}
		// Measured over the two hours since the restart, not the four.
		if m.Transactions != 660 {
			t.Errorf("transactions = %d, want 660 (700-40)", m.Transactions)
		}
		if m.Over != "2h0m0s" {
			t.Errorf("over = %q, want 2h0m0s", m.Over)
		}
		if m.Samples != 3 {
			t.Errorf("samples = %d, want the 3 since the restart", m.Samples)
		}
		// And the shortening is said, or the figures silently describe a
		// different period from the one that was asked for.
		if !hasNote(notes, "statistics restarted during this window") {
			t.Errorf("the window was shortened without saying so: %v", notes)
		}
	})

	// A branch suspended and resumed mid-period: the subtraction still holds,
	// because Postgres keeps its statistics across a clean restart — but the
	// period includes time the branch was not running, so the rate understates
	// what it does while warm. Reported with the caveat rather than silently.
	t.Run("a suspension mid-period is measured and flagged", func(t *testing.T) {
		m, notes := measure([]auth.ActivitySample{
			sample(1000, 900, 100),
			sample(1000+hour, 900, 200),
			sample(1000+2*hour, 1000+2*hour, 260), // resumed: a new warm_since
		}, nil)
		if m == nil {
			t.Fatalf("no measurement; notes: %v", notes)
		}
		if m.Transactions != 160 {
			t.Errorf("transactions = %d, want 160", m.Transactions)
		}
		if !hasNote(notes, "suspended and resumed") {
			t.Errorf("the rate is averaged over downtime and does not say so: %v", notes)
		}
	})

	t.Run("a reading taken while it was down is flagged too", func(t *testing.T) {
		_, notes := measure([]auth.ActivitySample{
			sample(1000, 900, 100),
			sample(1000+hour, 0, 100),
			sample(1000+2*hour, 900, 120),
		}, nil)
		if !hasNote(notes, "suspended and resumed") {
			t.Errorf("notes: %v", notes)
		}
	})

	// Two readings at the same instant: the period is zero, so a rate would be
	// a division by zero. The work is still real and is reported.
	t.Run("a zero-length period reports work without a rate", func(t *testing.T) {
		m, _ := measure([]auth.ActivitySample{sample(1000, 900, 100), sample(1000, 900, 150)}, nil)
		if m == nil {
			t.Fatal("no measurement")
		}
		if m.Transactions != 50 {
			t.Errorf("transactions = %d, want 50", m.Transactions)
		}
		if m.PerDay != 0 {
			t.Errorf("per day = %f, want 0 rather than an infinity", m.PerDay)
		}
	})
}

// slots is one held bookmark of the given size.
func slots(held int64) []branch.SlotLag {
	return []branch.SlotLag{{Slot: "fox_rt_main_stream", Active: true, HeldBytes: held}}
}

func hasNote(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}

// Idle is the judgement the report offers and never acts on.
func TestIdle(t *testing.T) {
	warm := func(d time.Duration, xacts int64) Report {
		r := Report{Warm: true, warmFor: d}
		if xacts >= 0 {
			r.Measured = &Measured{Transactions: xacts}
		}
		return r
	}
	cases := []struct {
		name string
		r    Report
		want bool
	}{
		{"warm for hours with nothing to show", warm(4*time.Hour, 0), true},
		{"warm for hours and used", warm(4*time.Hour, 500), false},
		{"warm briefly with nothing yet", warm(10*time.Minute, 0), false},
		{"warm with nothing measured yet", Report{Warm: true, warmFor: 4 * time.Hour}, false},
		{"not warm at all", Report{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.Idle(2 * time.Hour); got != c.want {
				t.Errorf("Idle = %v, want %v", got, c.want)
			}
		})
	}
}

// The sentence a person reads has to distinguish the three states that cost
// different amounts, because that is the only reason it exists.
func TestCost(t *testing.T) {
	cold := Report{}
	if !strings.Contains(cold.Cost(), "Not running") {
		t.Errorf("a suspended branch: %q", cold.Cost())
	}

	subscribed := Report{Warm: true, WarmFor: "3h0m0s", Subscribers: 2, Slots: slots(5 << 20)}
	if got := subscribed.Cost(); !strings.Contains(got, "2 subscriber") || !strings.Contains(got, "5 MB") {
		t.Errorf("subscribed: %q", got)
	}

	// Nobody attached but log still held: the case worth noticing, because it
	// is a bill with no one reading the thing being paid for.
	held := Report{Warm: true, WarmFor: "3h0m0s", Slots: slots(900 << 20)}
	if got := held.Cost(); !strings.Contains(got, "nobody attached") || !strings.Contains(got, "900 MB") {
		t.Errorf("held: %q", got)
	}

	plain := Report{Warm: true, WarmFor: "1m0s"}
	if got := plain.Cost(); !strings.Contains(got, "reaper") {
		t.Errorf("warm and unused: %q", got)
	}
}

// The subscriber cap: refused with the number, because "try again later"
// without one tells a developer nothing about whether they have a bug.
func TestSubscriberCap(t *testing.T) {
	t.Setenv("FOX_REALTIME_MAX_SUBSCRIBERS", "2")
	h := NewHub()
	a, err := h.TrySubscribe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.TrySubscribe(); err != nil {
		t.Fatal(err)
	}
	_, err = h.TrySubscribe()
	if err == nil {
		t.Fatal("a third subscriber was accepted at a cap of two")
	}
	if !strings.Contains(err.Error(), "2") || !strings.Contains(err.Error(), "MAX_SUBSCRIBERS") {
		t.Errorf("the refusal does not name the count or the way to raise it: %v", err)
	}
	// A subscriber leaving frees its place: the cap is concurrent streams, not
	// a quota on how many a branch may ever serve.
	a.Close()
	if _, err := h.TrySubscribe(); err != nil {
		t.Errorf("a place did not free up after a subscriber left: %v", err)
	}
	// And the counters the meter reads.
	subs, _, peak := h.Stats()
	if subs != 2 || peak != 2 {
		t.Errorf("Stats = (%d subs, peak %d), want (2, 2)", subs, peak)
	}
}

func TestDeliveredCount(t *testing.T) {
	h := NewHub()
	s := h.Subscribe()
	defer s.Close()
	for i := 0; i < 3; i++ {
		h.Publish(map[string]string{"type": "change"})
	}
	if _, delivered, _ := h.Stats(); delivered != 3 {
		t.Errorf("delivered = %d, want 3", delivered)
	}
}
