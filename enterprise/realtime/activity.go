//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"fmt"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// What a warm branch has cost, and whether anything used it.
//
// This follows from a decision taken deliberately. A branch nobody queries is
// suspended by the reaper, and that is what makes an idle branch nearly free.
// A branch with a subscriber attached must stay up, or the feed would miss what
// happened while it was away — so realtime chose the warm model, and a cold
// start was rejected because it defeats the point of realtime.
//
// That was the right trade and it is not a free one. The bill is: a container
// running, and write-ahead log held for a bookmark. Neither is visible from
// anywhere else in the product, so somebody paying for it has no way to tell a
// branch earning its keep from one that has been warm for a fortnight for the
// sake of a forgotten tab.
//
// So: how long it has been warm, what it did in that time, and what the feed
// is holding. Measured, not estimated.

// Report is the answer for one branch.
type Report struct {
	Branch string `json:"branch"`
	Warm   bool   `json:"warm"`
	// WarmSince and WarmFor describe the current warm period. A suspended
	// branch reports neither, which is the cheap and ordinary state.
	WarmSince string `json:"warm_since,omitempty"`
	WarmFor   string `json:"warm_for,omitempty"`
	warmFor   time.Duration

	// Now is what the engine reports this instant.
	Subscribers int   `json:"subscribers"`
	EventsNow   int64 `json:"events_delivered"`
	PeakSubs    int   `json:"peak_subscribers"`

	// Measured is the subtraction between the oldest and newest readings held
	// for this branch, and is empty until there are two of them. This is the
	// part that answers "how much did it do, and over what period" — a single
	// reading of a cumulative counter cannot.
	Measured *Measured `json:"measured,omitempty"`

	// Slots is what the feed's bookmarks are holding, and how close each is to
	// the budget past which Postgres drops it rather than keep more.
	Slots []branch.SlotLag `json:"slots,omitempty"`

	// Tables is how many of this branch's tables are streaming.
	Tables int `json:"tables_streaming"`

	// Note is said when a number needs a caveat rather than a footnote.
	Notes []string `json:"notes,omitempty"`
}

// Measured is work observed over a period.
type Measured struct {
	From         string  `json:"from"`
	To           string  `json:"to"`
	Over         string  `json:"over"`
	Transactions int64   `json:"transactions"`
	RowsReturned int64   `json:"rows_returned"`
	PerDay       float64 `json:"transactions_per_day"`
	Samples      int     `json:"samples"`
}

// Activity builds the report for one branch from the readings kept for it.
//
// window is how far back to look. Readings are taken on a timer, so a window
// shorter than the interval produces a report with no measured section rather
// than a wrong one — which is the intended behaviour: saying "not yet known" is
// better than dividing by a period nobody observed.
func Activity(store *auth.Store, branchName string, window time.Duration, hub *Hub) (Report, error) {
	r := Report{Branch: branchName}

	since, err := branch.WarmSince(branchName)
	if err != nil {
		return r, err
	}
	if !since.IsZero() {
		r.Warm = true
		r.WarmSince = since.Format(time.RFC3339)
		r.warmFor = time.Since(since).Truncate(time.Second)
		r.WarmFor = r.warmFor.String()
	}

	if hub != nil {
		r.Subscribers, r.EventsNow, r.PeakSubs = hub.Stats()
	}

	if lags, err := branch.ReadSlotLag(branchName); err == nil {
		r.Slots = lags
	} else if r.Warm {
		// Only worth saying when the branch is up: a suspended branch cannot
		// answer, and that is not a fault.
		r.Notes = append(r.Notes, "could not read the feed's slots: "+err.Error())
	}

	if tables, err := branch.PublishedTables(branchName); err == nil {
		r.Tables = len(tables)
	}

	if store != nil {
		samples, err := store.ActivitySince(branchName, time.Now().Add(-window).Unix(), 0)
		if err != nil {
			return r, err
		}
		r.Measured, r.Notes = measure(samples, r.Notes)
	}
	return r, nil
}

// measure subtracts the ends of a series.
//
// The awkward cases are the point of this function, and each one is answered
// with a note rather than a number that would be wrong:
//
//   - fewer than two readings: nothing to subtract yet.
//   - the statistics were reset between the ends: the counters restarted, so
//     the difference would be a negative or a nonsense.
//   - the branch was suspended and resumed in between: Postgres keeps its
//     statistics across a clean restart, so the subtraction still holds — but
//     the period includes time the branch was not warm, so a per-day rate
//     computed from it would understate the rate while it was running. Said,
//     not silently averaged.
func measure(samples []auth.ActivitySample, notes []string) (*Measured, []string) {
	if len(samples) < 2 {
		return nil, append(notes,
			"not enough readings yet to say how much work happened — they are taken on a timer")
	}

	// Measure over the longest run of readings at the end that nothing
	// restarted, rather than over the whole window.
	//
	// Postgres discards its statistics when a database comes back from an
	// unclean shutdown, and a branch is stopped and started routinely — the
	// reaper suspends it, a failover moves which container serves it, an
	// upgrade restarts it. The counters then start again from zero, and
	// subtracting across that point gives a negative or, worse, a plausible
	// number that is wrong.
	//
	// Refusing the whole window was the first version of this, and it was too
	// blunt: one restart three hours ago threw away the two readings from five
	// minutes ago that were perfectly subtractable. So the run is trimmed to
	// where the counters last became continuous, and the shortening is said.
	start := len(samples) - 1
	for i := len(samples) - 1; i > 0; i-- {
		prev, cur := samples[i-1], samples[i]
		if cur.StatsReset != prev.StatsReset || cur.Transactions < prev.Transactions {
			break
		}
		start = i - 1
	}
	if trimmed := start; trimmed > 0 {
		notes = append(notes,
			"the database's statistics restarted during this window, so the figures below cover only the period since then")
		samples = samples[trimmed:]
	}
	if len(samples) < 2 {
		return nil, append(notes,
			"the database's statistics restarted too recently to measure a period — there is only one reading since")
	}
	first, last := samples[0], samples[len(samples)-1]

	over := time.Duration(last.At-first.At) * time.Second
	m := &Measured{
		From:         time.Unix(first.At, 0).UTC().Format(time.RFC3339),
		To:           time.Unix(last.At, 0).UTC().Format(time.RFC3339),
		Over:         over.Truncate(time.Second).String(),
		Transactions: last.Transactions - first.Transactions,
		RowsReturned: last.RowsReturned - first.RowsReturned,
		Samples:      len(samples),
	}
	if over > 0 {
		m.PerDay = float64(m.Transactions) / over.Hours() * 24
	}

	// Was it warm throughout? A changed warm_since means it was suspended and
	// resumed, and a zero one means a reading was taken while it was down.
	restarted := false
	for _, s := range samples {
		if s.WarmSince == 0 || s.WarmSince != first.WarmSince {
			restarted = true
			break
		}
	}
	if restarted {
		notes = append(notes,
			"the branch was suspended and resumed during this period, so the rate above is averaged over time it was not running")
	}
	return m, notes
}

// Idle reports whether a branch has been warm with nothing to show for it,
// which is the shape of the bill nobody wants: a container running because a
// subscriber is attached, and no work going through it.
//
// A judgement, not a measurement, so it is reported rather than acted on. The
// engine does not suspend a branch somebody is subscribed to — that is the
// promise realtime makes — and a cap or a teardown is a person's decision.
func (r Report) Idle(threshold time.Duration) bool {
	return r.Warm && r.warmFor >= threshold && r.Measured != nil && r.Measured.Transactions == 0
}

// Cost is the sentence a person reads.
func (r Report) Cost() string {
	if !r.Warm {
		return "Not running. A suspended branch costs its disk and nothing else."
	}
	held := int64(0)
	for _, s := range r.Slots {
		held += s.HeldBytes
	}
	switch {
	case r.Subscribers > 0:
		return fmt.Sprintf("Warm for %s with %d subscriber(s) attached, holding %s of write-ahead log. "+
			"A subscribed branch is never suspended — that is what makes the feed continuous.",
			r.WarmFor, r.Subscribers, humanBytes(held))
	case held > 0:
		return fmt.Sprintf("Warm for %s with nobody attached, and %s of write-ahead log still held for a "+
			"bookmark somebody may come back to. `realtime slots` shows which.", r.WarmFor, humanBytes(held))
	default:
		return fmt.Sprintf("Warm for %s. Nothing is subscribed and no log is being held, so the reaper "+
			"will suspend it once it goes idle.", r.WarmFor)
	}
}
