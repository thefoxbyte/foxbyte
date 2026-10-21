//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"testing"

	"github.com/jackc/pglogrepl"
)

// What a subscriber's ?since= is answered with.
//
// Every case here was previously one case — "stream from here" — and two of
// them were silent faults: a position the feed had read past came back as a
// live stream with a hole in it, and a position ahead of the branch was
// reported to Postgres as flushed, which killed the branch's feed outright.
func TestJudgeResume(t *testing.T) {
	const (
		old    = pglogrepl.LSN(1000)
		mark   = pglogrepl.LSN(2000)
		latest = pglogrepl.LSN(3000)
	)

	t.Run("no position asked for is still from here", func(t *testing.T) {
		// The common case, and it must not have changed: no query, no refusal.
		for _, w := range []Window{{}, {Live: true, Floor: latest}, {HaveSlot: true, Confirmed: latest}} {
			if got := JudgeResume(0, w); got != ResumeLive {
				t.Errorf("window %+v gave %v, want ResumeLive", w, got)
			}
		}
	})

	t.Run("a position ahead of the branch is refused, never acknowledged", func(t *testing.T) {
		// The one that poisons the slot. It is not always a client bug: every
		// branch has its own log, so a mark from another branch is ahead of a
		// young one by construction, and a restore moves a branch's log back
		// under a client still holding a mark from before it.
		got := JudgeResume(latest+1, Window{HaveSlot: true, Confirmed: old, WALEnd: latest})
		if got != ResumeAhead {
			t.Fatalf("got %v, want ResumeAhead", got)
		}
		// The log end decides it wherever it is known, including alongside a
		// live hub that would otherwise have accepted the position. (The route
		// does not read the log end when a hub is already running, because
		// nothing is acknowledged on that path -- see resumeFor.)
		if got := JudgeResume(latest+1, Window{Live: true, Floor: old, WALEnd: latest}); got != ResumeAhead {
			t.Errorf("with a live hub, got %v, want ResumeAhead", got)
		}
	})

	t.Run("a position the slot has been read past cannot be replayed", func(t *testing.T) {
		// Postgres does not refuse this: asked to start before a slot's
		// confirmed position it simply starts at the confirmed one, and says
		// nothing. That silence was the gap.
		got := JudgeResume(old, Window{HaveSlot: true, Confirmed: mark, WALEnd: latest})
		if got != ResumeExpired {
			t.Errorf("got %v, want ResumeExpired", got)
		}
	})

	t.Run("a position still within the slot is replayed from", func(t *testing.T) {
		// What the feature is for, and it has to keep working: a client's mark
		// is routinely ahead of the slot, since the slot is only acknowledged
		// every ten seconds.
		for _, since := range []pglogrepl.LSN{mark, mark + 1, latest} {
			got := JudgeResume(since, Window{HaveSlot: true, Confirmed: mark, WALEnd: latest})
			if got != ResumeFrom {
				t.Errorf("since=%s gave %v, want ResumeFrom", since, got)
			}
		}
	})

	t.Run("no slot at all means nothing to replay from", func(t *testing.T) {
		// A first subscriber that passes a position: there is no slot, so the
		// decoder would create one starting now and everything up to then is
		// gone. Told to refetch rather than quietly started at the present.
		got := JudgeResume(mark, Window{WALEnd: latest})
		if got != ResumeExpired {
			t.Errorf("got %v, want ResumeExpired", got)
		}
	})

	t.Run("a stream in progress can only honour a position nothing has passed", func(t *testing.T) {
		// This is G1 itself. A fan-out cannot replay: what it published went to
		// whoever was attached at the time.
		if got := JudgeResume(old, Window{Live: true, Floor: mark, WALEnd: latest}); got != ResumeExpired {
			t.Errorf("behind the floor: got %v, want ResumeExpired", got)
		}
		if got := JudgeResume(mark, Window{Live: true, Floor: mark, WALEnd: latest}); got != ResumeLive {
			t.Errorf("exactly at the floor: got %v, want ResumeLive", got)
		}
		if got := JudgeResume(latest, Window{Live: true, Floor: mark, WALEnd: latest}); got != ResumeLive {
			t.Errorf("ahead of the floor: got %v, want ResumeLive", got)
		}
	})

	t.Run("a hub that cannot say where it began answers with a refetch", func(t *testing.T) {
		// One needless refetch is the price; attaching the subscriber to a
		// stream that may have started after the position it asked for is the
		// bug.
		if got := JudgeResume(mark, Window{Live: true, Floor: 0, WALEnd: latest}); got != ResumeExpired {
			t.Errorf("got %v, want ResumeExpired", got)
		}
	})

	t.Run("an unknown log end does not make a position ahead", func(t *testing.T) {
		// WALEnd zero means it could not be read, not that the log is empty,
		// and a check that cannot be made must not become a refusal.
		if got := JudgeResume(mark, Window{HaveSlot: true, Confirmed: old}); got != ResumeFrom {
			t.Errorf("got %v, want ResumeFrom", got)
		}
	})
}
