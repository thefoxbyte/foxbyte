//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import "github.com/jackc/pglogrepl"

// What a subscriber's ?since= may be answered with.
//
// Until this existed the answer was always "stream from here", whatever the
// client passed, and two faults came out of that — both of them silent, which
// is the fault this design says it will not have.
//
// A client that reconnected with a position the feed had moved past joined the
// stream in progress and received everything from that moment on. No gap was
// reported, because nothing compared the position with what the feed could
// still produce: the changes in between had been handed to whoever was
// subscribed at the time and were simply not there any more. A dashboard that
// dropped for a minute while a worker kept reading came back missing a minute
// of rows and had no way to know.
//
// A client that passed a position *ahead* of the branch was worse. The decoder
// reported it to Postgres as flushed, so the slot's confirmed position jumped
// to a place the WAL had not reached yet, and from then on the branch's feed
// delivered nothing at all — to anybody, across restarts, with `fox realtime
// slots` still calling the slot idle and healthy. One request did that.
//
// So the position is judged before the stream opens, against what the feed can
// actually replay.
//
// ResumeVerdict rather than Verdict: readiness.go already has one of those, for
// whether a table can be streamed at all.
type ResumeVerdict int

const (
	// ResumeFrom replays from the position: it is still within reach.
	ResumeFrom ResumeVerdict = iota
	// ResumeLive joins the stream in progress, which is what no ?since= has
	// always meant and what a position nothing has passed still means.
	ResumeLive
	// ResumeAhead is a position this branch has not reached. Refused, rather
	// than handed to the decoder.
	ResumeAhead
	// ResumeExpired is a position the feed can no longer replay from. The
	// subscriber is told to refetch instead of being quietly moved to the
	// present.
	ResumeExpired
)

// Window is what a ?since= is judged against.
//
// Confirmed and WALEnd come from the branch; Live and Floor from the fan-out
// already running, if there is one. Every field is "as it was a moment ago",
// which is why the comparisons are all one-sided: each of them rules a position
// out, and a position no comparison rules out is served.
type Window struct {
	// Confirmed is the slot's confirmed_flush_lsn — how far the feed has been
	// acknowledged, and so the oldest position Postgres will still replay from.
	// Zero when the branch has no slot yet, which is itself a reason a position
	// cannot be replayed.
	Confirmed pglogrepl.LSN
	// HaveSlot distinguishes "no slot" from "a slot at position zero".
	HaveSlot bool
	// WALEnd is the branch's current write position. A ?since= beyond it did
	// not come from this branch.
	WALEnd pglogrepl.LSN
	// Live is whether a fan-out is already running for this branch.
	Live bool
	// Floor is the oldest position a subscriber joining that fan-out is still
	// given everything after: the position its decoder started from, raised as
	// changes are published to the subscribers already attached. Meaningless
	// unless Live.
	Floor pglogrepl.LSN
}

// JudgeResume decides what to do with a subscriber's ?since=.
//
// Pure, because every one of these cases is a position and two numbers, and the
// bug it fixes was a case nobody had written down rather than a hard sum.
func JudgeResume(since pglogrepl.LSN, w Window) ResumeVerdict {
	if since == 0 {
		return ResumeLive // no ?since= at all: from here, as it always has been
	}
	// Ahead of the branch's own log. Either this position came from somewhere
	// else -- another branch's feed, or the same branch before a restore moved
	// its log back -- or a client is making it up. It is refused in every case:
	// this is the one that poisons the slot.
	if w.WALEnd != 0 && since > w.WALEnd {
		return ResumeAhead
	}
	if w.Live {
		// A fan-out is running. It cannot replay: a subscriber attaching to it
		// receives what is published from now on, and what was published
		// before went to the subscribers that were there. So the only position
		// it can honour is one nothing has passed.
		//
		// A floor of zero is a hub that cannot say where its stream begins, and
		// it is answered with a refetch rather than an attach. It costs a
		// client one needless refetch; the alternative is attaching it to a
		// stream that may have started after the position it asked for, which
		// is the gap again.
		if w.Floor == 0 || since < w.Floor {
			return ResumeExpired
		}
		return ResumeLive
	}
	// Nothing is running, so the decoder will start where it is told -- but
	// Postgres will not go back further than the slot has been acknowledged to,
	// and it does not say so. Asking for an older position there is how the
	// stream silently became "from the slot" instead.
	if !w.HaveSlot || since < w.Confirmed {
		return ResumeExpired
	}
	return ResumeFrom
}
