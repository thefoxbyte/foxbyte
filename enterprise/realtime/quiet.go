//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"sync"

	"github.com/jackc/pglogrepl"
)

// What a quiet stretch of a slot's position leaves behind for a resume.
//
// A slot acknowledged on keepalives moves past positions where nothing was
// published, which is what stops a quiet table's WAL from piling up. But the
// resume check reads the slot's confirmed position as "everything before this
// was somebody else's": a client reconnecting with the commit position it
// last saw is judged against it, and the slot having moved on would tell it to
// refetch, for a gap that never held a single change. A client on a quiet table
// reconnects at least hourly, so that would be a refetch an hour for nothing.
//
// So this keeps, per slot, the span the decoder has acknowledged without
// publishing anything: from the last position a change was published at
// (from) to the furthest position acknowledged (to). A position inside that
// span has missed nothing, and QuietSpan hands it to the resume check.
//
// In memory, per process, and only ever evidence that a position is safe: with
// nothing recorded (a restarted control plane, a slot read by something else)
// the check goes back to refusing whatever is before the slot's position, which
// costs a client one refetch and never a silent gap. A span from a slot that
// has since been dropped or moved by something else is refused by QuietSpan,
// because the slot's position is then past anything this process acknowledged.
type quietSpan struct{ from, to pglogrepl.LSN }

var quiet = struct {
	mu sync.Mutex
	m  map[string]quietSpan
}{m: map[string]quietSpan{}}

// noteQuietStart records a decoder starting on a slot. The first decoder on a
// slot since this process began starts the span at the position it was asked
// for, or else at the hub's floor; a later one continues the span.
func noteQuietStart(slot string, since, floor pglogrepl.LSN) {
	quiet.mu.Lock()
	defer quiet.mu.Unlock()
	s, ok := quiet.m[slot]
	if !ok {
		s.from = since
		if s.from == 0 {
			s.from = floor
		}
	}
	if since > s.to {
		s.to = since
	}
	quiet.m[slot] = s
}

// noteQuietAcked records a position acknowledged with nothing published.
func noteQuietAcked(slot string, lsn pglogrepl.LSN) {
	quiet.mu.Lock()
	defer quiet.mu.Unlock()
	s := quiet.m[slot]
	if lsn > s.to {
		s.to = lsn
	}
	quiet.m[slot] = s
}

// noteQuietPublished records a position a change was published at: everything
// before it has been somebody's to receive, so the span starts again here.
func noteQuietPublished(slot string, lsn pglogrepl.LSN) {
	quiet.mu.Lock()
	defer quiet.mu.Unlock()
	s := quiet.m[slot]
	s.from = lsn
	if lsn > s.to {
		s.to = lsn
	}
	quiet.m[slot] = s
}

// QuietSpan is a slot's quiet span for a resume check, given the slot's
// confirmed position as read just now. Both are zero when there is nothing
// trustworthy to go on. A confirmed position past what this process ever
// acknowledged means the slot is not the one the span describes -- dropped and
// made again, or moved by something else -- so the span is forgotten.
func QuietSpan(slot string, confirmed pglogrepl.LSN, haveSlot bool) (from, to pglogrepl.LSN) {
	quiet.mu.Lock()
	defer quiet.mu.Unlock()
	s, ok := quiet.m[slot]
	if !ok {
		return 0, 0
	}
	if !haveSlot || confirmed > s.to {
		delete(quiet.m, slot)
		return 0, 0
	}
	if s.from == 0 {
		return 0, 0
	}
	return s.from, s.to
}
