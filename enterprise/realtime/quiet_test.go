//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/jackc/pglogrepl"
)

// A decoder on a test's own slot, with one subscriber that has read everything
// so far unless the test leaves its events in the buffer.
func quietDecoder(t *testing.T, slot string) (*Decoder, *Subscriber) {
	t.Helper()
	quiet.mu.Lock()
	delete(quiet.m, slot)
	quiet.mu.Unlock()
	h := NewHub()
	s := h.Subscribe()
	t.Cleanup(s.Close)
	d := &Decoder{hub: h, slot: slot, relations: map[uint32]Relation{}}
	d.relations[1] = Relation{Schema: "public", Name: "t", ReplicaIdentity: 'd',
		Columns: []Column{{Name: "id", TypeOID: 20, Key: true}}}
	return d, s
}

func keepaliveAt(end pglogrepl.LSN, reply bool) []byte {
	b := make([]byte, 18)
	b[0] = pglogrepl.PrimaryKeepaliveMessageByteID
	binary.BigEndian.PutUint64(b[1:], uint64(end))
	if reply {
		b[17] = 1
	}
	return b
}

// xlogAt wraps pgoutput's own bytes for a message as a walsender sends them.
func xlogAt(start, end pglogrepl.LSN, wal []byte) []byte {
	b := make([]byte, 25, 25+len(wal))
	b[0] = pglogrepl.XLogDataByteID
	binary.BigEndian.PutUint64(b[1:], uint64(start))
	binary.BigEndian.PutUint64(b[9:], uint64(end))
	return append(b, wal...)
}

func beginWAL(final pglogrepl.LSN, xid uint32) []byte {
	b := make([]byte, 21)
	b[0] = 'B'
	binary.BigEndian.PutUint64(b[1:], uint64(final))
	binary.BigEndian.PutUint32(b[17:], xid)
	return b
}

func commitWAL(commit, end pglogrepl.LSN) []byte {
	b := make([]byte, 26)
	b[0] = 'C'
	binary.BigEndian.PutUint64(b[2:], uint64(commit))
	binary.BigEndian.PutUint64(b[10:], uint64(end))
	return b
}

func insertWAL(rel uint32, value string) []byte {
	b := []byte{'I', 0, 0, 0, 0, 'N', 0, 1, 't', 0, 0, 0, byte(len(value))}
	binary.BigEndian.PutUint32(b[1:], rel)
	return append(b, value...)
}

func drain(s *Subscriber) (n int) {
	for {
		select {
		case <-s.Events():
			n++
		default:
			return n
		}
	}
}

func mustCopy(t *testing.T, d *Decoder, data []byte) bool {
	t.Helper()
	reply, err := d.handleCopyData(data)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestAKeepaliveAdvancesAQuietSlot(t *testing.T) {
	d, _ := quietDecoder(t, "ka")
	if mustCopy(t, d, keepaliveAt(1000, false)) {
		t.Error("a keepalive not asking for a reply got one")
	}
	if d.acked != 1000 {
		t.Fatalf("acked = %v, want the keepalive's position", d.acked)
	}
	if !mustCopy(t, d, keepaliveAt(1500, true)) {
		t.Error("a keepalive asking for a reply did not get one")
	}
	// Never backwards: a server can report what it has already reported.
	mustCopy(t, d, keepaliveAt(1200, false))
	if d.acked != 1500 {
		t.Errorf("acked = %v after an older keepalive, want 1500", d.acked)
	}
	// The XLogData header carries a position too, and a message arriving when
	// nothing is open advances on it just the same.
	mustCopy(t, d, xlogAt(1500, 1800, []byte("O\x00\x00\x00\x00\x00\x00\x00\x00x\x00")))
	if d.acked != 1800 {
		t.Errorf("acked = %v after XLogData's position, want 1800", d.acked)
	}
}

// Empty CopyData has no type byte: indexing it would panic in the decoder that
// every subscriber on the branch is reading from.
func TestEmptyCopyDataIsHarmless(t *testing.T) {
	d, _ := quietDecoder(t, "empty")
	if reply, err := d.handleCopyData(nil); reply || err != nil {
		t.Fatalf("empty CopyData: %v %v", reply, err)
	}
	if reply, err := d.handleCopyData([]byte{}); reply || err != nil {
		t.Fatalf("empty CopyData: %v %v", reply, err)
	}
	if d.acked != 0 {
		t.Errorf("acked moved on nothing: %v", d.acked)
	}
	// Short messages are refused by their parsers, not read past their end.
	if _, err := d.handleCopyData([]byte{pglogrepl.PrimaryKeepaliveMessageByteID}); err == nil {
		t.Error("a truncated keepalive was accepted")
	}
}

// The one that must not happen: a position past a change someone has not been
// given. Inside a transaction a keepalive may be ahead of the commit.
func TestAKeepaliveDoesNotAcknowledgeInsideATransaction(t *testing.T) {
	d, s := quietDecoder(t, "intx")
	mustCopy(t, d, keepaliveAt(1000, false))
	mustCopy(t, d, xlogAt(1000, 1100, beginWAL(2000, 7)))
	mustCopy(t, d, keepaliveAt(1900, false))
	if d.acked != 1000 {
		t.Fatalf("a keepalive inside a transaction moved acked to %v", d.acked)
	}
	mustCopy(t, d, xlogAt(1100, 1200, insertWAL(1, "1")))
	drain(s)
	mustCopy(t, d, keepaliveAt(1950, false))
	if d.acked != 1000 {
		t.Fatalf("a keepalive after a row moved acked to %v", d.acked)
	}
	mustCopy(t, d, xlogAt(1200, 2000, commitWAL(2000, 2010)))
	if d.acked != 2000 {
		t.Fatalf("a commit acknowledged %v, want the commit's position", d.acked)
	}
	drain(s)
	mustCopy(t, d, keepaliveAt(3000, false))
	if d.acked != 3000 {
		t.Errorf("acked = %v once quiet again, want 3000", d.acked)
	}
}

func TestAKeepaliveWaitsForSubscribersToBeGivenEverything(t *testing.T) {
	d, s := quietDecoder(t, "buffered")
	d.hub.Publish(Commit{Type: "commit"}) // an event still in the buffer
	mustCopy(t, d, keepaliveAt(1000, false))
	if d.acked != 0 {
		t.Fatalf("acked = %v with an event still buffered", d.acked)
	}
	drain(s)
	mustCopy(t, d, keepaliveAt(1000, false))
	if d.acked != 1000 {
		t.Errorf("acked = %v once drained, want 1000", d.acked)
	}
}

// With nobody attached, nobody has been given anything.
func TestAKeepaliveDoesNotAdvanceWithNoSubscribers(t *testing.T) {
	d, s := quietDecoder(t, "nosubs")
	s.Close()
	mustCopy(t, d, keepaliveAt(1000, false))
	if d.acked != 0 {
		t.Errorf("acked = %v with nobody attached", d.acked)
	}
}

// The resume check against the positions acknowledged on keepalives, which is
// what the keepalive advance puts at risk: a client that saw the last commit,
// on a table nobody has written to since, must still be able to come back.
func TestAResumeSurvivesAQuietSlotMovingOn(t *testing.T) {
	d, s := quietDecoder(t, "resume")
	noteQuietStart(d.slot, 1000, 1000)
	d.acked = 1000
	mustCopy(t, d, xlogAt(1000, 1100, beginWAL(2000, 7)))
	mustCopy(t, d, xlogAt(1100, 1200, insertWAL(1, "1")))
	mustCopy(t, d, xlogAt(1200, 2000, commitWAL(2000, 2010)))
	drain(s)
	mustCopy(t, d, keepaliveAt(9000, false))
	if d.acked != 9000 {
		t.Fatalf("acked = %v", d.acked)
	}

	window := func(confirmed pglogrepl.LSN) Window {
		w := Window{HaveSlot: true, Confirmed: confirmed, WALEnd: 10000}
		w.QuietFrom, w.QuietTo = QuietSpan(d.slot, confirmed, true)
		return w
	}
	w := window(9000)
	if got := JudgeResume(2000, w); got != ResumeFrom {
		t.Errorf("a client at the last commit, after only keepalives: %v, want ResumeFrom", got)
	}
	if got := JudgeResume(5000, w); got != ResumeFrom {
		t.Errorf("a position inside the quiet span: %v, want ResumeFrom", got)
	}
	if got := JudgeResume(1500, w); got != ResumeExpired {
		t.Errorf("a client from before the last commit has missed a change: %v, want ResumeExpired", got)
	}

	// A slot gone past what this process acknowledged is a different slot:
	// the span is no evidence about it, and is forgotten.
	w = window(12000)
	if w.QuietFrom != 0 || w.QuietTo != 0 {
		t.Fatalf("a span survived a slot that moved past it: %+v", w)
	}
	if got := JudgeResume(2000, Window{HaveSlot: true, Confirmed: 12000, WALEnd: 20000}); got != ResumeExpired {
		t.Errorf("no evidence must mean a refetch: %v", got)
	}
}

func TestAQuietSpanIsForgottenWithItsSlot(t *testing.T) {
	const slot = "dropped"
	noteQuietPublished(slot, 100)
	noteQuietAcked(slot, 500)
	if from, to := QuietSpan(slot, 500, true); from != 100 || to != 500 {
		t.Fatalf("span: %v %v", from, to)
	}
	if from, _ := QuietSpan(slot, 0, false); from != 0 {
		t.Fatal("a span survived its slot")
	}
	if from, _ := QuietSpan(slot, 500, true); from != 0 {
		t.Fatal("a forgotten span came back")
	}
	if from, to := QuietSpan("unknown-slot", 500, true); from != 0 || to != 0 {
		t.Fatalf("a span for a slot never seen: %v %v", from, to)
	}
	// A fan-out that could not say where it started has no span to give.
	noteQuietStart("no-floor", 0, 0)
	if from, _ := QuietSpan("no-floor", 0, true); from != 0 {
		t.Errorf("a span from nowhere: %v", from)
	}
	// A later decoder continues a span rather than restarting it.
	noteQuietPublished("continued", 800)
	noteQuietStart("continued", 900, 900)
	if from, to := QuietSpan("continued", 900, true); from != 800 || to != 900 {
		t.Errorf("continued span: %v %v", from, to)
	}
}

func TestJudgeResumeQuietNeedsTheSpanToCoverTheSlot(t *testing.T) {
	cases := []struct {
		w    Window
		want ResumeVerdict
	}{
		{Window{HaveSlot: true, Confirmed: 5000, QuietFrom: 1000, QuietTo: 5000}, ResumeFrom},
		{Window{HaveSlot: true, Confirmed: 5000, QuietFrom: 1000, QuietTo: 6000}, ResumeFrom}, // the slot lags what was reported
		{Window{HaveSlot: true, Confirmed: 7000, QuietFrom: 1000, QuietTo: 6000}, ResumeExpired},
		{Window{HaveSlot: true, Confirmed: 5000, QuietFrom: 3000, QuietTo: 6000}, ResumeExpired},
		{Window{HaveSlot: true, Confirmed: 5000}, ResumeExpired},
		{Window{HaveSlot: false, Confirmed: 0, QuietFrom: 1000, QuietTo: 6000}, ResumeExpired},
	}
	for i, c := range cases {
		if got := JudgeResume(2000, c.w); got != c.want {
			t.Errorf("case %d (%s): %v, want %v", i, fmt.Sprint(c.w), got, c.want)
		}
	}
}
