//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pglogrepl"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Fan-out: one decoder per branch, many subscribers.
//
// The decision that shapes this: **a subscriber that cannot keep up is dropped,
// loudly.** One decoder feeds every subscriber of a branch, so a single slow
// reader blocking the send would stall the feed for everyone and let the
// replication slot's WAL grow behind it. The alternatives were worse — an
// unbounded buffer moves the failure to memory, and skipping events leaves a
// subscriber running with silent holes in its copy, which is the one outcome
// nobody can detect downstream.
//
// So: a bounded buffer, and overflow ends that subscriber's stream with a
// reason it can act on. Dropping one subscriber loudly beats degrading all of
// them quietly.

// BufferSize is how many events one subscriber may fall behind by.
//
// Big enough to ride out a garbage collection or a slow network write, small
// enough that a subscriber which has genuinely stopped reading is noticed in
// seconds rather than minutes.
const BufferSize = 256

// EnvBuffer raises or lowers that, because the number is also a ceiling on how
// large a transaction can be delivered at all: pgoutput proto 1 sends a
// transaction whole, so one with more changes than this cannot reach a
// subscriber however fast it reads. Nothing said so, and nothing could be done
// about it on an install that needed it.
const EnvBuffer = "REALTIME_BUFFER"

// Buffer is BufferSize, adjusted by FOX_REALTIME_BUFFER.
func Buffer() int {
	if v := strings.TrimSpace(brand.Getenv(EnvBuffer)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		log.Printf("realtime: %s=%q is not a positive number; using %d",
			brand.EnvPrefix+EnvBuffer, v, BufferSize)
	}
	return BufferSize
}

// Hub fans one branch's changes out to its subscribers.
type Hub struct {
	mu     sync.Mutex
	subs   map[int64]*Subscriber
	nextID int64
	// closed and why are remembered, so a subscriber that attaches after the
	// decoder has already given up is told immediately rather than waiting.
	//
	// That race is real and was not theoretical: the route starts the decoder
	// and then subscribes, so a decoder that failed at once -- an invalidated
	// slot, say -- closed the hub before anybody was on it, and the subscriber
	// then sat on a stream that would never carry anything until the hour-long
	// deadline. Exactly the silence this design promises never to produce.
	closed bool
	why    Notice
	// delivered counts change events fanned out since this hub started, and
	// peak is the most subscribers it has held at once.
	//
	// Both are in-process and restart with the control plane, which is exactly
	// why the meter records them next to a timestamp rather than treating them
	// as totals: a counter that silently restarts is worse than no counter, and
	// a reading that says "this many, as of then" cannot mislead.
	delivered int64
	peak      int
	// floor is the oldest position a subscriber joining now is still given
	// everything after: where this hub's decoder started, raised to a
	// transaction's commit position as soon as that transaction starts being
	// published.
	//
	// It exists because this fan-out cannot replay. Everything published went
	// to whoever was attached at the time and is not kept, so a subscriber
	// arriving with an older ?since= would be quietly moved to the present --
	// which is the gap this hub's own comment promises not to produce, and the
	// one it was producing.
	floor pglogrepl.LSN
	// inTx is whether a transaction is open in the stream being published. The
	// hub sees every begin and commit frame, whether or not any subscriber
	// asked for them, so it can tell the two overflows apart: one a subscriber
	// can resume from, one it cannot.
	inTx bool
	// txChanges counts the changes published in the open transaction, so the
	// notice can say how large it was rather than only that it was too large.
	txChanges int
	// releasable is set when a transaction that dropped a subscriber has been
	// published in full, so the decoder can acknowledge it before those
	// subscribers are detached. See ReleasePending.
	releasable bool
}

func NewHub() *Hub { return &Hub{subs: map[int64]*Subscriber{}} }

// StartedAt records where this hub's decoder began, which is the floor until a
// transaction is published. Called once, before the first subscriber attaches.
func (h *Hub) StartedAt(lsn pglogrepl.LSN) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.floor = lsn
}

// Floor is the oldest ?since= a subscriber may join this hub with. A position
// below it was either never covered by this decoder or has already been
// published to somebody else.
func (h *Hub) Floor() pglogrepl.LSN {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.floor
}

// Subscriber is one open stream.
type Subscriber struct {
	id   int64
	hub  *Hub
	ch   chan any
	done chan struct{}
	once sync.Once

	mu     sync.Mutex
	reason Notice // why the stream ended, when it ended for a reason
	// pending is a reason this stream is about to end with, held until the
	// decoder has acknowledged the transaction it died in. See pend.
	pending Notice
}

// MaxSubscribers is how many streams one branch may have at once.
//
// A cap exists because every subscriber is a reason the branch cannot be
// suspended and a share of the decoder's fan-out, and because the failure
// without one is unpleasant: a client that reconnects on error, with a bug,
// adds a stream per attempt until the process runs out of something. Refusing
// the ninth with a message naming the count is a better afternoon than
// discovering it from a memory graph.
//
// Eight by default — generous for the subscriber-per-application shape this is
// built for, and well short of anything that hurts. One fan-out serves them
// all, so this is not a throughput limit.
func MaxSubscribers() int {
	if v := strings.TrimSpace(brand.Getenv(EnvMaxSubscribers)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		log.Printf("realtime: %s=%q is not a positive number; using %d",
			brand.EnvPrefix+EnvMaxSubscribers, v, defaultMaxSubscribers)
	}
	return defaultMaxSubscribers
}

const (
	defaultMaxSubscribers = 8
	// EnvMaxSubscribers raises or lowers the per-branch cap.
	EnvMaxSubscribers = "REALTIME_MAX_SUBSCRIBERS"
)

// ErrTooManySubscribers is returned when a branch is at its cap. It names the
// number, because "try again later" without one tells a developer nothing about
// whether they have a bug or a busy install.
type ErrTooManySubscribers struct{ Have, Max int }

func (e ErrTooManySubscribers) Error() string {
	return fmt.Sprintf("branch is already serving %d change-feed subscribers, which is the limit (%s raises it)",
		e.Have, brand.EnvPrefix+EnvMaxSubscribers)
}

// TrySubscribe opens a stream unless the branch is at its cap.
//
// Separate from Subscribe rather than replacing it: Subscribe is called by the
// decoder's own tests and by paths that are not a client asking for a stream,
// and silently giving them a cap would be a change to working behaviour rather
// than an addition.
func (h *Hub) TrySubscribe() (*Subscriber, error) {
	max := MaxSubscribers()
	h.mu.Lock()
	have := len(h.subs)
	h.mu.Unlock()
	if have >= max {
		return nil, ErrTooManySubscribers{Have: have, Max: max}
	}
	return h.Subscribe(), nil
}

// Subscribe opens a stream. The caller must Close it.
func (h *Hub) Subscribe() *Subscriber {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	s := &Subscriber{id: h.nextID, hub: h, ch: make(chan any, Buffer()), done: make(chan struct{})}
	if h.closed {
		// Already over. Hand back a stream that is finished and says why, so
		// the caller reports it and moves on.
		s.reason = h.why
		close(s.done)
		return s
	}
	h.subs[s.id] = s
	if len(h.subs) > h.peak {
		h.peak = len(h.subs)
	}
	return s
}

// Count is how many subscribers are attached. The decoder starts on the first
// and stops after the last: a branch with nobody listening should not be
// holding a replication slot open.
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Stats is what this hub has done, for the meter.
func (h *Hub) Stats() (subscribers int, delivered int64, peak int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs), h.delivered, h.peak
}

// Publish sends to every subscriber without blocking on any of them.
func (h *Hub) Publish(ev any) {
	done := false // a transaction finished in this call
	h.mu.Lock()
	h.delivered++
	// Where the stream is, for a subscriber that joins later and for the
	// notice an overflow carries.
	switch e := ev.(type) {
	case Begin:
		h.inTx, h.txChanges = true, 0
		// The floor rises here rather than at the commit, and that is the whole
		// point of it: once a transaction has started being published, nobody
		// joining can be given it whole, and landing a subscriber in the middle
		// of one is the thing resume exists to avoid. pgoutput announces the
		// commit position in the begin frame, so it is known now.
		if lsn, err := pglogrepl.ParseLSN(e.CommitLSN); err == nil && lsn > h.floor {
			h.floor = lsn
		}
	case Change:
		h.txChanges++
	case Commit:
		h.inTx, h.txChanges = false, 0
		done = true
	}
	full := h.overflowNotice()
	subs := make([]*Subscriber, 0, len(h.subs))
	for _, s := range h.subs {
		subs = append(subs, s)
	}
	h.mu.Unlock()

	for _, s := range subs {
		select {
		case s.ch <- ev:
		default:
			// Full. This subscriber has stopped reading, and waiting for it
			// would stall the decoder and every other subscriber behind it.
			if s.isPending() {
				// Already doomed, and its reason is already decided. Without
				// this the transaction's own commit frame -- which arrives
				// when inTx is no longer set -- would detach it with the
				// ordinary overflow notice, which is both the wrong message
				// and the early detach this is here to prevent.
				continue
			}
			if full.Code == CodeTxTooLarge {
				// Dropped, but not detached yet. Detaching the last subscriber
				// inside a transaction is what wedged the feed: the fan-out
				// empties, the decoder is cancelled where it stands, the
				// transaction is never acknowledged, and the next subscriber
				// starts a decoder that replays the same transaction and
				// overflows in the same place. For ever.
				//
				// So the stream stays attached until the transaction has been
				// published in full and the decoder has reported it. One more
				// transaction's worth of dropped events costs nothing: they
				// were being dropped already.
				s.pend(full)
				continue
			}
			s.end(full)
		}
	}
	if done {
		h.mu.Lock()
		h.releasable = len(h.pendingSubs()) > 0
		h.mu.Unlock()
	}
}

// pendingSubs are the subscribers waiting to be detached. The caller holds the
// lock.
func (h *Hub) pendingSubs() []*Subscriber {
	var out []*Subscriber
	for _, s := range h.subs {
		if s.isPending() {
			out = append(out, s)
		}
	}
	return out
}

// Releasable reports whether a transaction that dropped a subscriber has been
// published in full, so its position can be acknowledged before that subscriber
// is told. The decoder asks; see ReleasePending.
func (h *Hub) Releasable() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.releasable
}

// ReleasePending ends the streams that overflowed inside a transaction, and is
// called by the decoder *after* it has acknowledged that transaction.
//
// The order is the whole point. Acknowledge first, then detach: the last
// subscriber leaving is what stops the decoder, and if it leaves before the
// transaction is reported the feed starts again from in front of a transaction
// it cannot deliver.
//
// The cost is that the subscriber hears nothing until the transaction has been
// decoded, which is milliseconds for a few thousand changes and could be a
// minute for millions. It is still the better trade: the alternative is to be
// told immediately and find the feed unusable afterwards. Delivering a
// transaction that large at all needs pgoutput's in-progress streaming, which
// is a larger change than this.
func (h *Hub) ReleasePending() {
	h.mu.Lock()
	subs := h.pendingSubs()
	h.releasable = false
	h.mu.Unlock()
	for _, s := range subs {
		s.end(s.takePending())
	}
}

// overflowNotice is what a subscriber that has run out of buffer is told. The
// caller holds the lock.
//
// Two different situations, and they were one message. Falling behind across
// transactions is the ordinary case: the subscriber has a whole transaction's
// commit position to come back with, and `reconnect with ?since=` is sound
// advice. Falling behind *inside* one transaction is not: every change in it
// carries that transaction's commit position, so coming back with the last one
// seen either asks for the transaction again -- overflowing in the same place,
// for ever -- or, if somebody else finished reading it meanwhile, skips the
// rest of it without a word. The only honest answer there is to refetch.
func (h *Hub) overflowNotice() Notice {
	if h.inTx {
		return Notice{Type: "resync", Code: CodeTxTooLarge,
			Detail: fmt.Sprintf("this transaction has more changes (%d so far) than one subscriber "+
				"can be buffered (%d), so it cannot be streamed whole; refetch the table and "+
				"subscribe again, or raise %s",
				h.txChanges, Buffer(), brand.EnvPrefix+EnvBuffer)}
	}
	return Notice{Type: "error", Code: CodeOverflow,
		Detail: "this subscriber fell more than " + strconv.Itoa(Buffer()) +
			" events behind; reconnect with ?since= to resume"}
}

// Close ends every subscriber, for a decoder that has given up or a branch
// going away.
func (h *Hub) Close(n Notice) {
	h.mu.Lock()
	h.closed, h.why = true, n
	subs := make([]*Subscriber, 0, len(h.subs))
	for _, s := range h.subs {
		subs = append(subs, s)
	}
	h.mu.Unlock()
	for _, s := range subs {
		s.end(n)
	}
}

// Events is the stream to read. It is never closed: Publish sends to it after
// releasing the hub's lock, so closing it from end would be a send on a closed
// channel waiting for the right interleaving. A reader selects on Done instead,
// which is closed exactly once.
func (s *Subscriber) Events() <-chan any { return s.ch }

// Done is closed when the stream has ended; Reason says why.
func (s *Subscriber) Done() <-chan struct{} { return s.done }

// Reason is why the stream ended, zero when the subscriber simply closed it.
func (s *Subscriber) Reason() Notice {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// Close detaches a subscriber that is finished with the stream.
func (s *Subscriber) Close() { s.end(Notice{}) }

// pend records why this stream will end without ending it yet. Idempotent: the
// rest of the transaction keeps overflowing, and the first reason is the one
// that counts.
func (s *Subscriber) pend(n Notice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending.Type == "" {
		s.pending = n
	}
}

func (s *Subscriber) isPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending.Type != ""
}

func (s *Subscriber) takePending() Notice {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.pending
	s.pending = Notice{}
	return n
}

func (s *Subscriber) end(n Notice) {
	s.once.Do(func() {
		if n.Type != "" {
			s.mu.Lock()
			s.reason = n
			s.mu.Unlock()
		}
		s.hub.mu.Lock()
		delete(s.hub.subs, s.id)
		s.hub.mu.Unlock()
		close(s.done)
	})
}
