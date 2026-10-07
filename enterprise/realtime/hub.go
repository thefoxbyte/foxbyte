//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"strconv"
	"sync"
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
}

func NewHub() *Hub { return &Hub{subs: map[int64]*Subscriber{}} }

// Subscriber is one open stream.
type Subscriber struct {
	id   int64
	hub  *Hub
	ch   chan any
	done chan struct{}
	once sync.Once

	mu     sync.Mutex
	reason Notice // why the stream ended, when it ended for a reason
}

// Subscribe opens a stream. The caller must Close it.
func (h *Hub) Subscribe() *Subscriber {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	s := &Subscriber{id: h.nextID, hub: h, ch: make(chan any, BufferSize), done: make(chan struct{})}
	if h.closed {
		// Already over. Hand back a stream that is finished and says why, so
		// the caller reports it and moves on.
		s.reason = h.why
		close(s.done)
		return s
	}
	h.subs[s.id] = s
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

// Publish sends to every subscriber without blocking on any of them.
func (h *Hub) Publish(ev any) {
	h.mu.Lock()
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
			s.end(Notice{Type: "error", Code: CodeOverflow,
				Detail: "this subscriber fell more than " + strconv.Itoa(BufferSize) +
					" events behind; reconnect with ?since= to resume"})
		}
	}
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
