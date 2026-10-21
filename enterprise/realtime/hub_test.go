//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEverySubscriberGetsEveryEvent(t *testing.T) {
	h := NewHub()
	a, b := h.Subscribe(), h.Subscribe()
	defer a.Close()
	defer b.Close()

	h.Publish(Change{Type: "change", Action: "insert"})
	for name, s := range map[string]*Subscriber{"a": a, "b": b} {
		select {
		case ev := <-s.Events():
			if c, ok := ev.(Change); !ok || c.Action != "insert" {
				t.Errorf("%s got %#v", name, ev)
			}
		case <-time.After(time.Second):
			t.Errorf("%s got nothing", name)
		}
	}
}

// The decision this design rests on: one slow reader must not stall the decoder
// or the subscribers behind it. It is dropped, and told why.
func TestASlowSubscriberIsDroppedAndTheRestKeepUp(t *testing.T) {
	h := NewHub()
	slow := h.Subscribe()
	fast := h.Subscribe()
	defer fast.Close()

	// Fill the slow one's buffer and then some, draining the fast one so it
	// stays healthy.
	for i := 0; i < BufferSize+10; i++ {
		h.Publish(Change{Type: "change"})
		select {
		case <-fast.Events():
		default:
		}
	}

	select {
	case <-slow.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a subscriber that stopped reading was never dropped")
	}
	if got := slow.Reason(); got.Code != CodeOverflow {
		t.Errorf("reason = %+v, want %s", got, CodeOverflow)
	}
	// And the hub carried on: the fast one is still attached and still fed.
	if h.Count() != 1 {
		t.Errorf("%d subscribers attached, want only the fast one", h.Count())
	}
	h.Publish(Change{Type: "change", Action: "after"})
	select {
	case <-fast.Events():
	case <-time.After(time.Second):
		t.Error("the healthy subscriber stopped receiving after the slow one was dropped")
	}
}

// A decoder that gives up ends every stream with the same reason, so no
// subscriber is left waiting on a feed that will never resume.
func TestClosingTheHubEndsEveryStream(t *testing.T) {
	h := NewHub()
	a, b := h.Subscribe(), h.Subscribe()
	h.Close(Notice{Type: "error", Code: CodeDecoderFailed})
	for name, s := range map[string]*Subscriber{"a": a, "b": b} {
		select {
		case <-s.Done():
			if s.Reason().Code != CodeDecoderFailed {
				t.Errorf("%s reason = %+v", name, s.Reason())
			}
		case <-time.After(time.Second):
			t.Errorf("%s was left open", name)
		}
	}
	if h.Count() != 0 {
		t.Errorf("%d subscribers left attached", h.Count())
	}
}

// Closing twice, and closing while the hub is publishing, must not panic.
func TestCloseIsSafeTwiceAndUnderPublish(t *testing.T) {
	h := NewHub()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		s := h.Subscribe()
		wg.Add(2)
		go func() { defer wg.Done(); s.Close(); s.Close() }()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				h.Publish(Change{Type: "change"})
			}
		}()
	}
	wg.Wait()
	if h.Count() != 0 {
		t.Errorf("%d subscribers left attached", h.Count())
	}
}

// A subscriber that attaches after the decoder has already given up must be
// told at once, not left waiting.
//
// The route starts a decoder and then subscribes, so a decoder that fails
// immediately -- an invalidated slot, say -- closes the hub before anybody is
// on it. The first version left that subscriber on a stream that would never
// carry anything until its hour-long deadline: exactly the silence this design
// promises never to produce.
func TestSubscribingAfterTheHubHasGivenUp(t *testing.T) {
	h := NewHub()
	h.Close(Notice{Type: "resync", Code: CodeSlotLost, Detail: "refetch and subscribe again"})

	s := h.Subscribe()
	select {
	case <-s.Done():
		if s.Reason().Code != CodeSlotLost {
			t.Errorf("reason = %+v, want %s", s.Reason(), CodeSlotLost)
		}
	case <-time.After(time.Second):
		t.Fatal("a subscriber attached to a hub that had given up was left waiting")
	}
}

// The floor: the oldest position a subscriber joining this fan-out can be given
// everything after. It is what makes a stream in progress able to say "I cannot
// serve that position" instead of attaching a subscriber to a hole.
func TestTheFloorRisesWithTheStream(t *testing.T) {
	h := NewHub()
	if got := h.Floor(); got != 0 {
		t.Errorf("a fresh hub starts at %s, want 0 (unknown)", got)
	}
	h.StartedAt(1000)
	if got := h.Floor(); got != 1000 {
		t.Errorf("floor = %s, want where the decoder started", got)
	}

	// A transaction raises it as soon as it *starts* being published, not when
	// it commits: once the first change has gone out, nobody joining can be
	// given the transaction whole, and landing a subscriber in the middle of
	// one is what resume exists to avoid.
	h.Publish(Begin{Type: "begin", CommitLSN: "0/2000"})
	if got := h.Floor(); got != 0x2000 {
		t.Errorf("floor = %s, want the open transaction's commit position", got)
	}
	h.Publish(Change{Type: "change"})
	h.Publish(Commit{Type: "commit", CommitLSN: "0/2000"})
	if got := h.Floor(); got != 0x2000 {
		t.Errorf("floor = %s after the commit, want it unchanged", got)
	}

	// And it never goes backwards, whatever arrives.
	h.Publish(Begin{Type: "begin", CommitLSN: "0/1000"})
	if got := h.Floor(); got != 0x2000 {
		t.Errorf("floor = %s, want it never to fall", got)
	}
}

// Overflow says two different things now, because there are two different ways
// out. Falling behind across transactions can be resumed from; falling behind
// inside one cannot, and telling a subscriber to resume there either replays
// the transaction for ever or skips the rest of it silently.
func TestOverflowInsideATransactionSaysRefetch(t *testing.T) {
	t.Run("inside a transaction: resync, refetch, and not before the ack", func(t *testing.T) {
		h := NewHub()
		s := h.Subscribe()
		h.Publish(Begin{Type: "begin", CommitLSN: "0/3000"})
		for i := 0; i < BufferSize+10; i++ {
			h.Publish(Change{Type: "change"})
		}
		// Dropped, but deliberately still attached. The last subscriber
		// leaving is what stops the decoder, and if it left here the
		// transaction would never be acknowledged and the next subscriber
		// would replay it and overflow in the same place.
		select {
		case <-s.Done():
			t.Fatal("the subscriber was detached inside the transaction")
		default:
		}
		if h.Count() != 1 {
			t.Errorf("%d subscribers attached, want the overflowed one held", h.Count())
		}
		if h.Releasable() {
			t.Error("releasable before the transaction finished")
		}

		// The commit is what makes it releasable, and the decoder reports the
		// position before letting go.
		h.Publish(Commit{Type: "commit", CommitLSN: "0/3000"})
		if !h.Releasable() {
			t.Fatal("a finished transaction that dropped a subscriber is not releasable")
		}
		h.ReleasePending()
		select {
		case <-s.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("the subscriber was never dropped")
		}
		if h.Releasable() {
			t.Error("still releasable after releasing")
		}
		got := s.Reason()
		if got.Type != "resync" || got.Code != CodeTxTooLarge {
			t.Fatalf("reason = %+v, want a resync with %s", got, CodeTxTooLarge)
		}
		// It must not send the client back with ?since=: that is the advice
		// that loops. And it has to name the knob, because on an install that
		// needs a larger transaction delivered there is now one.
		if strings.Contains(got.Detail, "?since=") {
			t.Errorf("detail %q tells the client to resume, which cannot work here", got.Detail)
		}
		for _, want := range []string{"refetch", "REALTIME_BUFFER"} {
			if !strings.Contains(got.Detail, want) {
				t.Errorf("detail %q does not mention %q", got.Detail, want)
			}
		}
	})

	t.Run("between transactions: the old error, and the old advice", func(t *testing.T) {
		// Unchanged on purpose. This subscriber has a transaction boundary to
		// come back with, and `?since=` is sound advice for it — now more so,
		// since the route checks the position before replaying it.
		h := NewHub()
		s := h.Subscribe()
		h.Publish(Begin{Type: "begin", CommitLSN: "0/4000"})
		h.Publish(Change{Type: "change"})
		h.Publish(Commit{Type: "commit", CommitLSN: "0/4000"})
		for i := 0; i < BufferSize+10; i++ {
			h.Publish(Schema{Type: "schema"})
		}
		select {
		case <-s.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("the subscriber was never dropped")
		}
		got := s.Reason()
		if got.Type != "error" || got.Code != CodeOverflow {
			t.Fatalf("reason = %+v, want an error with %s", got, CodeOverflow)
		}
		if !strings.Contains(got.Detail, "?since=") {
			t.Errorf("detail %q no longer offers the resume that works here", got.Detail)
		}
	})
}

// The buffer is a cap on how large a transaction can be delivered at all, so it
// has to be reachable from outside.
func TestBufferSetting(t *testing.T) {
	t.Setenv("FOX_REALTIME_BUFFER", "")
	if got := Buffer(); got != BufferSize {
		t.Errorf("unset gave %d, want the default %d", got, BufferSize)
	}
	t.Setenv("FOX_REALTIME_BUFFER", "4096")
	if got := Buffer(); got != 4096 {
		t.Errorf("4096 gave %d", got)
	}
	// Nonsense keeps the default rather than becoming zero, which would drop
	// every subscriber on its first event.
	for _, bad := range []string{"lots", "0", "-1"} {
		t.Setenv("FOX_REALTIME_BUFFER", bad)
		if got := Buffer(); got != BufferSize {
			t.Errorf("%q gave %d, want the default", bad, got)
		}
	}
}
