//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
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
