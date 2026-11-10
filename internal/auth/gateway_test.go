// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A store whose gateway guard runs on a clock the test moves.
func guardedStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s := testStore(t)
	now := time.Now()
	clock := func() time.Time { return now }
	s.gateway.now, s.gateway.limit.now = clock, clock
	return s, &now
}

func gatewayEvents(t *testing.T, s *Store) []SecurityEvent {
	t.Helper()
	evs, err := s.SecurityEvents(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// One event per window however many refusals, the first when it happens, and
// the next one saying how many it stands for.
func TestGatewayRefusalsAreCoalesced(t *testing.T) {
	s, now := guardedStore(t)
	const ip = "203.0.113.7"
	for i := 0; i < 1000; i++ {
		s.GatewayInvalidKey("main", ip)
	}
	evs := gatewayEvents(t, s)
	if len(evs) != 1 || evs[0].Kind != EvGatewayRefused || evs[0].IP != ip || evs[0].Detail != "invalid API key" {
		t.Fatalf("after 1000 refusals in one window: %+v", evs)
	}
	*now = now.Add(gatewayWindow)
	s.GatewayInvalidKey("main", ip)
	evs = gatewayEvents(t, s)
	if len(evs) != 2 || !strings.Contains(evs[1].Detail, "999 more") {
		t.Fatalf("the next window's event: %+v", evs)
	}
	if id, why := CheckEventChain(evs); id != 0 {
		t.Fatalf("the chain: %s", why)
	}
}

// An address that stops mid-window still gets its count written, without
// waiting for a refusal that may never come, and no extra event.
func TestGatewayCountIsWrittenWhenTheWindowEnds(t *testing.T) {
	s, now := guardedStore(t)
	for i := 0; i < 5; i++ {
		s.GatewayInvalidKey("main", "203.0.113.7")
	}
	s.gateway.flush(false)
	if n := len(gatewayEvents(t, s)); n != 1 {
		t.Fatalf("written before the window ended: %d events", n)
	}
	*now = now.Add(gatewayWindow)
	s.gateway.flush(false)
	evs := gatewayEvents(t, s)
	if len(evs) != 2 || !strings.Contains(evs[1].Detail, "4 more") {
		t.Fatalf("after the window: %+v", evs)
	}
	// The count opened the next window: that one wrote nothing more, and it
	// then goes away.
	*now = now.Add(gatewayWindow)
	s.gateway.flush(false)
	if n := len(gatewayEvents(t, s)); n != 2 {
		t.Fatalf("a quiet window added an event: %d", n)
	}
	if len(s.gateway.runs) != 0 {
		t.Fatalf("a quiet address was remembered: %d runs", len(s.gateway.runs))
	}
}

// Closing the store writes what was waiting.
func TestGatewayCountIsWrittenOnClose(t *testing.T) {
	s, _ := guardedStore(t)
	s.GatewayInvalidKey("main", "203.0.113.7")
	s.GatewayInvalidKey("main", "203.0.113.7")
	s.gateway.close()
	evs := gatewayEvents(t, s)
	if len(evs) != 2 || !strings.Contains(evs[1].Detail, "1 more") {
		t.Fatalf("after close: %+v", evs)
	}
}

// A throttled address is held for its window, then let go, and its held
// attempts are counted without a row each.
func TestGatewayThrottleHoldsAnAddress(t *testing.T) {
	s, now := guardedStore(t)
	const ip = "203.0.113.7"
	for i := 0; i < gatewayMaxFails; i++ {
		if held, _ := s.GatewayThrottled("main", ip); held {
			t.Fatalf("held after %d failures", i)
		}
		s.GatewayInvalidKey("main", ip)
	}
	for i := 0; i < 500; i++ {
		if held, wait := s.GatewayThrottled("main", ip); !held || wait <= 0 {
			t.Fatalf("not held once its failures were used up: %v %v", held, wait)
		}
	}
	if n := len(gatewayEvents(t, s)); n != 1 {
		t.Fatalf("held attempts wrote %d events", n)
	}
	*now = now.Add(gatewayWindow)
	if held, _ := s.GatewayThrottled("main", ip); held {
		t.Fatal("still held after its window")
	}
}

// One address's refusals cost nobody else anything: not another address, and
// not a run of refusals naming a database or an account.
func TestGatewayThrottleIsPerAddress(t *testing.T) {
	s, _ := guardedStore(t)
	for i := 0; i < gatewayMaxFails*2; i++ {
		s.GatewayInvalidKey(fmt.Sprintf("db%d", i), "203.0.113.7")
	}
	if held, _ := s.GatewayThrottled("main", "203.0.113.8"); held {
		t.Fatal("an attacker's refusals held another address")
	}
	if held, _ := s.GatewayThrottled("main", "2001:db8::1"); held {
		t.Fatal("an attacker's refusals held another family's address")
	}
	if held, _ := s.GatewayThrottled("anything", "203.0.113.7"); !held {
		t.Fatal("the attacker was not held whatever database it named")
	}
}

// A valid key that was refused is logged and coalesced, and is never held
// against the address: a client asking for a branch it may not open must not
// lose the branches it may.
func TestGatewayValidKeyRefusalsDoNotThrottle(t *testing.T) {
	s, _ := guardedStore(t)
	const ip = "203.0.113.7"
	for i := 0; i < gatewayMaxFails*3; i++ {
		s.GatewayRefused(EvDenied, "a@x.com", "secret", ip, "gateway")
		s.GatewayRefused(EvGatewayRefused, "a@x.com", "secret", ip, "realtime key at the gateway")
	}
	if held, _ := s.GatewayThrottled("main", ip); held {
		t.Fatal("refusals of a valid key throttled the address")
	}
	if n := len(gatewayEvents(t, s)); n != 2 {
		t.Fatalf("want one event per kind in the window, got %d", n)
	}
	// One person's refusals do not hide another's.
	s.GatewayRefused(EvDenied, "b@x.com", "secret", ip, "gateway")
	if n := len(gatewayEvents(t, s)); n != 3 {
		t.Fatalf("a second actor was folded into the first: %d events", n)
	}
}

// This machine's address is shared by everything on it and by anything
// forwarding to the Gateway, so it is coalesced and not held.
func TestGatewayDoesNotHoldLoopback(t *testing.T) {
	s, _ := guardedStore(t)
	for _, ip := range []string{"127.0.0.1", "::1"} {
		for i := 0; i < gatewayMaxFails*2; i++ {
			s.GatewayInvalidKey("main", ip)
		}
		if held, _ := s.GatewayThrottled("main", ip); held {
			t.Errorf("%s was held", ip)
		}
	}
	if n := len(gatewayEvents(t, s)); n != 2 {
		t.Fatalf("loopback refusals: %d events, want one per address", n)
	}
}

func TestGatewayBucket(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":                "203.0.113.7",
		"::ffff:203.0.113.7":         "203.0.113.7",
		"2001:db8:1:2:3:4:5:6":       "2001:db8:1:2::/64",
		"2001:db8:1:2:aaaa:bbbb:c:d": "2001:db8:1:2::/64",
		"2001:db8:1:3:aaaa:bbbb:c:d": "2001:db8:1:3::/64",
		"not an address":             "not an address",
	} {
		if got := gatewayBucket(in); got != want {
			t.Errorf("gatewayBucket(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckEventChainFromTakesUpAfterAnAnchor(t *testing.T) {
	s := testStore(t)
	for i := 0; i < 6; i++ {
		s.Audit(EvLoginOK, "a@x.com", "", "", "")
	}
	evs := gatewayEvents(t, s)
	if id, why := CheckEventChainFrom(evs[3:], evs[2].ID, evs[2].RowHash); id != 0 {
		t.Fatalf("a genuine tail: %s", why)
	}
	if id, _ := CheckEventChainFrom(evs[3:], evs[2].ID, "wrong"); id != evs[3].ID {
		t.Fatalf("a tail not following the anchor: %d", id)
	}
	if id, _ := CheckEventChainFrom(evs[3:], evs[3].ID, evs[2].RowHash); id != evs[3].ID {
		t.Fatalf("a tail with the wrong id: %d", id)
	}
}
