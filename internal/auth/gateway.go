// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// The Gateway's refusals, kept from flooding the security log.
//
// Every invalid key used to be one event, and one event is a chained row
// written under SQLite's write lock in a log that is never trimmed, so anyone
// who could reach the port could grow it without limit and queue every other
// writer behind them. Two things stop that, both per client address.
//
// The refusals are coalesced: one event per address per window, the first as
// it happens, carrying how many were suppressed since the event before it, so
// the log still says that an address was hammering the door and roughly how
// hard. A window's suppressed count is written when the window ends even if
// the address has gone quiet by then; a process killed inside a window loses
// that one count, never the event that opened it.
//
// And an address that has used up its invalid keys is refused before any key
// is looked up, until its window has passed. Only invalid keys count towards
// that. A valid key that is refused (a realtime key, a branch its owner may
// not open) is coalesced but never held against the address, because it proves
// the holder is a real client with a mistake to fix, and a success does not
// clear the count, because an attacker with one working key could then keep
// guessing for ever.
//
// Nothing here is keyed on anything an attacker can choose about someone else:
// a count belongs to the address that earned it, so refusals from one address
// never lock out another, and the check runs only when a connection opens, so
// a session already in progress is never ended by it. Clients sharing an
// address (behind one NAT) do share its count; that is the cost of the address
// being the only identity there is before a key has been checked.
//
// In memory and per process, like the sign-in throttle: a brake, not a record.
const (
	gatewayMaxFails = 30
	// gatewayWindow is both how long an address's invalid keys are counted and
	// how often a refusing address can add a row to a log nothing trims: at
	// most 288 rows a day per address, against thousands a second before. A
	// client whose key was wrong is back within five minutes of fixing it.
	gatewayWindow = 5 * time.Minute
)

// gatewayGuard is the Gateway's throttle and its coalescer.
type gatewayGuard struct {
	store  *Store
	limit  *throttle
	window time.Duration
	now    func() time.Time

	mu     sync.Mutex
	runs   map[string]*refusalRun
	timer  *time.Timer // set while a run is waiting to be written
	closed bool
}

// refusalRun is one address's refusals of one sort in the current window: the
// event that opened it, and how many have been suppressed since.
type refusalRun struct {
	first                    time.Time
	suppressed               int
	kind, actor, subject, ip string
	detail                   string
}

func newGatewayGuard(s *Store) *gatewayGuard {
	return &gatewayGuard{store: s, limit: newThrottle(gatewayMaxFails, gatewayWindow),
		window: gatewayWindow, now: time.Now, runs: map[string]*refusalRun{}}
}

// gatewayBucket is what an address is counted under. An IPv6 client is
// normally handed a whole /64, so counting single addresses would let it pick
// a fresh one for every attempt.
func gatewayBucket(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

// gatewayExempt is an address the throttle does not hold: this machine, whose
// one address is shared by every process on it and by anything forwarding
// connections to the Gateway, so holding it would let one of them lock out the
// rest. Its refusals are still coalesced.
func gatewayExempt(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Unmap().IsLoopback()
}

// GatewayThrottled reports whether an address has used up its invalid keys,
// and for how much longer. Called before a key is read: a held address costs
// no key lookup. A held attempt is added to the address's coalesced count.
func (s *Store) GatewayThrottled(database, ip string) (bool, time.Duration) {
	if s == nil || s.gateway == nil || gatewayExempt(ip) {
		return false, 0
	}
	held, wait := s.gateway.limit.blocked(gatewayBucket(ip))
	if held {
		s.gateway.note(EvGatewayRefused, "", database, ip, "invalid API key")
	}
	return held, wait
}

// GatewayInvalidKey records a key that matched nothing: it counts towards the
// address's throttle, and the event is coalesced.
func (s *Store) GatewayInvalidKey(database, ip string) {
	if s == nil || s.gateway == nil {
		return
	}
	s.gateway.limit.fail(gatewayBucket(ip))
	s.gateway.note(EvGatewayRefused, "", database, ip, "invalid API key")
}

// GatewayRefused records a valid key refused at the Gateway: coalesced like an
// invalid one, and never counted against the address. Runs are kept apart by
// kind and actor, so one person's refusals do not hide another's.
func (s *Store) GatewayRefused(kind, actor, subject, ip, detail string) {
	if s == nil || s.gateway == nil {
		return
	}
	s.gateway.note(kind, actor, subject, ip, detail)
}

// note counts one refusal, and writes an event if it opens a window.
func (g *gatewayGuard) note(kind, actor, subject, ip, detail string) {
	k := gatewayBucket(ip) + "\x00" + kind + "\x00" + actor
	g.mu.Lock()
	now := g.now()
	r, ok := g.runs[k]
	if ok && now.Sub(r.first) < g.window {
		r.suppressed++
		g.mu.Unlock()
		return
	}
	prior := 0
	if ok {
		prior = r.suppressed
	}
	g.runs[k] = &refusalRun{first: now, kind: kind, actor: actor, subject: subject, ip: ip, detail: detail}
	g.arm()
	g.mu.Unlock()
	g.store.Audit(kind, actor, subject, ip, coalescedDetail(detail, prior))
}

// coalescedDetail says how many refusals an event stands for beyond itself.
func coalescedDetail(detail string, suppressed int) string {
	if suppressed == 0 {
		return detail
	}
	return fmt.Sprintf("%s, and %d more refused from this address since the last record", detail, suppressed)
}

// arm makes sure a timer is due to write what is waiting. The caller holds mu.
func (g *gatewayGuard) arm() {
	if g.timer == nil && !g.closed {
		g.timer = time.AfterFunc(g.window/4, g.tick)
	}
}

func (g *gatewayGuard) tick() {
	g.flush(false)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.timer = nil
	if len(g.runs) > 0 {
		g.arm()
	}
}

// flush writes the suppressed counts of the windows that have ended, or of
// every window when all is set. A window that ended with nothing suppressed
// is forgotten; one that wrote a count opens the next window, so an address
// still gets at most one event per window however its refusals fall.
func (g *gatewayGuard) flush(all bool) {
	g.mu.Lock()
	now := g.now()
	var due []refusalRun
	for k, r := range g.runs {
		if !all && now.Sub(r.first) < g.window {
			continue
		}
		if r.suppressed == 0 {
			delete(g.runs, k)
			continue
		}
		due = append(due, *r)
		r.first, r.suppressed = now, 0
	}
	g.mu.Unlock()
	for _, r := range due {
		g.store.Audit(r.kind, r.actor, r.subject, r.ip, coalescedDetail(r.detail, r.suppressed))
	}
}

// close writes what is waiting, while there is still a store to write it to.
func (g *gatewayGuard) close() {
	g.mu.Lock()
	g.closed = true
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
	g.mu.Unlock()
	g.flush(true)
}
