// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"crypto/sha256"
	"io"
	"log"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// One global pool of slots is not enough on its own: a single host could fill
// it with connections that never authenticate, or a single key could hold every
// slot for as long as it liked, and every other client would be refused. So a
// connection is admitted against four limits:
//
//   - the global cap (FOX_GATEWAY_MAX_CONNS), which keeps the gateway under
//     Postgres's own limit;
//   - a smaller cap on connections still authenticating, so the slots left
//     over are always available to clients that have a key;
//   - a cap per client address, so one host cannot take the whole pool;
//   - a cap per API key on authenticated sessions, so one key cannot either.
//
// The defaults are fractions of the global cap, well above a typical
// application pool of 10 to 20 connections, so a normal app never meets them.

// gatewayLimits is what Serve admits connections against.
type gatewayLimits struct {
	slots   chan struct{} // every connection, authenticated or not
	preauth chan struct{} // connections that have not authenticated yet
	perIP   *counter
	perKey  *counter
}

func newGatewayLimits(total, preauth, perIP, perKey int) *gatewayLimits {
	return &gatewayLimits{
		slots:   make(chan struct{}, total),
		preauth: make(chan struct{}, preauth),
		perIP:   newCounter(perIP),
		perKey:  newCounter(perKey),
	}
}

// limitsFromEnv reads the caps from the environment.
func limitsFromEnv() *gatewayLimits {
	total := maxConns()
	return newGatewayLimits(total, maxPreauthConns(total), maxConnsPerIP(total), maxConnsPerKey(total))
}

// admit takes the slots a new connection needs, or returns the message to
// refuse it with. A refused connection holds nothing.
func (g *gatewayLimits) admit(c net.Conn) (*ticket, string) {
	t := &ticket{g: g}
	host := remoteHost(c)
	if !loopbackHost(host) {
		t.ip = addressBucket(host)
		if !g.perIP.acquire(t.ip) {
			return nil, "too many connections to the gateway from this address — try again shortly"
		}
	}
	select {
	case g.slots <- struct{}{}:
	default:
		t.release()
		return nil, "too many connections to the gateway — try again shortly"
	}
	t.slot = true
	select {
	case g.preauth <- struct{}{}:
	default:
		t.release()
		return nil, "too many connections to the gateway waiting to authenticate — try again shortly"
	}
	t.preauth = true
	return t, ""
}

// ticket is what one admitted connection holds. Every method is safe on a nil
// ticket, which is a connection admitted by nothing (handle called directly).
type ticket struct {
	g       *gatewayLimits
	mu      sync.Mutex
	ip      string // "" when the address is exempt
	key     string // "" until an API key is admitted
	slot    bool
	preauth bool
}

// authenticated hands the pre-authentication slot back: the client has a key,
// and from here only the global, per-address and per-key caps hold it.
func (t *ticket) authenticated() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.preauth {
		t.preauth = false
		<-t.g.preauth
	}
}

// admitKey counts this session against its API key, reporting false when the
// key already has as many sessions as it may.
func (t *ticket) admitKey(key string) bool {
	if t == nil {
		return true
	}
	id := keyID(key)
	if !t.g.perKey.acquire(id) {
		return false
	}
	t.mu.Lock()
	t.key = id
	t.mu.Unlock()
	return true
}

// release gives back everything the ticket holds. Safe to call twice.
func (t *ticket) release() {
	if t == nil {
		return
	}
	t.authenticated()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.slot {
		t.slot = false
		<-t.g.slots
	}
	if t.ip != "" {
		t.g.perIP.release(t.ip)
		t.ip = ""
	}
	if t.key != "" {
		t.g.perKey.release(t.key)
		t.key = ""
	}
}

// keyID is what a key is counted under: a digest, so the table of live
// sessions does not keep the keys themselves.
func keyID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return string(sum[:16])
}

// counter is a set of named semaphores of the same size.
type counter struct {
	mu  sync.Mutex
	max int
	n   map[string]int
}

func newCounter(max int) *counter { return &counter{max: max, n: map[string]int{}} }

func (c *counter) acquire(k string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n[k] >= c.max {
		return false
	}
	c.n[k]++
	return true
}

func (c *counter) release(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n[k] <= 1 {
		delete(c.n, k) // an address seen once is not remembered for ever
		return
	}
	c.n[k]--
}

func (c *counter) count(k string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[k]
}

// addressBucket is what a client address is counted under, grouped as the
// invalid-key throttle groups it (auth/gateway.go): an IPv6 client is normally
// handed a whole /64, so counting single addresses would let it pick a fresh
// one for every connection.
func addressBucket(ip string) string {
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

// loopbackHost is an address the per-address cap does not apply to: this
// machine, whose one address is shared by every process on it and by anything
// forwarding connections to the gateway, so capping it would let one of them
// lock out the rest. The global and pre-authentication caps still apply.
func loopbackHost(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Unmap().IsLoopback()
}

// envPositive reads a positive integer setting, or returns def.
func envPositive(name string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(brand.Getenv(name))); err == nil && n > 0 {
		return n
	}
	return def
}

// fraction is num/den of total, at least 1.
func fraction(total, num, den int) int {
	if n := total * num / den; n >= 1 {
		return n
	}
	return 1
}

// maxPreauthConns is FOX_GATEWAY_MAX_PREAUTH_CONNS, or half the global cap
// (48 by default). Authenticating takes milliseconds, so even a whole pool
// reconnecting at once fits.
func maxPreauthConns(total int) int {
	return envPositive("GATEWAY_MAX_PREAUTH_CONNS", fraction(total, 1, 2))
}

// maxConnsPerIP is FOX_GATEWAY_MAX_CONNS_PER_IP, or two thirds of the global
// cap (64 by default).
func maxConnsPerIP(total int) int {
	return envPositive("GATEWAY_MAX_CONNS_PER_IP", fraction(total, 2, 3))
}

// maxConnsPerKey is FOX_GATEWAY_MAX_CONNS_PER_KEY, or two thirds of the global
// cap (64 by default).
func maxConnsPerKey(total int) int {
	return envPositive("GATEWAY_MAX_CONNS_PER_KEY", fraction(total, 2, 3))
}

// sessionIdleTimeout is FOX_GATEWAY_IDLE_TIMEOUT: how long an authenticated
// session may go with neither the client nor the branch sending anything
// before the gateway closes it. Off by default, because applications keep
// pooled connections open and silent for hours and expect them to work. A Go
// duration ("30m") or a number of seconds; zero or unset is off.
func sessionIdleTimeout() time.Duration {
	v := strings.TrimSpace(brand.Getenv("GATEWAY_IDLE_TIMEOUT"))
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n <= 0 {
			return 0
		}
		return time.Duration(n) * time.Second
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		if err != nil {
			log.Printf("%s=%q is not a duration — idle timeout off", brand.EnvName("GATEWAY_IDLE_TIMEOUT"), v)
		}
		return 0
	}
	return d
}

// TCP keepalive on client connections, so a client that vanished without
// closing (a laptop that slept, a NAT that forgot the mapping) gives its slot
// back in minutes rather than holding it until the idle timeout, which is off
// by default.
var clientKeepAlive = net.KeepAliveConfig{
	Enable:   true,
	Idle:     60 * time.Second,
	Interval: 15 * time.Second,
	Count:    4,
}

// recovered is deferred at the root of every goroutine the gateway starts. A
// panic there would otherwise end the process and every session with it; this
// logs it, closes what that goroutine was serving, and lets the rest carry on.
// It must be the deferred function itself, since recover only works there.
func recovered(what string, closers ...io.Closer) {
	r := recover()
	if r == nil {
		return
	}
	log.Printf("gateway: panic in %s: %v\n%s", what, r, debug.Stack())
	for _, c := range closers {
		if c != nil {
			_ = c.Close()
		}
	}
}

// pipe relays a session in both directions until either side closes. With an
// idle timeout, it also closes the session once neither side has sent
// anything for that long; without one it is a plain copy each way.
func pipe(client, backend net.Conn, idle time.Duration) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{}, 2)
	half := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		defer recovered("session relay", client, backend)
		if idle <= 0 {
			_, _ = io.Copy(dst, src)
			return
		}
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go half(backend, client)
	go half(client, backend)
	if idle <= 0 {
		<-done
		return
	}
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-done:
			return
		case <-timer.C:
			quiet := time.Since(time.Unix(0, last.Load()))
			if quiet < idle {
				timer.Reset(idle - quiet)
				continue
			}
			log.Printf("gateway: closing a session idle for %s", quiet.Round(time.Second))
			// Postgres's own words for its idle_session_timeout, so a client
			// that reads the error knows to reconnect rather than retry.
			sendError(client, "57P05", "terminating connection due to idle-session timeout")
			_ = client.Close()
			_ = backend.Close()
			<-done
			return
		}
	}
}
