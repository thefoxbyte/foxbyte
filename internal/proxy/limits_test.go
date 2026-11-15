// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// from is a connection that appears to come from ip.
func from(ip string) net.Conn {
	remote, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(ip, "50000"))
	return addrConn{remote: remote}
}

func TestPerAddressCap(t *testing.T) {
	g := newGatewayLimits(20, 20, 2, 20)
	a, _ := g.admit(from("203.0.113.7"))
	b, _ := g.admit(from("203.0.113.7"))
	if a == nil || b == nil {
		t.Fatal("refused under the per-address cap")
	}
	if tk, msg := g.admit(from("203.0.113.7")); tk != nil || !strings.Contains(msg, "this address") {
		t.Fatalf("third from one address: %v %q", tk, msg)
	}
	if tk, _ := g.admit(from("203.0.113.8")); tk == nil {
		t.Fatal("another address was refused")
	}
	// A refusal holds nothing, and closing gives the address its slot back.
	a.release()
	a.release() // twice is harmless
	if tk, _ := g.admit(from("203.0.113.7")); tk == nil {
		t.Fatal("not admitted after one closed")
	}
	if n := len(g.slots); n != 3 {
		t.Fatalf("global slots held = %d, want 3", n)
	}
}

func TestPerAddressCapGroupsIPv6By64(t *testing.T) {
	g := newGatewayLimits(20, 20, 2, 20)
	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2:aaaa::9"} {
		if tk, _ := g.admit(from(ip)); tk == nil {
			t.Fatalf("%s refused", ip)
		}
	}
	if tk, _ := g.admit(from("2001:db8:1:2:ffff::1")); tk != nil {
		t.Fatal("a third address in the same /64 was admitted")
	}
	if tk, _ := g.admit(from("2001:db8:1:3::1")); tk == nil {
		t.Fatal("the next /64 was refused")
	}
}

func TestLoopbackIsExemptFromThePerAddressCap(t *testing.T) {
	g := newGatewayLimits(20, 20, 1, 20)
	for i := 0; i < 5; i++ {
		for _, ip := range []string{"127.0.0.1", "::1"} {
			if tk, msg := g.admit(from(ip)); tk == nil {
				t.Fatalf("loopback %s refused on connection %d: %s", ip, i, msg)
			}
		}
	}
	// It still counts against the global cap.
	if len(g.slots) != 10 {
		t.Fatalf("global slots held = %d, want 10", len(g.slots))
	}
}

func TestPreauthCap(t *testing.T) {
	g := newGatewayLimits(20, 2, 20, 20)
	a, _ := g.admit(from("203.0.113.1"))
	b, _ := g.admit(from("203.0.113.2"))
	if a == nil || b == nil {
		t.Fatal("refused under the pre-authentication cap")
	}
	if tk, msg := g.admit(from("203.0.113.3")); tk != nil || !strings.Contains(msg, "authenticate") {
		t.Fatalf("third unauthenticated: %v %q", tk, msg)
	}
	if g.perIP.count("203.0.113.3") != 0 || len(g.slots) != 2 {
		t.Fatal("a refused connection kept a slot")
	}
	a.authenticated() // a's client sent a good key
	c, _ := g.admit(from("203.0.113.3"))
	if c == nil {
		t.Fatal("not admitted after another authenticated")
	}
	a.release() // releasing an authenticated session gives back no pre-auth slot it no longer holds
	if len(g.preauth) != 2 || len(g.slots) != 2 {
		t.Fatalf("preauth %d, slots %d, want 2 and 2", len(g.preauth), len(g.slots))
	}
}

func TestGlobalCapRefusesAndReleases(t *testing.T) {
	g := newGatewayLimits(1, 1, 5, 5)
	a, _ := g.admit(from("203.0.113.1"))
	if tk, msg := g.admit(from("203.0.113.2")); tk != nil || msg != "too many connections to the gateway — try again shortly" {
		t.Fatalf("over the global cap: %v %q", tk, msg)
	}
	if g.perIP.count("203.0.113.2") != 0 {
		t.Fatal("refused connection kept its address slot")
	}
	a.release()
	if tk, _ := g.admit(from("203.0.113.2")); tk == nil {
		t.Fatal("not admitted after release")
	}
}

func TestLimitDefaults(t *testing.T) {
	for _, k := range []string{"FOX_GATEWAY_MAX_PREAUTH_CONNS", "FOX_GATEWAY_MAX_CONNS_PER_IP", "FOX_GATEWAY_MAX_CONNS_PER_KEY"} {
		t.Setenv(k, "")
	}
	// Under the global cap of 96, and far above a pool of 10 to 20.
	if maxPreauthConns(96) != 48 || maxConnsPerIP(96) != 64 || maxConnsPerKey(96) != 64 {
		t.Fatalf("defaults %d %d %d", maxPreauthConns(96), maxConnsPerIP(96), maxConnsPerKey(96))
	}
	if maxPreauthConns(1) != 1 || maxConnsPerIP(1) != 1 {
		t.Fatal("a cap of 1 must leave room for one connection")
	}
	t.Setenv("FOX_GATEWAY_MAX_CONNS_PER_IP", "7")
	t.Setenv("FOX_GATEWAY_MAX_CONNS_PER_KEY", "-3")
	if maxConnsPerIP(96) != 7 || maxConnsPerKey(96) != 64 {
		t.Fatalf("overrides %d %d", maxConnsPerIP(96), maxConnsPerKey(96))
	}
}

func TestSessionIdleTimeoutSetting(t *testing.T) {
	for v, want := range map[string]time.Duration{
		"": 0, "0": 0, "-5": 0, "junk": 0, "90": 90 * time.Second, "30m": 30 * time.Minute,
	} {
		t.Setenv("FOX_GATEWAY_IDLE_TIMEOUT", v)
		if got := sessionIdleTimeout(); got != want {
			t.Errorf("%q = %s, want %s", v, got, want)
		}
	}
}

// A key is held to its own cap only once it has proved real, and a closed
// session gives its place back.
func TestPerKeyCap(t *testing.T) {
	store, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x", SignupOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.CreateUser("k@example.com", "a-long-password-1")
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := store.CreateAPIKey(u.ID, "app")
	if err != nil {
		t.Fatal(err)
	}
	prevStore, prevTLS, prevRun := authStore, tlsConfig, ensureRunning
	authStore, tlsConfig = store, testTLSConfig(t)
	ensureRunning = func(string) (string, error) { return "", errors.New("no branch here") }
	defer func() { authStore, tlsConfig, ensureRunning = prevStore, prevTLS, prevRun }()

	g := newGatewayLimits(20, 20, 20, 1)
	held, _ := g.admit(from("203.0.113.1"))
	if !held.admitKey(key) { // a session already open with this key
		t.Fatal("first session refused")
	}
	tk, _ := g.admit(from("203.0.113.2"))
	if _, code := connectHolding(t, "203.0.113.2", key, tk); code != "53300" {
		t.Fatalf("second session with the key: code %q, want 53300", code)
	}
	tk.release()
	// An invalid key is not counted against anything.
	tk, _ = g.admit(from("203.0.113.2"))
	if _, code := connectHolding(t, "203.0.113.2", "key_nonsense", tk); code != "28P01" {
		t.Fatalf("invalid key: code %q", code)
	}
	tk.release()

	held.release()
	tk, _ = g.admit(from("203.0.113.2"))
	// Past every cap, it goes on to route the branch, which the stub refuses.
	if _, code := connectHolding(t, "203.0.113.2", key, tk); code == "53300" || code == "" {
		t.Fatalf("after the first closed: code %q", code)
	}
	if g.perKey.count(keyID(key)) != 1 || len(g.preauth) != 0 {
		t.Fatalf("while open: key count %d, preauth %d", g.perKey.count(keyID(key)), len(g.preauth))
	}
	tk.release()
	if g.perKey.count(keyID(key)) != 0 || len(g.slots) != 0 {
		t.Fatal("closing did not give the key's place back")
	}
}

// A session with neither side talking is closed once the idle timeout passes,
// and the client is told why.
func TestIdleSessionIsClosed(t *testing.T) {
	client, gwClient := net.Pipe()
	backend, gwBackend := net.Pipe()
	defer client.Close()
	defer backend.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pipe(gwClient, gwBackend, 100*time.Millisecond)
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if got := readErrorResponse(t, client); !strings.Contains(got, "57P05") {
		t.Fatalf("idle close: %q", got)
	}
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after the error: %v, want EOF", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipe did not return")
	}
}

// Traffic in either direction keeps a session open past the idle timeout.
func TestActiveSessionIsKept(t *testing.T) {
	client, gwClient := net.Pipe()
	backend, gwBackend := net.Pipe()
	defer client.Close()
	defer backend.Close()
	go pipe(gwClient, gwBackend, 150*time.Millisecond)
	buf := make([]byte, 4)
	deadline := time.Now().Add(600 * time.Millisecond)
	for i := 0; time.Now().Before(deadline); i++ {
		src, dst := client, backend
		if i%2 == 1 {
			src, dst = backend, client
		}
		_ = dst.SetDeadline(time.Now().Add(2 * time.Second))
		go func() { _, _ = src.Write([]byte("ping")) }()
		if _, err := io.ReadFull(dst, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("round %d: %q %v", i, buf, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// listen runs serveListener with handler h on a loopback port and returns its
// address.
func listen(t *testing.T, g *gatewayLimits, h func(net.Conn, *ticket)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = serveListener(ln, g, h) }()
	return ln.Addr().String()
}

// A connection over the cap hears 53300 from the real accept loop, and the
// slot comes back when the session ends.
func TestAcceptLoopRefusesAtTheCap(t *testing.T) {
	release := make(chan struct{})
	addr := listen(t, newGatewayLimits(1, 1, 5, 5), func(c net.Conn, _ *ticket) {
		defer c.Close()
		<-release
	})

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	time.Sleep(50 * time.Millisecond) // let the loop admit it
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(3 * time.Second))
	if got := readErrorResponse(t, second); !strings.Contains(got, "53300") {
		t.Fatalf("over the cap: %q", got)
	}
	close(release)
	waitAdmitted(t, addr)
}

// waitAdmitted dials until a connection is served rather than refused.
func waitAdmitted(t *testing.T, addr string) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		b := make([]byte, 1)
		_, err = c.Read(b)
		c.Close()
		if err != nil && b[0] != 'E' { // closed by the handler, not refused
			return
		}
	}
	t.Fatal("the slot never came back")
}

// A handler that panics closes its own connection and nothing else: the
// listener keeps accepting, and the panicking session's slot is released.
func TestPanicInASessionKeepsTheGatewayUp(t *testing.T) {
	addr := listen(t, newGatewayLimits(1, 1, 5, 5), func(net.Conn, *ticket) { panic("bad packet") })

	// With room for one connection, each of these is only served if the
	// one before it gave its slot back after panicking.
	for i := 0; i < 3; i++ {
		waitAdmitted(t, addr)
	}
}
