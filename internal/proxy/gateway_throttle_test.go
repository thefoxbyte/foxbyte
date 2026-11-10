// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// connectFrom runs one connection through handle from a public address, over
// TLS as any such client must be, and returns what the Gateway answered first
// and the SQLSTATE it finally refused with.
func connectFrom(t *testing.T, ip, password string) (first byte, code string) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		remote, _ := net.ResolveTCPAddr("tcp", ip+":50000")
		handle(addrConn{Conn: server, remote: remote})
	}()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	ssl := make([]byte, 8)
	binary.BigEndian.PutUint32(ssl[0:], 8)
	binary.BigEndian.PutUint32(ssl[4:], codeSSL)
	if _, err := client.Write(ssl); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, ssl[:1]); err != nil || ssl[0] != 'S' {
		t.Fatalf("SSLRequest: %q %v", ssl[0], err)
	}
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
	if _, err := tc.Write(buildStartup(map[string]string{"user": "u", "database": "main"})); err != nil {
		t.Fatal(err)
	}
	typ, body, err := readMsg(tc)
	if err != nil {
		t.Fatal(err)
	}
	first = typ
	if typ == 'R' { // the password asked for
		if err := writeMsg(tc, 'p', append([]byte(password), 0)); err != nil {
			t.Fatal(err)
		}
		if typ, body, err = readMsg(tc); err != nil {
			t.Fatal(err)
		}
	}
	if typ == 'E' {
		for _, f := range bytes.Split(body, []byte{0}) {
			if len(f) > 1 && f[0] == 'C' {
				code = string(f[1:])
			}
		}
	}
	<-done
	return first, code
}

// The whole refusal path through handle: invalid keys coalesce into one event,
// an address that has used up its failures is turned away before it is even
// asked for a key, and another address is still asked.
func TestGatewayThrottlesInvalidKeys(t *testing.T) {
	store, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prevStore, prevTLS := authStore, tlsConfig
	authStore, tlsConfig = store, testTLSConfig(t)
	defer func() { authStore, tlsConfig = prevStore, prevTLS }()

	const attacker = "203.0.113.7"
	attempts := 0
	for ; attempts < 200; attempts++ {
		first, code := connectFrom(t, attacker, "key_nonsense")
		if first != 'R' {
			if first != 'E' || code != "28000" {
				t.Fatalf("attempt %d: first answer %q, code %q", attempts, first, code)
			}
			break
		}
		if code != "28P01" {
			t.Fatalf("attempt %d: code %q, want 28P01", attempts, code)
		}
	}
	if attempts == 200 {
		t.Fatal("never throttled")
	}
	if first, code := connectFrom(t, "203.0.113.8", "key_nonsense"); first != 'R' || code != "28P01" {
		t.Fatalf("another address: first %q, code %q", first, code)
	}
	evs, err := store.SecurityEvents(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.Kind == auth.EvGatewayRefused && e.IP == attacker {
			n++
		}
	}
	if n != 1 || len(evs) != 2 {
		t.Fatalf("after %d refusals from one address: %d events for it, %d in all, want 1 and 2", attempts, n, len(evs))
	}
}
