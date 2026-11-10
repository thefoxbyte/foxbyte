// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBuildParseStartupRoundtrip(t *testing.T) {
	in := map[string]string{"user": "foxbyte", "database": "qa", "application_name": "psql"}
	msg := buildStartup(in)

	if int(binary.BigEndian.Uint32(msg[:4])) != len(msg) {
		t.Fatalf("length prefix %d != actual %d", binary.BigEndian.Uint32(msg[:4]), len(msg))
	}
	if binary.BigEndian.Uint32(msg[4:8]) != codeStartup30 {
		t.Fatalf("wrong protocol version code")
	}
	got := parseParams(msg[8:])
	for k, v := range in {
		if got[k] != v {
			t.Errorf("param %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestReadStartupSkipsSSL(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	errc := make(chan error, 1)
	go func() {
		ssl := make([]byte, 8)
		binary.BigEndian.PutUint32(ssl[0:], 8)
		binary.BigEndian.PutUint32(ssl[4:], codeSSL)
		if _, err := client.Write(ssl); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 1)
		if _, err := client.Read(buf); err != nil {
			errc <- err
			return
		}
		if buf[0] != 'N' {
			errc <- fmt.Errorf("expected 'N' after SSLRequest, got %q", buf[0])
			return
		}
		_, err := client.Write(buildStartup(map[string]string{"user": "u", "database": "main"}))
		errc <- err
	}()

	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	_, params, err := readStartup(server)
	if err != nil {
		t.Fatalf("readStartup: %v", err)
	}
	if params["database"] != "main" {
		t.Fatalf("database = %q, want main", params["database"])
	}
	if err := <-errc; err != nil {
		t.Fatalf("client goroutine: %v", err)
	}
}

// When TLS is configured, an SSLRequest is answered 'S', the connection is
// upgraded, and the StartupMessage is read over the encrypted conn — the path
// that lets sslmode=require clients connect.
func TestReadStartupUpgradesTLS(t *testing.T) {
	prev := tlsConfig
	tlsConfig = testTLSConfig(t)
	defer func() { tlsConfig = prev }()

	client, server := net.Pipe()
	defer client.Close()

	errc := make(chan error, 1)
	go func() {
		ssl := make([]byte, 8)
		binary.BigEndian.PutUint32(ssl[0:], 8)
		binary.BigEndian.PutUint32(ssl[4:], codeSSL)
		if _, err := client.Write(ssl); err != nil {
			errc <- err
			return
		}
		buf := make([]byte, 1)
		if _, err := client.Read(buf); err != nil {
			errc <- err
			return
		}
		if buf[0] != 'S' {
			errc <- fmt.Errorf("expected 'S' after SSLRequest with TLS enabled, got %q", buf[0])
			return
		}
		tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			errc <- fmt.Errorf("client handshake: %w", err)
			return
		}
		_, err := tc.Write(buildStartup(map[string]string{"user": "u", "database": "qa"}))
		errc <- err
	}()

	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	upgraded, params, err := readStartup(server)
	if err != nil {
		t.Fatalf("readStartup: %v", err)
	}
	if _, ok := upgraded.(*tls.Conn); !ok {
		t.Fatalf("expected returned conn to be *tls.Conn, got %T", upgraded)
	}
	if params["database"] != "qa" {
		t.Fatalf("database = %q, want qa", params["database"])
	}
	if err := <-errc; err != nil {
		t.Fatalf("client goroutine: %v", err)
	}
}

// testTLSConfig builds an in-memory self-signed server config for the TLS path.
func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// A CancelRequest is recognized in the startup phase and handled (forwarded to
// the owning backend), so handle() returns without opening a session.
func TestReadStartupHandlesCancel(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		pkt := make([]byte, 16)
		binary.BigEndian.PutUint32(pkt[0:], 16)
		binary.BigEndian.PutUint32(pkt[4:], codeCancel)
		binary.BigEndian.PutUint32(pkt[8:], 12345)  // pid
		binary.BigEndian.PutUint32(pkt[12:], 67890) // secret (unknown key -> no-op)
		_, _ = client.Write(pkt)
	}()

	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	_, _, err := readStartup(server)
	if !errors.Is(err, errHandledCancel) {
		t.Fatalf("expected errHandledCancel for a CancelRequest, got %v", err)
	}
}

func TestSendError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		sendError(server, "3D000", "boom")
		server.Close()
	}()
	got, _ := io.ReadAll(client)
	if len(got) == 0 || got[0] != 'E' {
		t.Fatalf("expected an 'E' ErrorResponse, got % x", got)
	}
	if !bytes.Contains(got, []byte("boom")) {
		t.Errorf("ErrorResponse missing message text: %q", got)
	}
	if !bytes.Contains(got, []byte("3D000")) {
		t.Errorf("ErrorResponse missing SQLSTATE code: %q", got)
	}
}

// readErrorResponse reads one ErrorResponse and returns its fields as text.
func readErrorResponse(t *testing.T, c net.Conn) string {
	t.Helper()
	h := make([]byte, 5)
	if _, err := io.ReadFull(c, h); err != nil {
		t.Fatalf("reading the error: %v", err)
	}
	if h[0] != 'E' {
		t.Fatalf("expected an ErrorResponse, got %q", h[0])
	}
	body := make([]byte, binary.BigEndian.Uint32(h[1:])-4)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatalf("reading the error body: %v", err)
	}
	return string(body)
}

// A startup packet that claims too much is refused on its header alone: the
// test never sends the body, so a reader that waited for it would time out.
func TestReadStartupRefusesOversizedPacket(t *testing.T) {
	for _, n := range []uint32{maxStartupPacket + 1, 1 << 20, 1<<32 - 1, 4} {
		client, server := net.Pipe()
		_ = server.SetDeadline(time.Now().Add(3 * time.Second))
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		go func() {
			h := make([]byte, 4)
			binary.BigEndian.PutUint32(h, n)
			_, _ = client.Write(h)
		}()
		errc := make(chan error, 1)
		go func() { _, _, err := readStartup(server); errc <- err }()
		if got := readErrorResponse(t, client); !bytes.Contains([]byte(got), []byte("08P01")) {
			t.Errorf("length %d: error %q, want SQLSTATE 08P01", n, got)
		}
		if err := <-errc; err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("length %d: readStartup = %v", n, err)
		}
		client.Close()
		server.Close()
	}
}

// The largest packet Postgres itself would take still gets through.
func TestReadStartupAcceptsLargestPacket(t *testing.T) {
	params := map[string]string{"user": "u", "database": "main"}
	params["options"] = strings.Repeat("x", maxStartupPacket-len(buildStartup(params))-len("options")-2)
	pkt := buildStartup(params)
	if len(pkt) != maxStartupPacket {
		t.Fatalf("test packet is %d bytes, want %d", len(pkt), maxStartupPacket)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = client.Write(pkt) }()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	_, got, err := readStartup(server)
	if err != nil {
		t.Fatalf("readStartup: %v", err)
	}
	if got["database"] != "main" {
		t.Errorf("database = %q", got["database"])
	}
}

// startPasswordRead runs requestClientPassword against a pipe and consumes the
// AuthenticationCleartextPassword request it sends first.
func startPasswordRead(t *testing.T) (net.Conn, chan error, *string) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	errc := make(chan error, 1)
	got := new(string)
	go func() {
		var err error
		*got, err = requestClientPassword(server)
		errc <- err
	}()
	if _, err := io.ReadFull(client, make([]byte, 9)); err != nil {
		t.Fatalf("reading the auth request: %v", err)
	}
	return client, errc, got
}

// A client that has not authenticated is held to a small password message, on
// the header alone (no body is ever sent here) and with a real protocol error.
func TestPasswordMessageIsCapped(t *testing.T) {
	for _, n := range []uint32{maxPasswordMessage + 1, 1 << 24, 3} {
		client, errc, _ := startPasswordRead(t)
		h := []byte{'p', 0, 0, 0, 0}
		binary.BigEndian.PutUint32(h[1:], n)
		if _, err := client.Write(h); err != nil {
			t.Fatal(err)
		}
		if got := readErrorResponse(t, client); !bytes.Contains([]byte(got), []byte("08P01")) {
			t.Errorf("length %d: error %q, want SQLSTATE 08P01", n, got)
		}
		if err := <-errc; !errors.Is(err, errBadMsgLength) {
			t.Errorf("length %d: %v, want errBadMsgLength", n, err)
		}
	}
}

// An API key, and anything up to the limit, is still read.
func TestPasswordMessageWithinLimit(t *testing.T) {
	for _, secret := range []string{"key_" + strings.Repeat("a", 64), strings.Repeat("k", maxPasswordMessage-5)} {
		client, errc, got := startPasswordRead(t)
		if err := writeMsg(client, 'p', append([]byte(secret), 0)); err != nil {
			t.Fatal(err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("%d-byte secret: %v", len(secret), err)
		}
		if *got != secret {
			t.Errorf("read %q, want %q", *got, secret)
		}
	}
}

// The limit is the client's alone: a backend may send much larger messages.
func TestBackendMessagesKeepTheirLimit(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	body := make([]byte, maxStartupPacket*4)
	go func() { _ = writeMsg(client, 'S', body) }()
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	typ, got, err := readMsg(server)
	if err != nil || typ != 'S' || len(got) != len(body) {
		t.Fatalf("readMsg: %q, %d bytes, %v", typ, len(got), err)
	}
}

// A SASLContinue too short to hold its code used to index out of range.
func TestScramRefusesShortSASLContinue(t *testing.T) {
	for _, short := range [][]byte{{}, {0, 0, 11}} {
		gateway, backend := net.Pipe()
		_ = gateway.SetDeadline(time.Now().Add(3 * time.Second))
		_ = backend.SetDeadline(time.Now().Add(3 * time.Second))
		go func() {
			_, _, _ = readMsg(backend) // SASLInitialResponse
			_ = writeMsg(backend, 'R', short)
		}()
		if err := scramSHA256(gateway, []byte("SCRAM-SHA-256\x00\x00"), "pw"); err == nil {
			t.Errorf("a %d-byte SASLContinue was accepted", len(short))
		}
		gateway.Close()
		backend.Close()
	}
}
