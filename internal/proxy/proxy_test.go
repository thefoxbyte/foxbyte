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
