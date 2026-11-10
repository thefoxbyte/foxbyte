// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A branch the gateway's reaper suspended leaves the console holding an address
// that no longer answers. The console routes again rather than showing an error.
func TestConsoleRecoversFromAStaleAddress(t *testing.T) {
	oldConnect, oldRoute := pgConnect, sessionRoute
	t.Cleanup(func() { pgConnect, sessionRoute = oldConnect, oldRoute })

	var hosts []string
	pgConnect = func(_ context.Context, c *pgx.ConnConfig) (*pgx.Conn, error) {
		hosts = append(hosts, c.Host)
		if c.Host == "10.0.0.1" {
			return nil, &net.OpError{Op: "dial", Err: errors.New("no route to host")}
		}
		return nil, nil
	}
	sessionRoute = func(string) (string, error) { return "10.0.0.2:5432", nil }

	cfg, err := pgx.ParseConfig("postgres://u:p@10.0.0.1:5432/d")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectSession(context.Background(), cfg, "dev"); err != nil {
		t.Fatalf("a stale address reached the user: %v", err)
	}
	if len(hosts) != 2 || hosts[1] != "10.0.0.2" {
		t.Fatalf("connected to %v, want the old address and then the new one", hosts)
	}
}

// An answer from a backend that is there is not a stale address.
func TestConsoleDoesNotRetryAnAnswer(t *testing.T) {
	oldConnect, oldRoute := pgConnect, sessionRoute
	t.Cleanup(func() { pgConnect, sessionRoute = oldConnect, oldRoute })
	calls := 0
	refused := errors.New("password authentication failed")
	pgConnect = func(context.Context, *pgx.ConnConfig) (*pgx.Conn, error) { calls++; return nil, refused }
	sessionRoute = func(string) (string, error) { t.Fatal("routed again after an answer"); return "", nil }
	cfg, _ := pgx.ParseConfig("postgres://u:p@10.0.0.1:5432/d")
	if _, err := connectSession(context.Background(), cfg, "dev"); !errors.Is(err, refused) || calls != 1 {
		t.Fatalf("err %v after %d connects", err, calls)
	}
}

// The check has to recognise the error pgx really returns, not just one built
// to look like it.
func TestIsDialFailureOnARealRefusal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = pgx.Connect(ctx, "postgres://u:p@"+addr+"/d?sslmode=disable")
	if err == nil {
		t.Skip("something answered on a closed port")
	}
	if !isDialFailure(err) {
		t.Fatalf("not recognised as a dial failure: %T %v", err, err)
	}
}
