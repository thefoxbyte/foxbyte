// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"net"
	"testing"
)

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

func TestNeedsTLS(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:50000": false, // this machine: psql in the VM, the suites
		"[::1]:50000":     false,
		"10.0.0.9:50000":  true, // another machine sending an API key
		"172.17.0.3:5000": true,
	} {
		tcp, _ := net.ResolveTCPAddr("tcp", addr)
		if got := needsTLS(addrConn{remote: tcp}); got != want {
			t.Errorf("plaintext from %s: needsTLS = %v, want %v", addr, got, want)
		}
	}
}

func TestMaxConns(t *testing.T) {
	t.Setenv("FOX_GATEWAY_MAX_CONNS", "")
	// Stock Postgres: 100 total, 3 reserved for superusers, one under that so
	// the gateway's 53300 is the error a client sees.
	if maxConns() != 96 {
		t.Errorf("default = %d, want 96", maxConns())
	}
	t.Setenv("FOX_GATEWAY_MAX_CONNS", "25")
	if maxConns() != 25 {
		t.Errorf("FOX_GATEWAY_MAX_CONNS=25 gave %d", maxConns())
	}
}

func TestConnectionCapStaysUnderTheSuperuserReserve(t *testing.T) {
	if got := ConnectionCap(100, 3); got != 96 {
		t.Errorf("stock = %d, want 96", got)
	}
	if got := ConnectionCap(20, 3); got != 16 {
		t.Errorf("20/3 = %d, want 16", got)
	}
	if got := ConnectionCap(0, 3); got != 96 {
		t.Errorf("unknown max = %d, want the stock cap", got)
	}
	if got := ConnectionCap(100, 0); got != 99 {
		t.Errorf("no reserve = %d, want 99", got)
	}
	if got := ConnectionCap(2, 5); got != 1 {
		t.Errorf("reserve larger than max = %d, want 1", got)
	}
}
