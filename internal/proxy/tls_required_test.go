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
	if maxConns() != 1000 {
		t.Errorf("default = %d, want 1000", maxConns())
	}
	t.Setenv("FOX_GATEWAY_MAX_CONNS", "25")
	if maxConns() != 25 {
		t.Errorf("FOX_GATEWAY_MAX_CONNS=25 gave %d", maxConns())
	}
}
