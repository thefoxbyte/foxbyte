// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// stubDial records the addresses dialled and fails the ones in down.
func stubDial(t *testing.T, down ...string) *[]string {
	t.Helper()
	dialled := &[]string{}
	old, oldForget := dialBackend, forgetBackends
	dialBackend = func(_, addr string, _ time.Duration) (net.Conn, error) {
		*dialled = append(*dialled, addr)
		for _, d := range down {
			if d == addr {
				return nil, errors.New("connect: no route to host")
			}
		}
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		return a, nil
	}
	t.Cleanup(func() { dialBackend, forgetBackends = old, oldForget })
	return dialled
}

// A branch another process suspended or moved leaves a remembered address that
// no longer answers. The client must not hear about that: the address is
// forgotten, the branch routed again, and the connection made.
func TestAStaleAddressIsForgottenAndRoutedAgain(t *testing.T) {
	dialled := stubDial(t, "10.0.0.1:5432")
	forgot := 0
	forgetBackends = func() { forgot++ }
	routes := 0
	conn, addr, err := connectBackend("10.0.0.1:5432", func() (string, error) {
		routes++
		return "10.0.0.2:5432", nil
	})
	if err != nil {
		t.Fatalf("a stale address reached the client: %v", err)
	}
	defer conn.Close()
	if addr != "10.0.0.2:5432" || routes != 1 || forgot != 1 {
		t.Fatalf("addr %s after %d routes and %d forgets, want the new address after one of each", addr, routes, forgot)
	}
	if len(*dialled) != 2 {
		t.Fatalf("dialled %v, want the old address and then the new one", *dialled)
	}
}

// A working address costs nothing but the dial.
func TestAGoodAddressIsNotRoutedAgain(t *testing.T) {
	stubDial(t)
	forgetBackends = func() { t.Fatal("forgot a working address") }
	conn, _, err := connectBackend("10.0.0.1:5432", func() (string, error) {
		t.Fatal("routed again after a good dial")
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

// One retry only: a backend that is really down is reported, not chased.
func TestABackendDownTwiceIsReported(t *testing.T) {
	dialled := stubDial(t, "10.0.0.1:5432")
	forgetBackends = func() {}
	_, addr, err := connectBackend("10.0.0.1:5432", func() (string, error) { return "10.0.0.1:5432", nil })
	if err == nil {
		t.Fatal("two failed dials were reported as a connection")
	}
	var refused *routeFailure
	if errors.As(err, &refused) {
		t.Fatalf("a dial failure was reported as a routing problem: %v", err)
	}
	if addr != "10.0.0.1:5432" || len(*dialled) != 2 {
		t.Fatalf("addr %q, dialled %v: want exactly two tries", addr, *dialled)
	}
}

// A retry can find the branch gone, which is a routing answer.
func TestARouteFailureOnRetryIsARoutingAnswer(t *testing.T) {
	stubDial(t, "10.0.0.1:5432")
	forgetBackends = func() {}
	gone := errors.New("branch does not exist")
	_, _, err := connectBackend("10.0.0.1:5432", func() (string, error) { return "", gone })
	var refused *routeFailure
	if !errors.As(err, &refused) || !errors.Is(refused.err, gone) {
		t.Fatalf("err = %v, want the routing failure", err)
	}
}

func TestRouteErrorCodes(t *testing.T) {
	cases := []struct {
		name    string
		standby bool
		err     error
		want    string
	}{
		{"no such branch", false, errors.New("branch does not exist"), "3D000"},
		{"masked branch being made", false, branch.ErrBranchClosed, "57P03"},
		// A docker that did not answer is not a branch that does not exist:
		// the client should come back.
		{"docker did not answer", false, branch.ErrStateUnknown, "57P03"},
		{"no standby here", true, branch.ErrNoStandbyRead, "3D000"},
		{"standby mid-rebuild", true, errors.New("rebuilding"), "57P03"},
	}
	for _, c := range cases {
		if got := routeErrorCode(c.standby, c.err); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
