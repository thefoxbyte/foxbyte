// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"errors"
	"net"
	"testing"
)

func TestAuthNeedsRole(t *testing.T) {
	for _, err := range []error{
		errors.New("backend refused connection: 28P01: password authentication failed"),
		errors.New("backend refused connection: 28000: role \"a@b.co\" does not exist"),
	} {
		if !authNeedsRole(err) {
			t.Errorf("%v should reprovision", err)
		}
	}
	if authNeedsRole(nil) || authNeedsRole(errors.New("connection refused")) {
		t.Error("a dial failure is not a missing role")
	}
}

// A branch deleted and created again while the gateway kept running: the
// first login is refused because the role is not on the new clone, the
// memory of it is dropped, the role is made, and the second login works.
func TestReopenIfRoleMissingProvisionsOnce(t *testing.T) {
	oldForget, oldEnsure, oldAuth := forgetLoginRole, ensureLoginRole, authenticateBackend
	t.Cleanup(func() {
		forgetLoginRole, ensureLoginRole, authenticateBackend = oldForget, oldEnsure, oldAuth
	})

	var forgot string
	var ensured int
	forgetLoginRole = func(branchName, email string) { forgot = branchName + " " + email }
	ensureLoginRole = func(branchName, email string) error {
		ensured++
		if branchName != "dev" || email != "a@b.co" {
			t.Errorf("ensured %s %s", branchName, email)
		}
		return nil
	}
	auths := 0
	authenticateBackend = func(net.Conn, map[string]string, string) error {
		auths++
		return nil
	}

	first, second := net.Pipe()
	defer second.Close()
	got, err := reopenIfRoleMissing(first, func() (net.Conn, error) {
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}, map[string]string{"user": "a@b.co"}, "pw", "dev", "a@b.co",
		errors.New("backend refused connection: 28000: role \"a@b.co\" does not exist"))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	if forgot != "dev a@b.co" || ensured != 1 || auths != 1 {
		t.Fatalf("forgot %q ensured %d second auths %d", forgot, ensured, auths)
	}
}

func TestReopenIfRoleMissingSkipsTheSharedRole(t *testing.T) {
	ensured := false
	old := ensureLoginRole
	ensureLoginRole = func(string, string) error { ensured = true; return nil }
	t.Cleanup(func() { ensureLoginRole = old })
	c, _ := net.Pipe()
	defer c.Close()
	_, err := reopenIfRoleMissing(c, nil, nil, "", "main", "", errors.New("backend refused connection: 28P01: password authentication failed"))
	if err == nil || ensured {
		t.Fatalf("err %v ensured %v", err, ensured)
	}
}
