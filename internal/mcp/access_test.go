// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func TestMCPAppliesTheAccessRule(t *testing.T) {
	s, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	alice, _ := s.CreateUser("alice@x.com", "password1")
	bob, _ := s.CreateUser("bob@x.com", "password1")
	oldACL, oldMe := acl, me
	t.Cleanup(func() { acl, me = oldACL, oldMe })
	acl = access.NewWith(s, func(string) bool { return false })
	_ = acl.Own(alice, "agent-a")
	_ = acl.Own(alice, "alice-dev")

	me = identity{Actor: bob.Email, User: bob}
	for tool, args := range map[string]string{
		"run_sql":       `{"branch":"alice-dev","sql":"select 1"}`,
		"changes":       `{"branch":"alice-dev"}`,
		"delete_branch": `{"agent_id":"a"}`,
		"blackbox_diff": `{"a":"main","b":"alice-dev"}`,
	} {
		if err := checkAccess(tool, []byte(args)); err == nil || !strings.Contains(err.Error(), "no branch") {
			t.Errorf("bob %s %s: %v, want no branch", tool, args, err)
		}
	}
	if err := checkAccess("run_sql", []byte(`{"sql":"select 1"}`)); err != nil {
		t.Errorf("bob on main: %v", err)
	}
	me = identity{Actor: alice.Email, User: alice}
	if err := checkAccess("delete_branch", []byte(`{"agent_id":"a"}`)); err != nil {
		t.Errorf("alice deleting her own agent: %v", err)
	}
}

// A new install's main is read-only for an account not granted write: MCP
// says so before Postgres does, for the tool that exists to change a branch.
func TestMCPRefusesAChangeToReadOnlyMain(t *testing.T) {
	s, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bob, _ := s.CreateUser("bob@x.com", "password1")
	oldACL, oldMe := acl, me
	t.Cleanup(func() { acl, me = oldACL, oldMe })
	acl = access.NewWith(s, func(string) bool { return false })
	_ = acl.Own(bob, "bob-dev")
	me = identity{Actor: bob.Email, User: bob}

	err = checkAccess("execute_change", []byte(`{"sql":"insert into t values (1)"}`))
	if err == nil || !strings.Contains(err.Error(), "main is read-only for your account") ||
		!strings.Contains(err.Error(), "access write grant bob@x.com") {
		t.Errorf("a change to main: %v", err)
	}
	for _, args := range []string{
		`{"sql":"insert into t values (1)","dry_run":true}`, // nothing is changed
		`{"branch":"bob-dev","sql":"insert into t values (1)"}`,
	} {
		if err := checkAccess("execute_change", []byte(args)); err != nil {
			t.Errorf("%s: %v", args, err)
		}
	}
	if err := checkAccess("run_sql", []byte(`{"sql":"select 1"}`)); err != nil {
		t.Errorf("reading main: %v", err)
	}
	_ = s.GrantMainWrite(bob.ID, "admin@x.com")
	if err := checkAccess("execute_change", []byte(`{"sql":"insert into t values (1)"}`)); err != nil {
		t.Errorf("granted: %v", err)
	}
}
