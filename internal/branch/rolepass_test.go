// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every login role has its own password, none of them the install secret
// (audit v2 G10).
func TestRolePasswordsAreDistinct(t *testing.T) {
	seen := map[string]string{"install secret": pgPass()}
	for what, pw := range map[string]string{
		"db_client":         ClientRolePassword(),
		"alice@x.com":       UserRolePassword("alice@x.com"),
		"bob@x.com":         UserRolePassword("bob@x.com"),
		"agent-a (agent)":   AgentRolePassword("agent-a"),
		"alice@x.com again": UserRolePassword("alice@x.com"),
	} {
		if what == "alice@x.com again" {
			if pw != UserRolePassword("alice@x.com") {
				t.Error("a role's password is not stable")
			}
			continue
		}
		for other, opw := range seen {
			if pw == opw {
				t.Errorf("%s has the same password as %s", what, other)
			}
		}
		seen[what] = pw
	}
}

// The superuser password, and the object store's secret key, are never an argument on a command line: the engine
// hands it to docker in an env file (pgenv.go). A new call site that passes it
// with -e would put it back in the process list.
func TestNoPasswordOnCommandLines(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "pgenv.go" || f == "target.go" { // these write the env files
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, `"PGPASSWORD=`) || strings.Contains(line, `"POSTGRES_PASSWORD=`) ||
				strings.Contains(line, `"AWS_SECRET_ACCESS_KEY=`) || strings.Contains(line, `"MINIO_ROOT_PASSWORD=`) {
				t.Errorf("%s:%d passes a password as an argument: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// A branch deleted and made again is a fresh clone with only the roles main had
// when it was cloned, so what this process remembers about its roles must go
// with it. Otherwise the engine skips creating an account's role there and
// Postgres reports the login as a wrong password.
func TestRecreatingABranchForgetsItsRoles(t *testing.T) {
	ensuredRoles.Store("dev\x00a@x.com", struct{}{})
	ensuredRoles.Store("dev2\x00a@x.com", struct{}{})
	appRoleSynced.Store("dev", struct{}{})
	forgetBranchRoles("dev")
	if _, ok := ensuredRoles.Load("dev\x00a@x.com"); ok {
		t.Error("the re-made branch still remembers its per-user role")
	}
	if _, ok := appRoleSynced.Load("dev"); ok {
		t.Error("the re-made branch still remembers its client role")
	}
	if _, ok := ensuredRoles.Load("dev2\x00a@x.com"); !ok {
		t.Error("another branch's roles were forgotten too")
	}
}
