// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"testing"
)

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"main", "standby", "agent-a1", "feature_x", "v1.2", "A", "import-db"} {
		if err := checkName(ok); err != nil {
			t.Errorf("checkName(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range []string{"", "..", "x/../main", "main@for-x", "-rf", ".hidden", "a b", "a..b",
		"x/y", "a\x00b", string(make([]byte, 64))} {
		if err := checkName(bad); !errors.Is(err, ErrBadName) {
			t.Errorf("checkName(%q) = %v, want ErrBadName", bad, err)
		}
	}
}

// Every engine entry point that acts on a name refuses a bad one before it
// runs anything.
func TestLifecycleRefusesBadNames(t *testing.T) {
	const bad = "x/../main"
	for what, err := range map[string]error{
		"Create":            Create(bad, "main"),
		"Create --from":     Create("ok", bad),
		"Delete":            Delete(bad),
		"Reset":             Reset(bad, "main"),
		"Suspend":           Suspend(bad),
		"Wake":              Wake(bad),
		"DeleteAgentBranch": DeleteAgentBranch("../main"),
	} {
		if !errors.Is(err, ErrBadName) {
			t.Errorf("%s(%q): %v, want ErrBadName", what, bad, err)
		}
	}
	if Exists(bad) {
		t.Error("Exists accepted a bad name")
	}
}

func TestPublishedPublicly(t *testing.T) {
	for out, want := range map[string]bool{
		"9000/tcp -> 0.0.0.0:9000\n9001/tcp -> 0.0.0.0:9001":     true,
		"9000/tcp -> [::]:9000":                                  true,
		"9000/tcp -> :::9000":                                    true,
		"9000/tcp -> 127.0.0.1:9000\n9001/tcp -> 127.0.0.1:9001": false,
		"": false,
	} {
		if got := publishedPublicly(out); got != want {
			t.Errorf("publishedPublicly(%q) = %v, want %v", out, got, want)
		}
	}
}

func TestPublishedPortsAreLoopback(t *testing.T) {
	if got := loopbackPort("5433", "5432"); got != "127.0.0.1:5433:5432" {
		t.Errorf("loopbackPort = %q", got)
	}
	for _, a := range standbyRunArgs("/x") {
		if a == "-p" {
			t.Error("the standby publishes a host port; the Gateway reaches it over the docker network")
		}
	}
}
