// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
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

// Any account could name a branch "standby", and making it began by removing
// the live HA standby's container.
func TestCheckNewNameRefusesEngineNames(t *testing.T) {
	for _, n := range []string{"main", "standby", "restore", "restore-check", "agent-zz", "agent-",
		"main-before-606", "x-before-y", "Standby", "AGENT-zz", "X-Before-1"} {
		if err := CheckNewName(n); !errors.Is(err, ErrReservedName) {
			t.Errorf("CheckNewName(%q) = %v, want ErrReservedName", n, err)
		}
	}
	for _, n := range []string{"qa", "feature-123", "import-db", "agents", "mainline", "standby2", "restored", "before", "x-before"} {
		if err := CheckNewName(n); err != nil {
			t.Errorf("CheckNewName(%q) = %v, want ok", n, err)
		}
	}
	if err := CheckNewName("x/../main"); !errors.Is(err, ErrBadName) {
		t.Errorf("a bad name: %v, want ErrBadName", err)
	}
	// The floor under the engine's own names is not raised.
	for _, n := range []string{"main", "standby", "restore", "restore-check", "agent-zz", "main-before-606"} {
		if err := checkName(n); err != nil {
			t.Errorf("checkName(%q) = %v: the engine uses this name", n, err)
		}
	}
}

// Each way a name comes in from outside is refused before anything is run, so
// these need no Docker.
func TestNewNameEntryPointsRefuseEngineNames(t *testing.T) {
	p := &Progress{}
	check := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrReservedName) {
			t.Errorf("%s: %v, want ErrReservedName", what, err)
		}
	}
	_, err := ImportToAs(p, "postgres://h/d", "standby", As{})
	check("import target", err)
	_, err = ImportToAs(p, "mongodb://h/d", "main-before-3", As{})
	check("mongodb target", err)
	_, err = ImportReaderToAs(p, strings.NewReader(""), srcSQL, "x.sql", "agent-zz", As{})
	check("upload target", err)
	_, err = ImportContinuousToAs(p, "postgres://h/d", "restore-check", As{})
	check("continuous target", err)
}

func TestCheckNoContainer(t *testing.T) {
	if err := checkNoContainer("qa", "absent"); err != nil {
		t.Errorf("no container: %v", err)
	}
	for _, state := range []string{"running", "exited", "created"} {
		if err := checkNoContainer("standby", state); !errors.Is(err, ErrBranchExists) {
			t.Errorf("a %s container: %v, want ErrBranchExists", state, err)
		}
	}
}

// branch-before makes the *-before-* names, so it must keep accepting them,
// and it now refuses the name it had missed.
func TestBeforeNameFollowsEngineNames(t *testing.T) {
	if err := validateBeforeName("restore-check"); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("restore-check: %v", err)
	}
	if err := validateBeforeName("main-before-12"); err != nil {
		t.Errorf("main-before-12: %v", err)
	}
}
