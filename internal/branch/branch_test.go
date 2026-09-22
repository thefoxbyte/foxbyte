// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
)

func TestParsePublishedPort(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"0.0.0.0:32781\n[::]:32781", "32781", false},
		{"0.0.0.0:5432", "5432", false},
		{"", "", true},
		{"garbage", "", true},
	}
	for _, c := range cases {
		got, err := parsePublishedPort(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parsePublishedPort(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePublishedPort(%q): unexpected error %v", c.in, err)
		} else if got != c.want {
			t.Errorf("parsePublishedPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDSN(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // isolate the generated secrets file from the dev's home
	got := dsn("172.18.0.5", "5432")
	// The password is a per-install secret, so assert the shape, not the value.
	if !strings.HasPrefix(got, "postgresql://dbadmin:") ||
		!strings.HasSuffix(got, "@172.18.0.5:5432/appdb") {
		t.Errorf("dsn = %q, want postgresql://dbadmin:<pw>@172.18.0.5:5432/appdb", got)
	}
}

func TestAgentBranchName(t *testing.T) {
	if got := agentBranch("alice"); got != "agent-alice" {
		t.Errorf("agentBranch = %q, want agent-alice", got)
	}
}

func TestContainerName(t *testing.T) {
	if got := container("main"); got != "pg-main" {
		t.Errorf("container = %q, want pg-main", got)
	}
}

// Everything that reaches the object store must address it by the name the
// container actually has. Renaming the container from "minio" to objstore while
// the wal-g environment still said http://minio:9000 broke WAL archiving,
// backups and point-in-time restore at once: the host simply did not resolve.
func TestWalgEnvPointsAtTheObjectStore(t *testing.T) {
	env := s3EnvContent(localTarget())
	if !strings.Contains(env, "AWS_ENDPOINT=http://"+objStore+":9000") {
		t.Errorf("wal-g is not pointed at %q: %s", objStore, env)
	}
	if got := localTarget().Root(); got != "s3://"+walBucket {
		t.Errorf("wal-g is not pointed at the %q bucket: %s", walBucket, got)
	}
	// The endpoint is derived, not written out a second time.
	if objStoreEndpoint != "http://"+objStore+":9000" {
		t.Errorf("objStoreEndpoint = %q, which does not follow objStore = %q", objStoreEndpoint, objStore)
	}
}

// An upgraded cluster archives under its own prefix; anything else — no file,
// or contents that are not a plain segment — means the bucket's root, which is
// where every install archived before upgrades existed.
func TestWalgPrefixFor(t *testing.T) {
	root := "s3://" + walBucket
	for in, want := range map[string]string{
		"":                        root,
		"pg18-20260921t120000z\n": root + "/pg18-20260921t120000z",
		"pg18-20260921t120000z":   root + "/pg18-20260921t120000z",
		"../elsewhere":            root,
		"pg18/../../x":            root,
		"PG18":                    root, // not what the upgrade writes
	} {
		if got := walgPrefixFor(in); got != want {
			t.Errorf("walgPrefixFor(%q) = %q, want %q", in, got, want)
		}
	}
}
