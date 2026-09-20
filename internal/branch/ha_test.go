// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
)

func TestSuspendRefusal(t *testing.T) {
	cases := []struct {
		name, primary string
		ha, refused   bool
	}{
		{"main", "pg-main", false, true},
		{"feature", "pg-main", true, false},
		{"standby", "pg-main", true, true},     // the HA standby
		{"standby", "pg-main", false, false},   // no HA: just a branch with that name
		{"standby", "pg-standby", true, true},  // serving main after a failover
		{"main", "pg-standby", true, true},     // the stepped-down old main
		{"feature", "pg-standby", true, false}, // ordinary branches stay suspendable
	}
	for _, c := range cases {
		err := suspendRefusal(c.name, c.primary, c.ha)
		if (err != nil) != c.refused {
			t.Errorf("suspendRefusal(%q, %q, ha=%v) = %v, want refused=%v", c.name, c.primary, c.ha, err, c.refused)
		}
	}
}

func TestHAGuard(t *testing.T) {
	for _, action := range []string{"enable", "disable", "failover"} {
		if err := haGuard(action, "pg-main"); err != nil {
			t.Errorf("%s with main as primary: %v", action, err)
		}
		err := haGuard(action, "pg-standby")
		if err == nil || !strings.Contains(err.Error(), "fox ha failback") {
			t.Errorf("%s after a failover = %v, want a refusal pointing to failback", action, err)
		}
	}
	if err := haGuard("failback", "pg-main"); err == nil {
		t.Error("failback without a failover was allowed")
	}
	if err := haGuard("failback", "pg-standby"); err != nil {
		t.Errorf("failback after a failover: %v", err)
	}
}

func TestPrimaryPointerGuards(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if got := PrimaryContainer(); got != "pg-main" {
		t.Fatalf("fresh install primary = %q", got)
	}
	if err := setPrimary("standby"); err != nil {
		t.Fatal(err)
	}
	if got := PrimaryContainer(); got != "pg-standby" {
		t.Fatalf("after failover primary = %q", got)
	}
	if haGuard("disable", PrimaryContainer()) == nil || suspendRefusal("standby", PrimaryContainer(), true) == nil {
		t.Fatal("the promoted standby isn't protected")
	}
	if err := setPrimary("main"); err != nil {
		t.Fatal(err)
	}
	if haGuard("enable", PrimaryContainer()) != nil {
		t.Fatal("enable refused after failback")
	}
}

func TestLSNAtLeast(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0/3000028", "0/3000028", true},
		{"1/0", "0/FFFFFFFF", true},
		{"0/2FFFFFF", "0/3000000", false},
		{" 16/B374D848\n", "16/B374D847", true},
		{"", "0/1", false},
		{"bad", "0/1", false},
		{"0/1", "zz/1", false},
	}
	for _, c := range cases {
		if got := lsnAtLeast(c.a, c.b); got != c.want {
			t.Errorf("lsnAtLeast(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestParseControlCheckpoint(t *testing.T) {
	out := `pg_control version number:            1300
Database cluster state:               shut down
Latest checkpoint location:           0/5000060
Latest checkpoint's REDO location:    0/5000028
`
	got, err := parseControlCheckpoint(out)
	if err != nil || got != "0/5000060" {
		t.Fatalf("parseControlCheckpoint = %q, %v", got, err)
	}
	if _, err := parseControlCheckpoint("Latest checkpoint's REDO location: 0/1\n"); err == nil {
		t.Fatal("accepted output without the checkpoint location")
	}
}

// A promoted standby must archive WAL, or nothing written after a failover can
// be backed up or restored. archive_mode is a postmaster setting, so it has to
// be on the standby's own command line from the start; on (not always) means
// nothing is archived while it is still in recovery and the primary is.
func TestStandbyRunArgsArchive(t *testing.T) {
	args := strings.Join(standbyRunArgs("/data/standby"), " ")
	for _, want := range []string{
		"archive_mode=on",
		"archive_command=wal-g wal-push %p",
		"WALG_S3_PREFIX=s3://wal-archive",
		"AWS_ENDPOINT=http://minio:9000",
		"/data/standby:/var/lib/postgresql/data",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("standby args are missing %q\ngot: %s", want, args)
		}
	}
	if strings.Contains(args, "archive_mode=always") {
		t.Error("archive_mode=always would double-archive while the primary is still archiving")
	}
}
