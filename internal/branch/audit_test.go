// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"reflect"
	"strings"
	"testing"
)

func auditOnFor(t *testing.T) {
	t.Helper()
	if err := SetAuditOn(true); err != nil {
		t.Fatal(err)
	}
}

// The promise turning audit on rests on: with it off, every database starts
// exactly as it did, with the feed off and with it on.
func TestWithAuditOffTheArgumentsAreUnchanged(t *testing.T) {
	realtimeOff(t)
	if AuditOn() {
		t.Fatal("audit should be off in a fresh state directory")
	}
	if got := postgresArgs(false, PGMajor); got != nil {
		t.Errorf("a branch was given a command line with audit and the feed off: %q", got)
	}
	if got, want := postgresArgs(true, PGMajor), primaryArgs("replica"); !reflect.DeepEqual(got, want) {
		t.Errorf("primary args changed\n got: %q\nwant: %q", got, want)
	}
	if auditMount("feature") != nil {
		t.Error("a container was given the audit log's mount with audit off")
	}
}

// On, each database gains the start-time settings, last and once, and nothing
// it had is changed: a branch gets `postgres` and them, a primary its five and
// them.
func TestWithAuditOnEachDatabaseGainsOnlyItsStartSettings(t *testing.T) {
	realtimeOff(t)
	auditOnFor(t)

	branchArgs := postgresArgs(false, PGMajor)
	if want := append([]string{"postgres"}, auditStartArgs...); !reflect.DeepEqual(branchArgs, want) {
		t.Errorf("branch args\n got: %q\nwant: %q", branchArgs, want)
	}
	primary := postgresArgs(true, PGMajor)
	base := primaryArgs("replica")
	if !reflect.DeepEqual(primary[:len(base)], base) || !reflect.DeepEqual(primary[len(base):], auditStartArgs) {
		t.Errorf("primary args should be its own, then audit's\n got: %q", primary)
	}
	if n := strings.Count(strings.Join(primary, " "), "shared_preload_libraries="); n != 1 {
		t.Errorf("shared_preload_libraries appears %d times: %q", n, primary)
	}
	for _, want := range []string{"shared_preload_libraries=pgaudit,bb_identity", "log_destination=jsonlog",
		"log_directory=" + AuditLogDirInContainer, "log_truncate_on_rotation=on", "log_file_mode=0600"} {
		if !containsArg(primary, want) {
			t.Errorf("missing %q: %q", want, primary)
		}
	}
	if got := auditMount("feature"); !reflect.DeepEqual(got, []string{"-v", AuditDir("feature") + ":" + AuditLogDirInContainer}) {
		t.Errorf("mount: %q", got)
	}
}

// With the feed on as well, a branch keeps the feed's command line and adds
// audit's after it.
func TestAuditAndTheFeedTogether(t *testing.T) {
	realtimeOnFor(t)
	auditOnFor(t)
	got := postgresArgs(false, PGMajor)
	if got[0] != "postgres" || !containsArg(got, "wal_level=logical") || !containsArg(got, "shared_preload_libraries=pgaudit,bb_identity") {
		t.Errorf("a branch should run both: %q", got)
	}
	if n := strings.Count(strings.Join(got, " "), "postgres "); n != 1 {
		t.Errorf("`postgres` should lead once: %q", got)
	}
}

// The policy is default mode, one statement a line (ALTER SYSTEM cannot share
// a transaction), the roles after, the reload last; and turning it off resets
// exactly what it set, leaving the roles and so the tables' marks.
func TestAuditPolicy(t *testing.T) {
	sql := auditPolicySQL()
	for _, want := range []string{
		"ALTER SYSTEM SET pgaudit.log = 'ddl, role';", "ALTER SYSTEM SET pgaudit.role = 'bb_audit';",
		"ALTER SYSTEM SET pgaudit.log_statement = off;", "ALTER SYSTEM SET pgaudit.log_parameter = off;",
		"ALTER SYSTEM SET log_min_error_statement = panic;",
		"CREATE ROLE bb_audit NOLOGIN", "CREATE ROLE bb_audit_read NOLOGIN",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("the policy is missing %q", want)
		}
	}
	if !strings.HasSuffix(sql, "SELECT pg_reload_conf();\n") {
		t.Error("the policy should end with a reload")
	}
	for _, line := range strings.Split(strings.TrimSpace(sql), "\n") {
		if strings.Count(line, ";") != 1 && !strings.HasPrefix(line, "DO $$") {
			t.Errorf("one statement a line: %q", line)
		}
	}
	reset := auditResetSQL()
	for _, n := range auditSettings() {
		if !strings.Contains(reset, "ALTER SYSTEM RESET "+n+";") {
			t.Errorf("turning audit off does not reset %s", n)
		}
	}
	if len(auditSettings()) != len(auditPolicy) || strings.Contains(reset, "DROP ROLE") {
		t.Error("the reset should undo every setting and no role")
	}
}

func TestParseAuditUsage(t *testing.T) {
	s, err := parseAuditUsage("1048576\n2147483648\n")
	if err != nil || s.Used != 1<<20 || s.Quota != 2<<30 {
		t.Errorf("got %+v, %v", s, err)
	}
	for _, bad := range []string{"", "12", "x\n2", "1\ny"} {
		if _, err := parseAuditUsage(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

// The log is kept beside the branches, never among them, where a branch of the
// same name would be mistaken for it.
func TestTheAuditLogIsNotABranch(t *testing.T) {
	if strings.HasPrefix(auditDataset, datasetBase+"/") || strings.HasPrefix(auditZFSMount, mountBase+"/") {
		t.Errorf("the audit dataset %s sits among the branches (%s)", auditDataset, datasetBase)
	}
	for _, n := range []string{AuditRole, AuditReadRole} {
		if !strings.HasPrefix(n, "bb_") {
			t.Errorf("%s is a stored name and should be brand-free, under bb_", n)
		}
	}
}
