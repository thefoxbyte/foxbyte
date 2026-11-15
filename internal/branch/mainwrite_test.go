// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func withMainWriteState(t *testing.T, all bool, writers ...string) {
	t.Helper()
	old := mainWriteState
	mainWriteState = func() (bool, []string, error) { return all, writers, nil }
	t.Cleanup(func() { mainWriteState = old })
}

// "all" applies only the role moves, with everybody a writer: on an install
// where nobody is a reader yet that moves nobody. "granted" first gives the
// reader what db_client may read.
func TestMainWriteSQLPerMode(t *testing.T) {
	all := MainWriteSQL(true, nil)
	if strings.Contains(all, "$mrs$") {
		t.Error(`mode "all" gives the reader grants it does not need`)
	}
	if !strings.Contains(all, "all_write boolean := true;") {
		t.Error(`mode "all" does not make everybody a writer`)
	}
	granted := MainWriteSQL(false, []string{"Bob@X.com"})
	for _, want := range []string{
		"all_write boolean := false;",
		"writers text[] := ARRAY['bob@x.com']::text[];", // matched in lower case
		"only_roles text[] := NULL::text[];",            // every account role
		"has_table_privilege('db_client', o.oid, 'SELECT')",
		"GRANT SELECT (%s) ON TABLE %s TO %I", // column grants, as on bb.schema_ledger
		"ALTER DEFAULT PRIVILEGES FOR ROLE db_client GRANT SELECT ON TABLES TO %I",
		"REVOKE CREATE ON SCHEMA public FROM PUBLIC",
		"session_replication_role', 'replica', true", // the engine's plumbing, not a recorded change
		"REVOKE db_client FROM %I",
		"GRANT db_main_reader TO %I",
		"ALTER ROLE %I SET role = db_main_reader",
		"pg_terminate_backend(pid)",
		"WITH INHERIT FALSE, SET FALSE", // an agent key stays an agent, without db_client's rights
	} {
		if !strings.Contains(granted, want) {
			t.Errorf("mode granted's SQL lacks %q", want)
		}
	}
	// db_client keeps every right it has: promotion, imports and the engine
	// log in as it. Nothing here may take a privilege from it.
	for _, bad := range []*regexp.Regexp{
		regexp.MustCompile(`REVOKE [A-Z, ]+ ON [^']* FROM db_client`),
		regexp.MustCompile(`ALTER DEFAULT PRIVILEGES[^;]* REVOKE`),
	} {
		if m := bad.FindString(granted); m != "" {
			t.Errorf("mode granted takes from db_client: %q", m)
		}
	}
	// The reader is never given anything that writes.
	for _, priv := range []string{"INSERT", "UPDATE", "DELETE", "TRUNCATE", "CREATE ON", "ALL ON"} {
		re := regexp.MustCompile(`GRANT [^']*` + priv + `[^']* TO %I', [^,]*, rd`)
		if m := re.FindString(granted); m != "" {
			t.Errorf("the reader is granted %s: %q", priv, m)
		}
	}
}

// A role is looked at only by name, and an email cannot break out of the block.
func TestMainAccessSQLOnlyRoles(t *testing.T) {
	sql := mainAccessSQL(false, nil, []string{"o'brien@x.com", "agent:a$$b@x.com"})
	if !strings.Contains(sql, "ARRAY['o''brien@x.com', ('agent:a' || chr(36) || '' || chr(36) || 'b@x.com')]::text[]") {
		t.Errorf("the role names are not quoted as values: %s", sql)
	}
	if strings.Count(sql, "$mw$") != 2 {
		t.Error("a name ended the block early")
	}
}

func TestMainWriteFor(t *testing.T) {
	withMainWriteState(t, false, "bob@x.com")
	for _, tc := range []struct {
		branch, email string
		want          bool
	}{
		{"main", "bob@x.com", true},
		{"", "BOB@x.com", true},           // "" is main; emails in any case
		{"main", "agent:bob@x.com", true}, // an agent key follows its account
		{"main", "alice@x.com", false},    // not granted (an admin is Postgres's to say)
		{"alice-dev", "alice@x.com", true},
	} {
		got, err := mainWriteFor(tc.branch, tc.email)
		if err != nil || got != tc.want {
			t.Errorf("%s on %q = %v, %v; want %v", tc.email, tc.branch, got, err, tc.want)
		}
	}
	withMainWriteState(t, true)
	if ok, _ := mainWriteFor("main", "alice@x.com"); !ok {
		t.Error(`in "all" an account may not write main`)
	}
}

// The shared roles write main, so a session that would fall back to one is
// refused for an account that may not write there, and told how to get it.
func TestMainWriteRefusal(t *testing.T) {
	withMainWriteState(t, false)
	old := isAdminOnMain
	isAdminOnMain = func(e string) bool { return e == "admin@x.com" }
	t.Cleanup(func() { isAdminOnMain = old })
	err := mainWriteRefusal("main", "agent:alice@x.com")
	if !errors.Is(err, ErrMainReadOnly) || !strings.Contains(err.Error(), "access write grant alice@x.com") {
		t.Errorf("alice on main: %v", err)
	}
	if err := mainWriteRefusal("main", "admin@x.com"); err != nil {
		t.Errorf("an admin: %v", err)
	}
	if err := mainWriteRefusal("alice-dev", "alice@x.com"); err != nil {
		t.Errorf("off main: %v", err)
	}
	mainWriteState = func() (bool, []string, error) { return false, nil, errors.New("store gone") }
	if err := mainWriteRefusal("main", "alice@x.com"); !errors.Is(err, ErrMainReadOnly) {
		t.Errorf("an unreadable store must refuse: %v", err)
	}
}

// The role SQL that runs on every login leaves a reader a reader: only
// mainAccessSQL moves a role in or out of db_client.
func TestRoleSQLLeavesAReaderAlone(t *testing.T) {
	for name, sql := range map[string]string{
		"person": userRoleSQL("bob@x.com", "pw"),
		"agent":  agentKeyRoleSQL(AgentKeyRole("bob@x.com"), "pw"),
	} {
		guard := strings.Index(sql, "m.roleid = to_regrole('"+MainReaderRole+"')")
		set := strings.Index(sql, "SET role = db_client")
		if guard < 0 || set < guard {
			t.Errorf("%s: SET role = db_client is not behind the reader check", name)
		}
	}
	// A masked reader is never main's reader too: the reader reads the real tables.
	for name, sql := range map[string]string{
		"person": maskedRoleSQL("bob@x.com", "pw"),
		"agent":  maskedAgentKeyRoleSQL(AgentKeyRole("bob@x.com"), "pw"),
	} {
		if !strings.Contains(sql, "REVOKE "+MainReaderRole+" FROM") {
			t.Errorf("%s: a masked role keeps main's reader", name)
		}
	}
}

func TestApplyMainWrite(t *testing.T) {
	withMainWriteState(t, false, "bob@x.com")
	var ran []string
	oldA, oldR := applyMainScript, mainRunning
	applyMainScript = func(sql string) error { ran = append(ran, sql); return nil }
	mainRunning = func() bool { return true }
	t.Cleanup(func() { applyMainScript, mainRunning = oldA, oldR })
	if err := ApplyMainWrite(); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMainWriteFor("Alice@x.com"); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 2 || !strings.Contains(ran[0], "$mrs$") {
		t.Fatalf("ran %d scripts", len(ran))
	}
	if !strings.Contains(ran[1], "ARRAY['alice@x.com', 'agent:alice@x.com']::text[]") {
		t.Errorf("one account's apply does not cover its agent keys: %s", ran[1])
	}
	mainRunning = func() bool { return false }
	ran = nil
	if err := ApplyMainWrite(); err != nil || len(ran) != 0 {
		t.Errorf("a stopped main: %v, ran %d", err, len(ran))
	}
}
