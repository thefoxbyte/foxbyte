// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"
)

// A branch set up as FoxByte sets one up, with backups and the audit log on.
func goodHardening() hardeningInput {
	s := func(p string) *string { return &p }
	return hardeningInput{
		Settings: map[string]string{
			"server_version": "18.1", "server_version_num": "180001", "shared_preload_libraries": "pgaudit,bb_identity",
			"data_directory": "/var/lib/postgresql/data", "logging_collector": "off", "log_connections": "on",
			"log_disconnections": "on", "log_min_messages": "warning", "log_min_error_statement": "error",
			"log_statement": "none", "log_error_verbosity": "default", "log_hostname": "off", "log_line_prefix": "%m [%p] %q%u@%d ",
			"log_timezone": "UTC", "pgaudit.log": "ddl, role", "password_encryption": "scram-sha-256", "ssl": "off",
			"idle_in_transaction_session_timeout": "600000", "fsync": "on", "full_page_writes": "on", "data_checksums": "on",
			"archive_mode": "on",
		},
		HBA: []hbaRule{{Line: 1, Type: "host", Address: s("all"), Method: "scram-sha-256"}},
		Roles: []roleInfo{{Name: "dbadmin", Super: true, Login: true, Password: "scram"},
			{Name: "db_client", Login: true, Password: "scram"}},
		Extensions:    []string{"pgaudit 17.0", "plpgsql 1.0", "vector 0.8.0"},
		DataDir:       "700 postgres",
		Ports:         []string{"127.0.0.1:5432"},
		AuditOn:       true,
		Forwarding:    true,
		Backup:        BackupHealth{Newest: "base_1", AgeHours: 3, Schedule: "every 24h0m0s", Remote: true},
		Restore:       RestoreCheck{OK: true, BaseBackup: "base_1", At: "2026-11-05T09:00:00Z"},
		RestoreRan:    true,
		BackupRemote:  true,
		FoxSuperusers: []string{"dbadmin", "postgres"},
	}
}

func statusOf(cs []HardeningCheck) map[string]HardeningCheck {
	m := map[string]HardeningCheck{}
	for _, c := range cs {
		m[c.ID] = c
	}
	return m
}

// Every check is named once, in a known section and level, says why it
// matters, and gives a fix whenever it does not pass.
func TestHardeningChecksAreComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range hardeningChecks {
		if seen[d.id] || d.section == "" || d.title == "" || d.why == "" || (d.level != "basic" && d.level != "strict") {
			t.Errorf("check %q: %+v", d.id, d)
		}
		seen[d.id] = true
	}
	if len(seen) < 35 {
		t.Fatalf("%d checks", len(seen))
	}
	bad := goodHardening()
	bad.Settings = map[string]string{}
	for _, c := range evaluateHardening(bad) {
		switch c.Status {
		case HardenPass, HardenNA:
			if c.Fix != "" {
				t.Errorf("%s passes and still has a fix", c.ID)
			}
		case HardenFail:
			if c.Fix == "" {
				t.Errorf("%s fails with no fix", c.ID)
			}
		case HardenManual:
		default:
			t.Errorf("%s: status %q", c.ID, c.Status)
		}
	}
}

// An install set up as FoxByte sets one up fails nothing; the manual checks
// are those a person has to judge.
func TestHardeningGood(t *testing.T) {
	var manual []string
	for _, c := range evaluateHardening(goodHardening()) {
		switch c.Status {
		case HardenFail:
			t.Errorf("%s fails: %s", c.ID, c.Evidence)
		case HardenManual:
			manual = append(manual, c.ID)
		}
	}
	if got := strings.Join(manual, " "); got != "install.minor set.fips set.set_user" {
		t.Fatalf("manual: %s", got)
	}
}

// What each weakness looks like.
func TestHardeningWeaknesses(t *testing.T) {
	s := func(p string) *string { return &p }
	in := goodHardening()
	in.Roles = append(in.Roles, roleInfo{Name: "ops", Super: true, Login: true, Password: "md5"},
		roleInfo{Name: "app", Login: true, BypassRLS: true, Password: "scram"})
	in.HBA = append(in.HBA, hbaRule{Line: 2, Type: "host", Method: "trust"}, hbaRule{Line: 3, Type: "host", Method: "md5"},
		hbaRule{Line: 4, Type: "host", Method: "scram-sha-256", Error: s("invalid IP mask")})
	in.Ports = []string{"0.0.0.0:5432"}
	in.PublicCreate = true
	in.DataDir = "755 postgres"
	in.Settings["log_min_error_statement"] = "panic"
	in.AuditOn, in.Forwarding = false, false
	in.Backup = BackupHealth{}
	in.RestoreRan = false
	m := statusOf(evaluateHardening(in))
	for id, want := range map[string]string{
		"roles.superusers": "ops", "roles.scram": "ops", "roles.bypassrls": "app", "conn.trust": "line 2",
		"conn.methods": "line 3 (md5)", "conn.hba_errors": "invalid IP mask", "conn.exposure": "0.0.0.0:5432",
		"roles.public_schema": "PUBLIC", "files.datadir": "755", "log.error_statement": "panic",
		"backup.recent": "no base backup", "backup.restored": "never",
	} {
		if c := m[id]; c.Status != HardenFail || !strings.Contains(c.Evidence, want) {
			t.Errorf("%s: %s %q, want fail naming %q", id, c.Status, c.Evidence, want)
		}
	}
	if c := m["audit.offhost"]; c.Status != HardenNA {
		t.Errorf("forwarding with audit off: %s", c.Status)
	}
}

// Where FoxByte differs on purpose, the check says so rather than failing.
func TestHardeningFoxByteChoices(t *testing.T) {
	in := goodHardening()
	in.HBA = []hbaRule{{Line: 1, Type: "local", Method: "trust"}}
	in.Settings["log_min_error_statement"] = "panic" // with the audit log on, errors are its records
	m := statusOf(evaluateHardening(in))
	if c := m["conn.trust"]; c.Status != HardenManual || !strings.Contains(c.Evidence, "inside the container") {
		t.Errorf("local trust: %+v", c)
	}
	if c := m["log.error_statement"]; c.Status != HardenManual || !strings.Contains(c.Evidence, "audit log") {
		t.Errorf("error statements with the audit log on: %+v", c)
	}
	if c := m["log.statement"]; c.Status != HardenPass || !strings.Contains(c.Evidence, "Blackbox") {
		t.Errorf("log_statement none with the Blackbox: %+v", c)
	}
	if c := m["conn.ssl_protocol"]; c.Status != HardenNA {
		t.Errorf("TLS at the Gateway, not the database: %+v", c)
	}
	in.GatewayTLS = errors.New("no certificate")
	if c := statusOf(evaluateHardening(in))["conn.tls"]; c.Status != HardenManual {
		t.Errorf("no certificate, this machine only: %+v", c)
	}
	in.Listen = "0.0.0.0"
	if c := statusOf(evaluateHardening(in))["conn.tls"]; c.Status != HardenFail {
		t.Errorf("no certificate, every interface: %+v", c)
	}
}

func TestParsePortBindings(t *testing.T) {
	got := parsePortBindings(`{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5433"}],"9/tcp":[{"HostIp":"","HostPort":"9"}]}`)
	if strings.Join(got, " ") != "0.0.0.0:9 127.0.0.1:5433" {
		t.Fatalf("got %v", got)
	}
	if parsePortBindings("null") != nil || parsePortBindings("{}") != nil {
		t.Fatal("no bindings")
	}
}
