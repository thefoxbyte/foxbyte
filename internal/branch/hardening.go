// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/tlsutil"
)

// The hardening report (point 3.2): how a branch's PostgreSQL, and the install
// around it, stand against a list of hardening checks. Standard, in every
// edition; fixes and profiles (3.3, 3.4) are Enterprise and come later.
//
// The checks are FoxByte's own, written from PostgreSQL's documentation. They
// cover the ground a benchmark such as CIS's covers (installation, files,
// logging and auditing, roles, connections, settings, backups), but carry
// none of its numbers or text: that benchmark's licence does not cover a
// product, so a mapping to it waits for one (founders, 5 November 2026).
//
// Each check is basic (little effect on how the database runs) or strict
// (more protection, at some cost or with more to set up), and ends pass, fail,
// manual (a person has to judge, and the evidence says what to look at) or not
// applicable. FoxByte runs PostgreSQL in containers behind its own Gateway, so
// where a check means something different there, its evidence says how.

// The statuses.
const (
	HardenPass   = "pass"
	HardenFail   = "fail"
	HardenManual = "manual"
	HardenNA     = "n/a"
)

// HardeningCheck is one check's result.
type HardeningCheck struct {
	ID       string `json:"id"`
	Section  string `json:"section"`
	Level    string `json:"level"` // basic or strict
	Title    string `json:"title"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"` // what was found
	Why      string `json:"why"`
	Fix      string `json:"fix,omitempty"` // for fail and manual
	// Fixable: a fix can be made for it here (Enterprise, 3.3), after a
	// preview. False in Standard, and for a fix that is a person's to make.
	Fixable bool `json:"fixable,omitempty"`
}

// HardeningReport is the report for one branch.
type HardeningReport struct {
	Branch    string           `json:"branch"`
	Generated string           `json:"generated"` // RFC 3339
	Postgres  string           `json:"postgres"`  // the server's version
	Basis     string           `json:"basis"`
	Summary   map[string]int   `json:"summary"` // status -> count
	Checks    []HardeningCheck `json:"checks"`
	Limits    []string         `json:"limits"`
	// Profile is the last hardening profile applied to the branch (3.4).
	Profile *AppliedProfile `json:"profile,omitempty"`
}

// HardeningBasis says what the checks are, and are not.
const HardeningBasis = "FoxByte's own hardening checks, written from PostgreSQL's documentation. Not the CIS Benchmark, and no claim of CIS compliance."

// HardeningLimits are what the report cannot show.
var HardeningLimits = []string{
	"It reads the branch as it is now; a setting changed afterwards is not in it.",
	"Manual checks need a person: their evidence says what to look at.",
	"It checks the database and FoxByte's own setup, not the host's operating system, firewall or disk encryption.",
}

// hbaRule is one line of pg_hba.conf, as PostgreSQL parsed it.
type hbaRule struct {
	Line     int      `json:"line_number"`
	Type     string   `json:"type"`
	Database []string `json:"database"`
	User     []string `json:"user_name"`
	Address  *string  `json:"address"`
	Method   string   `json:"auth_method"`
	Error    *string  `json:"error"`
}

// roleInfo is one role, and how its password is kept.
type roleInfo struct {
	Name        string `json:"name"`
	Super       bool   `json:"super"`
	Login       bool   `json:"login"`
	CreateRole  bool   `json:"createrole"`
	BypassRLS   bool   `json:"bypassrls"`
	Replication bool   `json:"replication"`
	Password    string `json:"password"` // none, scram, md5, other
}

// hardeningInput is everything the checks read, gathered first so the checks
// are a pure function of it, and tested.
type hardeningInput struct {
	Settings      map[string]string
	HBA           []hbaRule
	Roles         []roleInfo
	PublicCreate  bool
	DefinerSuper  []string // SECURITY DEFINER functions a superuser owns, outside the system's and FoxByte's schemas
	Extensions    []string
	DataDir       string // mode and owner, "700 postgres"
	Ports         []string
	Listen        string // FOX_LISTEN, "" for this machine only
	GatewayTLS    error  // nil when the Gateway's certificate loads
	AuditOn       bool
	Forwarding    bool
	Backup        BackupHealth
	Restore       RestoreCheck
	RestoreRan    bool
	BackupRemote  bool
	Errors        []string // what could not be read
	FoxSuperusers []string
}

type hardeningDef struct {
	id, section, level, title, why string
	eval                           func(in hardeningInput) (status, evidence, fix string)
}

// set reads a setting, "" when it is not there.
func (in hardeningInput) set(name string) string { return in.Settings[name] }

func onOff(v string) bool { return v == "on" || v == "true" || v == "1" }

// hardeningChecks is every check, in the order the report lists them.
var hardeningChecks = []hardeningDef{
	// ---- installation ----
	{"install.supported", "installation", "basic", "A PostgreSQL major version that still gets security fixes",
		"Releases out of support get no fixes for vulnerabilities found later.",
		func(in hardeningInput) (string, string, string) {
			v := in.set("server_version")
			n, _ := strconv.Atoi(in.set("server_version_num"))
			if n == 0 {
				return HardenManual, "the version could not be read", ""
			}
			if major := n / 10000; major >= 14 {
				return HardenPass, "PostgreSQL " + v, ""
			}
			return HardenFail, "PostgreSQL " + v + ", out of support", fmt.Sprintf("upgrade the major version: %s pg-upgrade", brand.CLI)
		}},
	{"install.minor", "installation", "basic", "The newest minor release of that major version",
		"Minor releases carry the security fixes; they change nothing else.",
		func(in hardeningInput) (string, string, string) {
			return HardenManual, "PostgreSQL " + in.set("server_version") + ": compare it with the newest minor release at postgresql.org",
				fmt.Sprintf("%s update brings the image this version of %s pins", brand.CLI, brand.Product)
		}},
	{"install.extensions", "installation", "basic", "Only the extensions that are needed",
		"Every extension runs code inside the server, with its privileges.",
		func(in hardeningInput) (string, string, string) {
			known := map[string]bool{"plpgsql": true, "bb_identity": true, "pgaudit": true, "vector": true}
			var other []string
			for _, e := range in.Extensions {
				if !known[strings.Fields(e)[0]] {
					other = append(other, e)
				}
			}
			if len(other) == 0 {
				return HardenPass, "only " + brand.Product + "'s own: " + strings.Join(in.Extensions, ", "), ""
			}
			return HardenManual, "also installed: " + strings.Join(other, ", "), "DROP EXTENSION any that is not used"
		}},
	{"install.preload", "installation", "strict", "Only known libraries loaded at start",
		"A library in shared_preload_libraries runs in every session.",
		func(in hardeningInput) (string, string, string) {
			v := strings.TrimSpace(in.set("shared_preload_libraries"))
			known := map[string]bool{"pgaudit": true, "bb_identity": true, "pg_stat_statements": true}
			var other []string
			for _, l := range strings.Split(v, ",") {
				if l = strings.TrimSpace(l); l != "" && !known[l] {
					other = append(other, l)
				}
			}
			if v == "" {
				return HardenPass, "none", ""
			}
			if len(other) == 0 {
				return HardenPass, v, ""
			}
			return HardenManual, v + " (not " + brand.Product + "'s: " + strings.Join(other, ", ") + ")", "remove what is not needed from shared_preload_libraries"
		}},
	// ---- files ----
	{"files.datadir", "files", "basic", "The data directory readable by its owner only",
		"Anyone who can read the data files can read every row, whatever the grants say.",
		func(in hardeningInput) (string, string, string) {
			f := strings.Fields(in.DataDir)
			if len(f) < 2 {
				return HardenManual, "could not be read", ""
			}
			if (f[0] == "700" || f[0] == "750") && f[1] == "postgres" {
				return HardenPass, in.set("data_directory") + ": mode " + f[0] + ", owned by " + f[1], ""
			}
			return HardenFail, in.set("data_directory") + ": mode " + f[0] + ", owned by " + f[1], "chmod 700 the data directory, owned by postgres"
		}},
	{"files.logs", "files", "strict", "Server logs kept outside the data directory",
		"A branch is a copy of its parent's data directory: logs inside it would be copied into every branch.",
		func(in hardeningInput) (string, string, string) {
			if !onOff(in.set("logging_collector")) {
				return HardenPass, "written to the container's output, kept by Docker outside the data directory", ""
			}
			dir := in.set("log_directory")
			if strings.HasPrefix(dir, "/") && !strings.HasPrefix(dir, in.set("data_directory")) {
				return HardenPass, "written to " + dir, ""
			}
			return HardenFail, "written to " + dir + ", inside the data directory", "set log_directory to an absolute path outside it"
		}},
	// ---- logging ----
	{"log.connections", "logging", "basic", "Connections logged",
		"Who connected, from where and when is the first question after an incident.",
		func(in hardeningInput) (string, string, string) {
			if v := in.set("log_connections"); v != "" && v != "off" && v != "false" {
				return HardenPass, "log_connections = " + v, ""
			}
			return HardenFail, "log_connections = off", "ALTER SYSTEM SET log_connections = on"
		}},
	{"log.disconnections", "logging", "basic", "Disconnections logged, with how long the session lasted",
		"With the connection lines, it says how long each session was open.",
		func(in hardeningInput) (string, string, string) {
			if onOff(in.set("log_disconnections")) {
				return HardenPass, "log_disconnections = on", ""
			}
			return HardenFail, "log_disconnections = off", "ALTER SYSTEM SET log_disconnections = on"
		}},
	{"log.min_messages", "logging", "basic", "Warnings and worse logged, debug output not",
		"Debug output floods the log and can hold data; too little hides errors.",
		func(in hardeningInput) (string, string, string) {
			v := in.set("log_min_messages")
			switch v {
			case "warning", "error", "notice", "info":
				return HardenPass, "log_min_messages = " + v, ""
			case "log", "fatal", "panic":
				return HardenFail, "log_min_messages = " + v + ": errors are not logged", "ALTER SYSTEM SET log_min_messages = warning"
			}
			return HardenFail, "log_min_messages = " + v, "ALTER SYSTEM SET log_min_messages = warning"
		}},
	{"log.error_statement", "logging", "basic", "The statement behind an error recorded",
		"An error with nothing to say what caused it cannot be investigated.",
		func(in hardeningInput) (string, string, string) {
			v := in.set("log_min_error_statement")
			switch v {
			case "error", "warning", "notice", "info", "log":
				return HardenPass, "log_min_error_statement = " + v, ""
			case "fatal", "panic":
				if in.AuditOn {
					return HardenManual, "log_min_error_statement = " + v + ": with the audit log on, " + brand.Product +
							" keeps statement text, and the values in it, out of the server log on purpose; each error is in the audit log as its code, with who and which object",
						"read errors with: " + brand.CLI + " audit-log show --errors"
				}
				return HardenFail, "log_min_error_statement = " + v, "ALTER SYSTEM SET log_min_error_statement = error"
			}
			return HardenFail, "log_min_error_statement = " + v, "ALTER SYSTEM SET log_min_error_statement = error"
		}},
	{"log.statement", "logging", "basic", "Schema changes recorded with who made them",
		"A change to a table's shape is the change most often asked about afterwards.",
		func(in hardeningInput) (string, string, string) {
			v := in.set("log_statement")
			if v == "ddl" || v == "mod" || v == "all" {
				return HardenPass, "log_statement = " + v, ""
			}
			return HardenPass, "log_statement = " + v + "; the Blackbox records every schema change, with who ran it, in a hash chain" +
				map[bool]string{true: ", and the audit log records it too", false: ""}[in.AuditOn], ""
		}},
	{"log.verbosity", "logging", "basic", "Error detail kept to the default",
		"Verbose errors write source locations and more context than an investigation needs.",
		func(in hardeningInput) (string, string, string) {
			if v := in.set("log_error_verbosity"); v != "verbose" {
				return HardenPass, "log_error_verbosity = " + v, ""
			}
			return HardenFail, "log_error_verbosity = verbose", "ALTER SYSTEM SET log_error_verbosity = default"
		}},
	{"log.hostname", "logging", "basic", "No reverse lookups for each connection",
		"A DNS lookup per connection slows every login, and the address is already logged.",
		func(in hardeningInput) (string, string, string) {
			if !onOff(in.set("log_hostname")) {
				return HardenPass, "log_hostname = off", ""
			}
			return HardenFail, "log_hostname = on", "ALTER SYSTEM SET log_hostname = off"
		}},
	{"log.prefix", "logging", "strict", "Every line saying when, who and which database",
		"A line without its time, user and database cannot be put back in order.",
		func(in hardeningInput) (string, string, string) {
			if strings.Contains(in.set("log_destination"), "jsonlog") {
				return HardenPass, "JSON lines, each with time, user, database and session", ""
			}
			p := in.set("log_line_prefix")
			if (strings.Contains(p, "%m") || strings.Contains(p, "%t") || strings.Contains(p, "%n")) && strings.Contains(p, "%u") && strings.Contains(p, "%d") {
				return HardenPass, "log_line_prefix = '" + p + "'", ""
			}
			return HardenFail, "log_line_prefix = '" + p + "'", "ALTER SYSTEM SET log_line_prefix = '%m [%p] %q%u@%d '"
		}},
	{"log.timezone", "logging", "basic", "Log times in a known time zone",
		"Times from different machines only line up in one zone.",
		func(in hardeningInput) (string, string, string) {
			v := in.set("log_timezone")
			if v == "UTC" || v == "Etc/UTC" {
				return HardenPass, "log_timezone = " + v, ""
			}
			return HardenManual, "log_timezone = " + v, "confirm it is the zone your other logs use, or ALTER SYSTEM SET log_timezone = 'UTC'"
		}},
	// ---- auditing ----
	{"audit.on", "auditing", "basic", "pgAudit recording who did what",
		"Logs say a statement ran; an audit log says who changed what, in a form an auditor accepts.",
		func(in hardeningInput) (string, string, string) {
			if strings.Contains(in.set("shared_preload_libraries"), "pgaudit") {
				return HardenPass, "pgAudit loaded; pgaudit.log = " + in.set("pgaudit.log"), ""
			}
			return HardenFail, "pgAudit is not loaded on this branch", brand.CLI + " audit-log setup   (it says what it costs first)"
		}},
	{"audit.classes", "auditing", "basic", "Role and schema changes audited for everyone",
		"Privilege changes and schema changes are what an attacker or a mistake leaves behind.",
		func(in hardeningInput) (string, string, string) {
			if !strings.Contains(in.set("shared_preload_libraries"), "pgaudit") {
				return HardenNA, "pgAudit is not loaded", ""
			}
			v := in.set("pgaudit.log")
			if strings.Contains(v, "ddl") && strings.Contains(v, "role") || strings.Contains(v, "all") {
				return HardenPass, "pgaudit.log = " + v, ""
			}
			return HardenFail, "pgaudit.log = " + v, brand.CLI + " audit-log setup"
		}},
	{"audit.offhost", "auditing", "strict", "Audit records copied off the machine",
		"Records kept only where an administrator can edit them prove less than a copy elsewhere.",
		func(in hardeningInput) (string, string, string) {
			if !in.AuditOn {
				return HardenNA, "the audit log is off", ""
			}
			if in.Forwarding {
				return HardenPass, "forwarded to a SIEM as they are collected", ""
			}
			return HardenFail, "kept on this machine only", brand.CLI + " audit-log forward https://… | syslog://…"
		}},
	// ---- roles ----
	{"roles.superusers", "roles", "basic", "No superuser that people or applications log in as",
		"A superuser bypasses every grant, row-level policy and audit setting.",
		func(in hardeningInput) (string, string, string) {
			own := map[string]bool{}
			for _, r := range in.FoxSuperusers {
				own[r] = true
			}
			var others []string
			for _, r := range in.Roles {
				if r.Super && r.Login && !own[r.Name] {
					others = append(others, r.Name)
				}
			}
			if len(others) == 0 {
				return HardenPass, "only the engine's own superuser (" + strings.Join(in.FoxSuperusers, ", ") + "), which no client is given", ""
			}
			sort.Strings(others)
			return HardenFail, "superusers that can log in: " + strings.Join(others, ", "), "ALTER ROLE … NOSUPERUSER, and grant what each needs instead"
		}},
	{"roles.scram", "roles", "basic", "Passwords stored with SCRAM-SHA-256",
		"MD5 password hashes can be replayed and are weak against guessing.",
		func(in hardeningInput) (string, string, string) {
			var md5 []string
			for _, r := range in.Roles {
				if r.Password == "md5" {
					md5 = append(md5, r.Name)
				}
			}
			enc := in.set("password_encryption")
			switch {
			case len(md5) > 0:
				sort.Strings(md5)
				return HardenFail, "MD5 hashes kept for: " + strings.Join(md5, ", "), "set each one's password again, with password_encryption = scram-sha-256"
			case enc != "scram-sha-256":
				return HardenFail, "password_encryption = " + enc, "ALTER SYSTEM SET password_encryption = 'scram-sha-256'"
			}
			return HardenPass, "password_encryption = scram-sha-256, and no MD5 hash kept", ""
		}},
	{"roles.bypassrls", "roles", "basic", "No role that ignores row-level security, other than superusers",
		"BYPASSRLS turns every row-level policy off for that role.",
		func(in hardeningInput) (string, string, string) {
			var b []string
			for _, r := range in.Roles {
				if r.BypassRLS && !r.Super {
					b = append(b, r.Name)
				}
			}
			if len(b) == 0 {
				return HardenPass, "none", ""
			}
			sort.Strings(b)
			return HardenFail, "BYPASSRLS: " + strings.Join(b, ", "), "ALTER ROLE … NOBYPASSRLS"
		}},
	{"roles.createrole", "roles", "strict", "Few roles that can make roles",
		"A role that makes roles can make itself more powerful ones.",
		func(in hardeningInput) (string, string, string) {
			var c []string
			for _, r := range in.Roles {
				if r.CreateRole && !r.Super && r.Login {
					c = append(c, r.Name)
				}
			}
			if len(c) == 0 {
				return HardenPass, "no login role other than a superuser can make roles", ""
			}
			sort.Strings(c)
			return HardenManual, "CREATEROLE: " + strings.Join(c, ", "), "confirm each needs it, or ALTER ROLE … NOCREATEROLE"
		}},
	{"roles.public_schema", "roles", "basic", "No one can create objects in the public schema by default",
		"Objects anyone can create in a shared schema can shadow the ones others use.",
		func(in hardeningInput) (string, string, string) {
			if !in.PublicCreate {
				return HardenPass, "PUBLIC has no CREATE on schema public", ""
			}
			return HardenFail, "PUBLIC may CREATE in schema public", "REVOKE CREATE ON SCHEMA public FROM PUBLIC"
		}},
	{"roles.definer", "roles", "strict", "No SECURITY DEFINER function that runs as a superuser",
		"A definer function runs with its owner's rights; a superuser's lets any caller act as one.",
		func(in hardeningInput) (string, string, string) {
			if len(in.DefinerSuper) == 0 {
				return HardenPass, "none outside the system's and " + brand.Product + "'s own", ""
			}
			return HardenManual, "run as a superuser: " + strings.Join(in.DefinerSuper, ", "),
				"give each an owner with only the rights it needs, or make it SECURITY INVOKER"
		}},
	// ---- connections ----
	{"conn.trust", "connections", "basic", "No connection allowed without a password",
		"trust lets anyone who reaches the server in as any role.",
		func(in hardeningInput) (string, string, string) {
			var host, local []string
			for _, r := range in.HBA {
				if r.Method != "trust" {
					continue
				}
				if r.Type == "local" {
					local = append(local, fmt.Sprintf("line %d", r.Line))
				} else {
					host = append(host, fmt.Sprintf("line %d (%s)", r.Line, r.Type))
				}
			}
			switch {
			case len(host) > 0:
				return HardenFail, "trust over the network: " + strings.Join(host, ", "), "use scram-sha-256 in pg_hba.conf"
			case len(local) > 0:
				return HardenManual, "trust on the server's own socket (" + strings.Join(local, ", ") +
					"): only something inside the container reaches it, which takes administrator rights on the host", ""
			}
			return HardenPass, "every rule asks for a password or a certificate", ""
		}},
	{"conn.methods", "connections", "basic", "No password sent in clear text or checked with MD5",
		"password sends it in the clear; md5 is weaker than scram-sha-256.",
		func(in hardeningInput) (string, string, string) {
			var weak []string
			for _, r := range in.HBA {
				if r.Method == "password" || r.Method == "md5" {
					weak = append(weak, fmt.Sprintf("line %d (%s)", r.Line, r.Method))
				}
			}
			if len(weak) == 0 {
				return HardenPass, "no password or md5 rule", ""
			}
			return HardenFail, strings.Join(weak, ", "), "use scram-sha-256 in pg_hba.conf"
		}},
	{"conn.hba_errors", "connections", "basic", "pg_hba.conf has no line PostgreSQL could not read",
		"A line that does not parse is silently not applied.",
		func(in hardeningInput) (string, string, string) {
			var bad []string
			for _, r := range in.HBA {
				if r.Error != nil && *r.Error != "" {
					bad = append(bad, fmt.Sprintf("line %d: %s", r.Line, *r.Error))
				}
			}
			if len(bad) == 0 {
				return HardenPass, fmt.Sprintf("%d rule(s), all read", len(in.HBA)), ""
			}
			return HardenFail, strings.Join(bad, "; "), "correct pg_hba.conf"
		}},
	{"conn.exposure", "connections", "basic", "The database not reachable from other machines",
		"A database port open to the network is attacked directly, past the Gateway's keys and limits.",
		func(in hardeningInput) (string, string, string) {
			var open []string
			for _, p := range in.Ports {
				if !strings.HasPrefix(p, "127.0.0.1:") && !strings.HasPrefix(p, "[::1]:") {
					open = append(open, p)
				}
			}
			if len(open) > 0 {
				return HardenFail, "published on " + strings.Join(open, ", "), "publish it on 127.0.0.1 only; clients go through the Gateway"
			}
			ev := "not published to other machines; clients reach it through the Gateway"
			if len(in.Ports) > 0 {
				ev = "published on " + strings.Join(in.Ports, ", ") + " only; clients reach it through the Gateway"
			}
			return HardenPass, ev, ""
		}},
	{"conn.tls", "connections", "basic", "Connections from other machines encrypted",
		"Without TLS, keys and data cross the network readable.",
		func(in hardeningInput) (string, string, string) {
			if in.GatewayTLS == nil {
				ev := "the Gateway offers TLS 1.2 or later, and refuses other machines without it"
				if in.Listen == "" || in.Listen == "127.0.0.1" {
					ev += "; it listens on this machine only"
				}
				return HardenPass, ev, ""
			}
			if in.Listen == "" || in.Listen == "127.0.0.1" {
				return HardenManual, "the Gateway has no certificate (" + in.GatewayTLS.Error() + "), so it serves this machine only, unencrypted",
					"set FOX_TLS_CERT and FOX_TLS_KEY before listening on another address"
			}
			return HardenFail, "no certificate: " + in.GatewayTLS.Error(), "set FOX_TLS_CERT and FOX_TLS_KEY"
		}},
	{"conn.ssl_protocol", "connections", "strict", "TLS 1.2 or later where the database speaks TLS itself",
		"Older TLS versions have known weaknesses.",
		func(in hardeningInput) (string, string, string) {
			if !onOff(in.set("ssl")) {
				return HardenNA, "the database does not speak TLS itself: it is reached only inside the host, and the Gateway encrypts from there", ""
			}
			v := in.set("ssl_min_protocol_version")
			if v == "TLSv1.2" || v == "TLSv1.3" {
				return HardenPass, "ssl_min_protocol_version = " + v, ""
			}
			return HardenFail, "ssl_min_protocol_version = " + v, "ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2'"
		}},
	{"conn.idle", "connections", "strict", "Sessions idle in a transaction ended",
		"A transaction left open holds locks and old rows, and an unattended session is one to take over.",
		func(in hardeningInput) (string, string, string) {
			v := in.set("idle_in_transaction_session_timeout")
			if v != "" && v != "0" {
				return HardenPass, "idle_in_transaction_session_timeout = " + v, ""
			}
			return HardenFail, "idle_in_transaction_session_timeout = 0 (never)", "ALTER SYSTEM SET idle_in_transaction_session_timeout = '10min'"
		}},
	// ---- settings ----
	{"set.durability", "settings", "basic", "Writes made durable before they are confirmed",
		"With fsync or full-page writes off, a crash can corrupt the data.",
		func(in hardeningInput) (string, string, string) {
			if onOff(in.set("fsync")) && onOff(in.set("full_page_writes")) {
				return HardenPass, "fsync = on, full_page_writes = on", ""
			}
			return HardenFail, "fsync = " + in.set("fsync") + ", full_page_writes = " + in.set("full_page_writes"), "ALTER SYSTEM SET fsync = on; ALTER SYSTEM SET full_page_writes = on"
		}},
	{"set.checksums", "settings", "strict", "Data page checksums",
		"Checksums find pages the disk or memory corrupted, before they are read as good.",
		func(in hardeningInput) (string, string, string) {
			if onOff(in.set("data_checksums")) {
				return HardenPass, "data_checksums = on", ""
			}
			return HardenFail, "data_checksums = off", "they are set when the cluster is made (initdb --data-checksums), or turned on offline with pg_checksums"
		}},
	{"set.fips", "settings", "strict", "FIPS-validated cryptography",
		"Some regulators require cryptography from a validated module.",
		func(in hardeningInput) (string, string, string) {
			return HardenManual, "FIPS mode belongs to the host's OpenSSL; the image does not turn it on", "required only where a regulator names FIPS 140"
		}},
	{"set.set_user", "settings", "strict", "Superuser use only through a logged switch",
		"An extension such as set_user makes each switch to a superuser logged and deliberate.",
		func(in hardeningInput) (string, string, string) {
			return HardenManual, "not installed; no login is a superuser (roles.superusers), and the engine's own superuser is used by the engine only",
				"needed only if people are given superuser rights"
		}},
	// ---- backups ----
	{"backup.archiving", "backups", "basic", "Write-ahead log archived continuously",
		"Without the archive, a restore can only go back to the last full backup.",
		func(in hardeningInput) (string, string, string) {
			if v := in.set("archive_mode"); v == "on" || v == "always" {
				return HardenPass, "archive_mode = " + v, ""
			}
			return HardenFail, "archive_mode = " + in.set("archive_mode"), brand.CLI + " backup target …   (archiving is on with a backup target)"
		}},
	{"backup.recent", "backups", "basic", "A recent base backup",
		"A restore needs a base backup to start from.",
		func(in hardeningInput) (string, string, string) {
			b := in.Backup
			switch {
			case b.Unknown:
				return HardenManual, "could not be listed: " + b.Err, brand.CLI + " backup list"
			case b.Newest == "":
				return HardenFail, "no base backup", brand.CLI + " backup create"
			case b.Stale:
				return HardenFail, fmt.Sprintf("the newest is %dh old (schedule %s)", b.AgeHours, b.Schedule), brand.CLI + " backup create"
			}
			return HardenPass, fmt.Sprintf("the newest is %dh old (schedule %s)", b.AgeHours, b.Schedule), ""
		}},
	{"backup.restored", "backups", "basic", "Backups proven by restoring one",
		"A backup nobody has restored is a hope, not a backup.",
		func(in hardeningInput) (string, string, string) {
			switch {
			case !in.RestoreRan:
				return HardenFail, "never checked on this install", brand.CLI + " backup verify"
			case !in.Restore.OK:
				return HardenFail, "the last check failed: " + in.Restore.Err, brand.CLI + " backup verify"
			}
			return HardenPass, "restored from " + in.Restore.BaseBackup + " at " + in.Restore.At, ""
		}},
	{"backup.offsite", "backups", "strict", "Backups kept off this machine",
		"Backups on the same machine are lost with it.",
		func(in hardeningInput) (string, string, string) {
			if in.BackupRemote {
				return HardenPass, "to a bucket", ""
			}
			return HardenFail, "on this machine only", brand.CLI + " backup target s3://…"
		}},
}

// LogLine is the security log's line for a report: how the branch stood.
func (r HardeningReport) LogLine() string {
	return fmt.Sprintf("hardening of %s: %d pass, %d fail, %d manual, %d n/a", r.Branch,
		r.Summary[HardenPass], r.Summary[HardenFail], r.Summary[HardenManual], r.Summary[HardenNA])
}

// evaluateHardening runs every check against what was read.
func evaluateHardening(in hardeningInput) []HardeningCheck {
	out := make([]HardeningCheck, 0, len(hardeningChecks))
	for _, d := range hardeningChecks {
		st, ev, fix := d.eval(in)
		if st == HardenPass || st == HardenNA {
			fix = ""
		}
		out = append(out, HardeningCheck{ID: d.id, Section: d.section, Level: d.level, Title: d.title,
			Status: st, Evidence: ev, Why: d.why, Fix: fix})
	}
	return out
}

// HardeningCheckIDs lists every check's id, for the docs and the tests.
func HardeningCheckIDs() []string {
	ids := make([]string, 0, len(hardeningChecks))
	for _, d := range hardeningChecks {
		ids = append(ids, d.id)
	}
	return ids
}

// The reads, each one query answering in JSON.
const (
	hardenSettingsSQL = `SELECT json_object_agg(name, setting) FROM pg_settings`
	hardenHBASQL      = `SELECT coalesce(json_agg(json_build_object('line_number', line_number, 'type', type, 'database', database,
  'user_name', user_name, 'address', address, 'auth_method', auth_method, 'error', error) ORDER BY line_number), '[]'::json) FROM pg_hba_file_rules`
	hardenRolesSQL = `SELECT coalesce(json_agg(json_build_object('name', rolname, 'super', rolsuper, 'login', rolcanlogin,
  'createrole', rolcreaterole, 'bypassrls', rolbypassrls, 'replication', rolreplication,
  'password', CASE WHEN rolpassword IS NULL THEN 'none' WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram'
                   WHEN rolpassword LIKE 'md5%' THEN 'md5' ELSE 'other' END) ORDER BY rolname), '[]'::json)
  FROM pg_authid WHERE rolname NOT LIKE 'pg\_%'`
	hardenMiscSQL = `SELECT json_build_object(
  'public_create', has_schema_privilege('public', 'public', 'CREATE'),
  'extensions', (SELECT coalesce(json_agg(extname || ' ' || extversion ORDER BY extname), '[]'::json) FROM pg_extension),
  'definer_super', (SELECT coalesce(json_agg(p.oid::regprocedure::text ORDER BY 1), '[]'::json)
     FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
    WHERE p.prosecdef AND r.rolsuper AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'bb', 'bb_f1')
      AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')))`
)

// ProduceHardening reads a branch and the install, and reports. A branch that
// is not running is not woken: it is refused, with the way to start it.
func ProduceHardening(name string) (HardeningReport, error) {
	if name == "" {
		name = "main"
	}
	if err := checkName(name); err != nil {
		return HardeningReport{}, err
	}
	if ContainerState(name) != "running" {
		return HardeningReport{}, fmt.Errorf("%w: %s is not running — start it first: %s branch resume %s", ErrInvalidRequest, name, brand.CLI, name)
	}
	in := gatherHardening(name)
	rep := HardeningReport{Branch: name, Generated: time.Now().UTC().Format(time.RFC3339), Postgres: in.set("server_version"),
		Basis: HardeningBasis, Summary: map[string]int{HardenPass: 0, HardenFail: 0, HardenManual: 0, HardenNA: 0},
		Checks: evaluateHardening(in), Limits: HardeningLimits}
	for _, e := range in.Errors {
		rep.Limits = append(rep.Limits, "Not read: "+e)
	}
	for _, c := range rep.Checks {
		rep.Summary[c.Status]++
	}
	fixable(name, rep.Checks)
	if p, ok := loadProfiles()[name]; ok {
		rep.Profile = &p
	}
	return rep, nil
}

func gatherHardening(name string) hardeningInput {
	in := hardeningInput{Settings: map[string]string{}, FoxSuperusers: []string{pgUser, "postgres"},
		Listen: strings.TrimSpace(brand.Getenv("LISTEN"))}
	read := func(what, sql string, into any) {
		out, err := QuerySQL(name, sql)
		if err == nil {
			err = json.Unmarshal([]byte(strings.TrimSpace(out)), into)
		}
		if err != nil {
			in.Errors = append(in.Errors, fmt.Sprintf("%s (%v)", what, err))
		}
	}
	read("settings", hardenSettingsSQL, &in.Settings)
	read("pg_hba.conf", hardenHBASQL, &in.HBA)
	read("roles", hardenRolesSQL, &in.Roles)
	var misc struct {
		PublicCreate bool     `json:"public_create"`
		Extensions   []string `json:"extensions"`
		DefinerSuper []string `json:"definer_super"`
	}
	read("schema privileges, extensions and functions", hardenMiscSQL, &misc)
	in.PublicCreate, in.Extensions, in.DefinerSuper = misc.PublicCreate, misc.Extensions, misc.DefinerSuper
	if dir := in.set("data_directory"); dir != "" {
		if out, err := capture("docker", "exec", container(name), "stat", "-c", "%a %U", dir); err == nil {
			in.DataDir = strings.TrimSpace(out)
		} else {
			in.Errors = append(in.Errors, "the data directory's mode ("+err.Error()+")")
		}
	}
	if out, err := capture("docker", "inspect", "-f", "{{json .HostConfig.PortBindings}}", container(name)); err == nil {
		in.Ports = parsePortBindings(out)
	}
	_, in.GatewayTLS = tlsutil.ServerConfig()
	in.AuditOn = AuditOn()
	in.Forwarding = LoadAuditSettings().Forward != nil
	in.Backup = CurrentBackupHealthProbe(0)
	in.Restore, in.RestoreRan = LastRestoreCheck()
	in.BackupRemote = in.Backup.Remote
	return in
}

// parsePortBindings reads docker's PortBindings as host:port strings.
func parsePortBindings(out string) []string {
	var m map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &m) != nil {
		return nil
	}
	var ports []string
	for _, bs := range m {
		for _, b := range bs {
			ip := b.HostIP
			if ip == "" {
				ip = "0.0.0.0"
			}
			ports = append(ports, ip+":"+b.HostPort)
		}
	}
	sort.Strings(ports)
	return ports
}
