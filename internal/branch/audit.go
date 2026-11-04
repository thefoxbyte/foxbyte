// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// The audit log (F6, docs/FOX_F6_Audit_Design.md): pgAudit in default mode,
// with bb_identity's hook keeping every value a statement held out of the
// server log, and a line per audited transaction saying how it ended and whom
// it was for.
//
// This file is turning it on and off (Gate 1, step 1): which databases start
// with it, where its log goes, and the policy each one runs. Marking tables,
// the collector and forwarding are later steps. Standard: who did what to the
// data is accountability, like the Blackbox itself.

// auditMarker records that an admin turned audit on. A file, as realtime's is,
// because it governs how every container starts and is read before any
// database runs. A variable so a test can point it somewhere harmless.
var auditMarker = func() string { return brand.StatePath("audit") }

// AuditOn reports whether this install's databases run with pgAudit.
//
// Off unless somebody asked. It costs capacity (section 19 of the design: far
// more than the 5% budget with every statement audited) and turning it on
// restarts main, so an upgrade never does it: `fox audit-log setup` is the one
// way in.
func AuditOn() bool {
	_, err := os.Stat(auditMarker())
	return err == nil
}

// SetAuditOn records the choice. It restarts nothing; the caller says what is
// about to happen and does it.
func SetAuditOn(on bool) error {
	if !on {
		if err := os.Remove(auditMarker()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(auditMarker()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(auditMarker(), []byte("on\n"), 0o600)
}

// Where the log goes. Never inside a data directory: a branch is a clone of
// its parent's, and a log kept there would be copied into every branch with
// the personal data it names. On ZFS it is a dataset of its own with a quota,
// beside the branches rather than among them, so it cannot be mistaken for
// one, and a full log stops audit lines without filling the disk the pool
// lives on. On btrfs it is a directory: there is no quota to set, and `fox
// check` watches its size instead.
const (
	auditDataset   = pool + "/audit"
	auditZFSMount  = "/" + auditDataset
	auditBtrfsRoot = "/var/lib/dbpool-audit"

	// AuditLogDirInContainer is where a database writes its log.
	AuditLogDirInContainer = "/var/log/bb-audit"

	// postgresUID owns the log directory: the official image's postgres user,
	// which the logging process writes as.
	postgresUID = "999"

	envAuditQuota     = "AUDIT_QUOTA"
	defaultAuditQuota = "2G"
)

// AuditRoot is the directory each database's log lives under, one directory
// per branch.
func AuditRoot() string {
	if activeStorage().name() == "btrfs" {
		return auditBtrfsRoot
	}
	return auditZFSMount
}

// AuditDir is one database's log directory. Branch names are checked before
// they get here (checkName), so a name is always one path element.
func AuditDir(name string) string { return AuditRoot() + "/" + name }

// AuditQuota is the most the log may hold, FOX_AUDIT_QUOTA or 2G.
func AuditQuota() string {
	if q := strings.TrimSpace(brand.Getenv(envAuditQuota)); q != "" {
		return q
	}
	return defaultAuditQuota
}

// ensureAuditStore makes the place the log goes, and sets its quota each
// time, so a changed FOX_AUDIT_QUOTA takes effect on the next start.
func ensureAuditStore() error {
	if activeStorage().name() == "btrfs" {
		return run("mkdir", "-p", auditBtrfsRoot)
	}
	if !datasetExists(auditDataset) {
		if err := run("zfs", "create", "-p", auditDataset); err != nil {
			return fmt.Errorf("creating the audit log's dataset: %w", err)
		}
	}
	return run("zfs", "set", "quota="+AuditQuota(), auditDataset)
}

// ensureAuditDir makes one database's log directory, owned by the user its
// logging process runs as, and readable by nobody else.
func ensureAuditDir(name string) error {
	if err := ensureAuditStore(); err != nil {
		return err
	}
	return run("install", "-d", "-o", postgresUID, "-g", postgresUID, "-m", "0700", AuditDir(name))
}

// auditMount is the container's log mount, when audit is on.
func auditMount(name string) []string {
	if !AuditOn() {
		return nil
	}
	return []string{"-v", AuditDir(name) + ":" + AuditLogDirInContainer}
}

// auditStartArgs are the settings that can only be given when the server
// starts: the two libraries, and the logging process writing JSON lines to the
// log directory. A week of hourly files, each overwritten a week later, so the
// log keeps itself to a week until the collector (step 3) takes the files away.
var auditStartArgs = []string{
	"-c", "shared_preload_libraries=pgaudit,bb_identity",
	"-c", "logging_collector=on",
	"-c", "log_destination=jsonlog",
	"-c", "log_directory=" + AuditLogDirInContainer,
	"-c", "log_filename=audit-%a-%H.log",
	"-c", "log_rotation_age=60",
	"-c", "log_rotation_size=0",
	"-c", "log_truncate_on_rotation=on",
	"-c", "log_file_mode=0600",
}

// withAudit adds them to a command line. A branch has none of its own unless
// realtime gave it one, and `postgres` has to lead, or docker takes the first
// flag for the command.
func withAudit(args []string) []string {
	if !AuditOn() {
		return args
	}
	if len(args) == 0 {
		args = []string{"postgres"}
	}
	return append(append([]string(nil), args...), auditStartArgs...)
}

// auditPolicy is default mode (design, section 4): schema and role changes
// for everyone, writes to marked tables through bb_audit, no statement text,
// no parameters, and no statement on PostgreSQL's own error lines. In ALTER
// SYSTEM, not on the command line, so changing the mode later is a reload
// rather than a restart: a command-line setting would win over it.
//
// The two audit roles are made here too. pgAudit finds marked tables by the
// grants they give bb_audit; bb_audit_read's are for reads, given per login.
var auditPolicy = []string{
	"ALTER SYSTEM SET pgaudit.log = 'ddl, role'",
	"ALTER SYSTEM SET pgaudit.role = 'bb_audit'",
	"ALTER SYSTEM SET pgaudit.log_parameter = off",
	"ALTER SYSTEM SET pgaudit.log_relation = on",
	"ALTER SYSTEM SET pgaudit.log_catalog = off",
	"ALTER SYSTEM SET pgaudit.log_client = off",
	"ALTER SYSTEM SET log_min_error_statement = panic",
	"ALTER SYSTEM SET log_parameter_max_length = 0",
	"ALTER SYSTEM SET log_parameter_max_length_on_error = 0",
}

// auditSettings are the names auditPolicy sets, which turning audit off
// resets.
func auditSettings() []string {
	var names []string
	for _, s := range auditPolicy {
		names = append(names, strings.Fields(strings.TrimPrefix(s, "ALTER SYSTEM SET "))[0])
	}
	return append(names, "pgaudit.log_statement")
}

// auditPolicySQL is the script that applies the policy: one statement at a
// time (ALTER SYSTEM cannot run inside the transaction several statements in
// one string would make), then the roles, then a reload.
func auditPolicySQL(forensic bool) string {
	var b strings.Builder
	for _, s := range auditPolicy {
		b.WriteString(s + ";\n")
	}
	// Forensic mode (step 5a) is the one difference: statement text, values
	// and all. Parameters stay off in both.
	if forensic {
		b.WriteString("ALTER SYSTEM SET pgaudit.log_statement = on;\n")
	} else {
		b.WriteString("ALTER SYSTEM SET pgaudit.log_statement = off;\n")
	}
	for _, role := range []string{AuditRole, AuditReadRole} {
		fmt.Fprintf(&b, "DO $$ BEGIN CREATE ROLE %s NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;\n", role)
	}
	b.WriteString("SELECT pg_reload_conf();\n")
	return b.String()
}

// auditResetSQL undoes the policy's settings. The roles stay: dropping them
// would drop every table's mark with them, and turning audit back on should
// find the marks where they were.
func auditResetSQL() string {
	var b strings.Builder
	for _, n := range auditSettings() {
		b.WriteString("ALTER SYSTEM RESET " + n + ";\n")
	}
	b.WriteString("SELECT pg_reload_conf();\n")
	return b.String()
}

// The roles pgAudit's object audit works through. Stored names, brand-free.
const (
	AuditRole     = "bb_audit"
	AuditReadRole = "bb_audit_read"
)

// runsWithAudit reports whether a database's container was started with
// pgAudit loaded, from its command line, without asking the database.
func runsWithAudit(name string) bool {
	out, err := capture("docker", "inspect", "-f", "{{json .Args}}", container(name))
	return err == nil && strings.Contains(out, "shared_preload_libraries=pgaudit")
}

// EnsureAuditPolicy applies the policy to a running database that was started
// with pgAudit. One that was not has nothing to apply it to: pgAudit's
// settings do not exist there, and ALTER SYSTEM would refuse them.
func EnsureAuditPolicy(name string) error {
	if !runsWithAudit(name) {
		return nil
	}
	return psqlQuiet(name, auditPolicySQL(ForensicFor(name)))
}

// applyAuditBestEffort is EnsureAuditPolicy where a failure must not stop a
// branch starting: the branch runs, and `fox audit-log status` names it.
func applyAuditBestEffort(name string) {
	if !AuditOn() {
		return
	}
	if err := EnsureAuditPolicy(name); err != nil {
		fmt.Fprintf(os.Stderr, "warning: applying the audit policy to %q: %v\n", name, err)
	}
}

// ResetAuditPolicy takes the policy's settings out of a running database that
// has pgAudit loaded, before it is restarted without it.
func ResetAuditPolicy(name string) error {
	if !runsWithAudit(name) {
		return nil
	}
	return psqlQuiet(name, auditResetSQL())
}

// AuditMismatch reports whether a database's container runs with audit when
// the install does not, or without it when the install does: one started
// before the change, which picks it up when it is next started.
func AuditMismatch(name string) bool {
	if ContainerState(name) == "absent" {
		return false
	}
	return runsWithAudit(name) != AuditOn()
}

// AuditPending is every database whose container does not yet match the
// install's audit setting.
func AuditPending() ([]string, error) {
	names, err := RunningBranches()
	if err != nil {
		return nil, err
	}
	var pending []string
	for _, n := range names {
		if AuditMismatch(n) {
			pending = append(pending, n)
		}
	}
	return pending, nil
}

// AuditHAGuard refuses what restarts main while the standby serves it, as the
// change feed's guard does, for the same reason.
func AuditHAGuard(action string) error {
	if ServingBranch("main") != "standby" {
		return nil
	}
	return fmt.Errorf("refusing `%s audit-log %s`: 'main' is being served by the promoted standby "+
		"since `%s ha failover`, and this restarts it.\nRun `%s ha failback` first",
		brand.CLI, action, brand.CLI, brand.CLI)
}

// EnsureAuditImage makes sure the engine image has pgAudit: revision 3 or
// later, fetched or built if the one in hand is older.
func EnsureAuditImage() error {
	img := pgImage()
	if err := ensureImageRef(img); err != nil {
		return err
	}
	if ours(img) && imageRevision(img) < 3 {
		return fmt.Errorf("the engine image %s is revision %d and has no pgAudit; "+
			"revision 3 could not be fetched or built", img, imageRevision(img))
	}
	return nil
}

// PrepareAuditDir makes main's log directory before main restarts with audit.
func PrepareAuditDir(name string) error { return ensureAuditDir(name) }

// AuditSpace is how much the log holds and may hold, in bytes. Quota is 0
// where there is none (btrfs).
type AuditSpace struct {
	Used, Quota int64
}

// AuditUsage reads the log's size.
func AuditUsage() (AuditSpace, error) {
	if activeStorage().name() == "btrfs" {
		out, err := capture("du", "-sb", auditBtrfsRoot)
		if err != nil {
			return AuditSpace{}, err
		}
		f := strings.Fields(out)
		if len(f) == 0 {
			return AuditSpace{}, fmt.Errorf("du said nothing about %s", auditBtrfsRoot)
		}
		used, err := strconv.ParseInt(f[0], 10, 64)
		return AuditSpace{Used: used}, err
	}
	out, err := capture("zfs", "get", "-Hp", "-o", "value", "used,quota", auditDataset)
	if err != nil {
		return AuditSpace{}, err
	}
	return parseAuditUsage(out)
}

// parseAuditUsage reads `zfs get -Hp -o value used,quota`: two numbers, one
// per line.
func parseAuditUsage(out string) (AuditSpace, error) {
	f := strings.Fields(out)
	if len(f) != 2 {
		return AuditSpace{}, fmt.Errorf("unexpected zfs output %q", out)
	}
	used, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return AuditSpace{}, err
	}
	quota, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return AuditSpace{}, err
	}
	return AuditSpace{Used: used, Quota: quota}, nil
}
