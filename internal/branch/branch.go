// SPDX-License-Identifier: AGPL-3.0-or-later

// Package branch implements instant copy-on-write database branching on ZFS.
//
// Each branch is a `zfs clone` of a parent dataset, served by its own Postgres
// container. Cloning is O(1) and space-efficient (copy-on-write), so a branch
// is created in seconds regardless of database size — the parent is untouched
// and the branch only stores the blocks it changes.
//
// This runs inside the Linux dev VM (ZFS + Docker). zfs and docker need root
// there, so privileged commands are run through sudo (passwordless in Lima).
package branch

import (
	"errors"
	"fmt"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
	"github.com/thefoxbyte/foxbyte/internal/secrets"
)

const (
	datasetBase = "dbpool/branches"
	mountBase   = "/dbpool/branches"
	network     = "dbnet"
	// Throwaway loader images used by the migration adapters, run on the shared
	// network so they can reach both the source and the target instance.
	// pgloaderImage is built locally on first use — Debian packages pgloader for
	// both amd64 and arm64, unlike the amd64-only Docker Hub image.
	pgloaderImage = "dbengine/pgloader:local" // MariaDB / MySQL ≤5.7 → Postgres
	mysqlImage    = "mysql:8"                 // client + mysqldump; speaks the MySQL 8.x protocol pgloader can't
	mongoImage    = "mongo:7"                 // ships mongosh for enumerating/exporting collections
	pgUser        = "dbadmin"
	pgDatabase    = "appdb"
	pgUID         = "999" // the postgres user's uid inside the official image

	// Names written into Docker and object storage. They carry no product name
	// on purpose: the product has been renamed twice, and each time anything
	// branded in an existing install had to be migrated or thrown away. These
	// are frozen (see brand.json and docs/branding.md).
	containerPrefix = "pg-"
	walBucket       = "wal-archive"
	objStoreVolume  = "objstore-data"
	// objStoreEndpoint is where wal-g and mc reach the object store. It follows
	// objStore: when the container was renamed and this was not, WAL archiving,
	// backups and restores all failed to resolve the host.
	objStoreEndpoint = "http://" + objStore + ":9000"
	objStoreWait     = 60 // seconds to wait for the object store before giving up
)

// The same names, exported: the uninstaller removes what the engine creates, and
// both must mean the same thing. Frozen and brand-free (see docs/branding.md).
const (
	// Database and ClientRole are what the Gateway must log clients into; it
	// used to spell them out again, and after a rename it connected to a
	// database that no longer existed.
	Database        = pgDatabase
	Superuser       = pgUser
	ClientRole      = "db_client"
	ContainerPrefix = containerPrefix
	ObjStore        = objStore
	ObjStoreVolume  = objStoreVolume
	Network         = network
	WALBucket       = walBucket
	ManagedLabel    = managedLabel
)

// Credentials are generated per install (internal/secrets), not hardcoded. The
// engine sets them on the containers it starts; the gateway reads the same
// Postgres password to authenticate to the backend.
func pgPass() string    { return secrets.Load().PGPassword }
func minioUser() string { return secrets.Load().MinioUser }
func minioPass() string { return secrets.Load().MinioPassword }

func dataset(name string) string    { return datasetBase + "/" + name }
func mountpoint(name string) string { return mountBase + "/" + name }
func container(name string) string  { return containerPrefix + name }
func snapFor(parent, name string) string {
	return dataset(parent) + "@for-" + name
}

// run executes a privileged command and streams output to the terminal.
func run(name string, args ...string) error {
	cmd := exec.Command("sudo", append([]string{name}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// quiet executes a privileged command, discarding output and errors. Used for
// best-effort cleanup where "not found" is not a failure.
func quiet(name string, args ...string) {
	_ = exec.Command("sudo", append([]string{name}, args...)...).Run()
}

// capture runs a privileged command and returns its trimmed stdout.
func capture(name string, args ...string) (string, error) {
	out, err := exec.Command("sudo", append([]string{name}, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}

func datasetExists(ds string) bool {
	return exec.Command("sudo", "zfs", "list", "-H", "-o", "name", ds).Run() == nil
}

// ensureNetwork creates the shared docker network (idempotent) so Postgres
// containers can reach MinIO by name.
func ensureNetwork() error {
	if exec.Command("sudo", "docker", "network", "inspect", network).Run() == nil {
		return nil
	}
	return run("docker", "network", "create", network)
}

// startContainer (re)starts the Postgres container for a branch, bind-mounting
// its ZFS dataset as the data directory. The primary ("main") additionally
// archives WAL to object storage (MinIO); branches do not archive — they are
// ephemeral copy-on-write clones.
func startContainer(name string, primary bool) error {
	img := pgImage()
	if err := checkDataMajor(name, dataMajor(name), img); err != nil {
		return err
	}
	quiet("docker", "rm", "-f", container(name))
	args := []string{"run", "-d",
		"--name", container(name),
		"--network", network,
		"--label", managedLabel,
		"-e", "POSTGRES_USER=" + pgUser,
		"-e", "POSTGRES_PASSWORD=" + pgPass(),
		"-e", "POSTGRES_DB=" + pgDatabase,
		"-e", "PGDATA=/var/lib/postgresql/data/pgdata",
		"-v", mountpoint(name) + ":/var/lib/postgresql/data",
	}
	// Branch Postgres is reached by the in-guest gateway over the docker network
	// (BackendAddr -> containerIP), so no host port is published by default. That
	// keeps branch databases unreachable from outside the VM, where a direct
	// connection would bypass the gateway, its API key, TLS, and ledger
	// attribution. FOX_DEBUG_PORTS publishes a host port for debugging.
	if brand.Getenv("DEBUG_PORTS") != "" {
		if primary {
			args = append(args, "-p", "5432:5432")
		} else {
			args = append(args, "-p", "0:5432")
		}
	}
	if primary {
		args = append(args, walgEnv()...)
		args = append(args, "-e", "WALG_COMPRESSION_METHOD=lz4")
	}
	args = append(args, img)
	if primary {
		args = append(args,
			"postgres",
			"-c", "wal_level=replica",
			"-c", "archive_mode=on",
			"-c", "archive_command=wal-g wal-push %p",
			"-c", "archive_timeout=60",
			"-c", "listen_addresses=*",
		)
	}
	return run("docker", args...)
}

func waitReady(name string) error {
	// Probed over TCP, deliberately, not the Unix socket.
	//
	// On a container's first start the Postgres entrypoint runs initdb against a
	// *temporary* server so it can create the database and run init scripts. That
	// server listens on the Unix socket but is started with listen_addresses='',
	// so a socket probe reports ready while the real cluster does not yet exist.
	// The engine then connects and gets either `database "foxbyte" does not
	// exist` or, if it lands in the window where the entrypoint stops the
	// temporary server, `the database system is shutting down` — which is exactly
	// how setup failed on a fresh Windows machine.
	//
	// TCP is refused for the whole of that window and accepted only once the real
	// server is up, which is the condition actually wanted here. Measured on a
	// fresh container: at the first socket-ready sample TCP still reported
	// "Connection refused" on every attempt, and the socket query failed with one
	// of the two errors above.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if exec.Command("sudo", "docker", "exec", container(name),
			"pg_isready", "-h", "127.0.0.1", "-U", pgUser, "-d", pgDatabase).Run() == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("branch %q did not become ready in time", name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Init creates the primary "main" dataset (if absent) and starts its Postgres
// container. On first run Postgres initializes a fresh cluster on the dataset.
func Init() error {
	if err := ensureNetwork(); err != nil {
		return err
	}
	// After `fox ha failover` the promoted standby is the primary; the old main
	// must stay stopped.
	if PrimaryContainer() == container("standby") {
		return ensurePromotedStandby()
	}
	if ContainerState("main") == "running" {
		if err := syncRolePassword("main"); err != nil { // ensure the role matches the generated secret
			return err
		}
		activeStorage().protectPrimary()
		if err := InstallLedger("main"); err != nil { // ensure the ledger is present
			return err
		}
		ensureLedgerV2BestEffort("main")
		return syncAppRole("main")
	}
	store := activeStorage()
	if !store.exists("main") {
		if err := store.createEmpty("main"); err != nil {
			return err
		}
	}
	if err := run("chown", "-R", pgUID+":"+pgUID, mountpoint("main")); err != nil {
		return err
	}
	if err := startContainer("main", true); err != nil {
		return err
	}
	if err := waitReady("main"); err != nil {
		return err
	}
	// The data dir may have been initialized with a different POSTGRES_PASSWORD
	// (an older install, or before per-install secrets existed). Sync the role
	// password to the generated secret so the gateway's TCP login matches.
	if err := syncRolePassword("main"); err != nil {
		return err
	}
	// Reserve pool space for the primary so branches can't take it read-only
	// (idempotent — also applies on an upgrade of an existing install).
	store.protectPrimary()
	// Install the Blackbox into main; every branch (a ZFS clone) inherits it.
	if err := InstallLedger("main"); err != nil {
		return err
	}
	ensureLedgerV2BestEffort("main")
	return syncAppRole("main")
}

// syncAppRole sets the non-superuser client role's password to the per-install
// secret, so the gateway can log clients in as it. The role is created by the
// ledger install (roles are cluster-global and travel with a branch's clone).
func syncAppRole(name string) error {
	return psqlStdin(name, fmt.Sprintf("ALTER ROLE db_client WITH LOGIN PASSWORD %s;", quoteLiteral(pgPass())))
}

// ensuredRoles caches which (branch, email) per-user roles this process has
// already provisioned, so the create runs at most once each.
var ensuredRoles sync.Map

// EnsureUserRole makes sure a per-user login role named for email exists on the
// branch's Postgres, so the gateway can log a client in AS that role — and the
// ledger can read session_user as the actor, an identity the client cannot forge
// (SET ROLE does not change session_user). The role is a member of db_client
// (inherits its data access) and defaults its current role to db_client, so
// object ownership and RLS stay shared exactly as before.
func EnsureUserRole(branchName, email string) error {
	if branchName == "" {
		branchName = "main"
	}
	k := branchName + "\x00" + email
	if _, ok := ensuredRoles.Load(k); ok {
		return nil
	}
	sql := fmt.Sprintf(`DO $do$
DECLARE r text := %s;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
    EXECUTE format('CREATE ROLE %%I LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB INHERIT IN ROLE db_client', r);
  END IF;
  EXECUTE format('ALTER ROLE %%I WITH LOGIN PASSWORD %%L', r, %s);
  EXECUTE format('ALTER ROLE %%I SET role = db_client', r);
END $do$;`, quoteLiteral(email), quoteLiteral(pgPass()))
	if err := psqlStdin(branchName, sql); err != nil {
		return err
	}
	ensuredRoles.Store(k, struct{}{})
	return nil
}

// syncRolePassword sets the Postgres role password to the per-install secret.
// It connects over the container's local socket (trust auth), so it works even
// when the stored password differs from the current secret.
func syncRolePassword(name string) error {
	return psqlStdin(name, fmt.Sprintf("ALTER USER %s WITH PASSWORD %s;", pgUser, quoteLiteral(pgPass())))
}

// quoteLiteral renders s as a single-quoted SQL string literal (doubling any
// embedded quotes). The generated password is hex, but quote defensively.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// psqlStdin runs a (possibly multi-statement) SQL script on a branch's Postgres
// by piping it to psql over stdin, aborting on the first error.
func psqlStdin(name, sql string) error {
	cmd := exec.Command("sudo", "docker", "exec", "-i",
		"-e", "PGPASSWORD="+pgPass(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1", "-q")
	cmd.Stdin = strings.NewReader(sql)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// InstallLedger installs (or upgrades) the Blackbox into a branch. It is
// idempotent and safe to run repeatedly.
func InstallLedger(name string) error {
	return psqlStdin(name, ledger.Schema)
}

// Ledger prints a branch's Blackbox (most recent first) — the RECORD layer:
// every DDL change, attributed and policy-checked.
func Ledger(name string, limit int) error {
	if name == "" {
		name = "main"
	}
	if limit <= 0 {
		limit = 50
	}
	q := fmt.Sprintf(`SELECT to_char(at,'MM-DD HH24:MI:SS') AS time,
		coalesce(actor,'-') AS actor, actor_kind AS kind, coalesce(tool,'-') AS tool,
		command_tag AS command, coalesce(object_identity,'') AS object,
		status, coalesce(risk,'') AS risk
		FROM bb.schema_ledger ORDER BY at DESC LIMIT %d`, limit)
	return run("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-P", "pager=off", "-c", q)
}

// ledgerVerifySQL recomputes each row's hash from the previous row's and this
// row's fields, and checks the chain linkage, returning:
//
//	legacy | chained | broken | first_broken_id
//
// LedgerVerifySQL is exported so the control-plane can run the same check.
const LedgerVerifySQL = `WITH v AS (
  SELECT id, prev_hash, row_hash, bb._ledger_hash(s.*) AS recomputed,
         lag(row_hash) OVER (ORDER BY id) AS prev_link
  FROM bb.schema_ledger s WHERE row_hash IS NOT NULL)
SELECT (SELECT count(*) FROM bb.schema_ledger WHERE row_hash IS NULL) AS legacy,
       count(*) AS chained,
       count(*) FILTER (WHERE row_hash <> recomputed OR prev_hash IS DISTINCT FROM coalesce(prev_link,'')) AS broken,
       coalesce(min(id) FILTER (WHERE row_hash <> recomputed OR prev_hash IS DISTINCT FROM coalesce(prev_link,''))::text,'') AS first_broken
FROM v`

// LedgerVerify recomputes the ledger's hash chain and returns a human-readable
// summary. A non-nil error means the chain is broken (a row was deleted or
// edited after the fact) — the message says where.
func LedgerVerify(name string) (string, error) {
	if name == "" {
		name = "main"
	}
	out, err := capture("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tA", "-F", "|", "-c", LedgerVerifySQL)
	if err != nil {
		return "", fmt.Errorf("verify query: %w", err)
	}
	f := strings.Split(strings.TrimSpace(out), "|")
	if len(f) < 3 {
		return "", fmt.Errorf("unexpected verify output: %q", out)
	}
	legacy, chained, broken := f[0], f[1], f[2]
	firstBroken := ""
	if len(f) >= 4 {
		firstBroken = f[3]
	}
	if broken != "0" {
		return "", fmt.Errorf("ledger TAMPERED — %s of %s chained rows fail verification (first at id %s)",
			broken, chained, firstBroken)
	}
	msg := fmt.Sprintf("ledger intact — %s rows hash-chained and verified", chained)
	if legacy != "0" && legacy != "" {
		msg += fmt.Sprintf("; %s earlier row(s) predate tamper-evidence and are unchained", legacy)
	}
	return msg, nil
}

// captureCombined runs a privileged command and returns its combined
// stdout+stderr, so a failing psql includes the server's error text.
func captureCombined(name string, args ...string) (string, error) {
	out, err := exec.Command("sudo", append([]string{name}, args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// QueryText runs SQL on a branch and returns psql's rendered output (used by the
// MCP run_sql tool and other capture callers). On failure the returned string is
// psql's error message.
func QueryText(name, sql string) (string, error) {
	if name == "" {
		name = "main"
	}
	out, err := captureCombined("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-P", "pager=off", "-c", sql)
	if err != nil {
		return out, fmt.Errorf("%s", out)
	}
	return out, nil
}

// LedgerText returns a branch's recent Blackbox entries as rendered text —
// the "show me what I changed" view for an agent.
func LedgerText(name string, limit int) (string, error) {
	if limit <= 0 {
		limit = 50
	}
	q := fmt.Sprintf(`SELECT to_char(at,'MM-DD HH24:MI:SS') AS time,
		coalesce(actor,'-') AS actor, actor_kind AS kind, command_tag AS command,
		coalesce(object_identity,'') AS object, status, coalesce(risk,'') AS risk
		FROM bb.schema_ledger ORDER BY at DESC LIMIT %d`, limit)
	return QueryText(name, q)
}

// ErrParentNotFound: a branch was asked to be created from one that doesn't exist.
var ErrParentNotFound = errors.New("no branch to create from")

// Create makes an instant copy-on-write branch of parent (default "main") and
// starts a Postgres container serving it.
func Create(name, parent string) error {
	if parent == "" {
		parent = "main"
	}
	// Cloning a branch that doesn't exist fails deep in the storage layer with a
	// message about datasets or snapshots; say what's actually wrong.
	if !activeStorage().exists(parent) {
		return fmt.Errorf("%w: %q", ErrParentNotFound, parent)
	}
	if activeStorage().exists(name) {
		return fmt.Errorf("branch %q already exists", name)
	}
	if err := ensureNetwork(); err != nil {
		return err
	}
	// Flush the parent to disk so the clone starts from a clean checkpoint
	// (best-effort; crash recovery would handle it either way).
	quiet("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container(parent),
		"psql", "-U", pgUser, "-d", pgDatabase, "-c", "CHECKPOINT;")

	if err := activeStorage().clone(parent, name); err != nil {
		return err
	}
	if err := run("chown", "-R", pgUID+":"+pgUID, mountpoint(name)); err != nil {
		return err
	}
	if err := startContainer(name, false); err != nil {
		return err
	}
	return waitReady(name)
}

// Delete stops a branch's container and destroys its dataset and origin
// snapshot. Refuses to delete "main".
func Delete(name string) error {
	if name == "main" {
		return fmt.Errorf("refusing to delete the primary branch 'main'")
	}
	quiet("docker", "rm", "-f", container(name))
	return activeStorage().destroy(name)
}

// Reset re-creates a branch as a fresh copy-on-write clone of parent (default
// "main"), discarding everything done on it. The most-wanted operation in an
// agent workflow — start over cheaply — and near-instant on the existing
// primitives.
func Reset(name, parent string) error {
	if name == "main" {
		return fmt.Errorf("refusing to reset the primary branch 'main'")
	}
	if parent == "" {
		parent = "main"
	}
	if err := Delete(name); err != nil {
		return err
	}
	return Create(name, parent)
}

// List shows the branches and their containers.
func List() error {
	store := activeStorage()
	// The heading names what the driver can actually report: ZFS gives a
	// per-branch copy-on-write delta, btrfs does not without quota groups, and
	// promising a column that is not there reads as a bug.
	if store.name() == "zfs" {
		fmt.Println("=== branch datasets (USED shows copy-on-write delta) ===")
	} else {
		fmt.Println("=== branches (copy-on-write subvolumes) ===")
	}
	if err := store.list(); err != nil {
		return err
	}
	fmt.Println("\n=== postgres containers ===")
	return run("docker", "ps", "--filter", "name=pg-",
		"--format", "table {{.Names}}\t{{.Status}}")
}

// SQL runs a single statement against a branch (used by the demo and, later,
// the Agent Branch API).
func SQL(name, stmt string) error {
	return run("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-c", stmt)
}

// Query runs a statement against a branch and returns trimmed stdout (unaligned,
// tuples-only) for programmatic checks.
func Query(name, stmt string) (string, error) {
	out, err := exec.Command("sudo", "docker", "exec",
		"-e", "PGPASSWORD="+pgPass(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc", stmt).Output()
	return strings.TrimSpace(string(out)), err
}

// --- unified VM stack: MinIO + primary + backups + PITR ---

// objStore is the object-storage container (MinIO), which holds archived WAL
// and base backups. The name is ours, not the software's: a container called
// plainly "minio" is common on a developer's machine, and the two would collide
// -- `setup` would find that container, skip creating its own, and then look
// for it on a network it was never attached to.
const objStore = "objstore"

func objStoreRunning() bool {
	out, _ := capture("docker", "ps", "--filter", "name=^"+objStore+"$", "--format", "{{.Names}}")
	return out == objStore
}

// managedLabel marks every container this engine creates, so cleanup finds them
// by what they are rather than by what they are called. Naming conventions have
// changed with the product's name; the label does not.
const managedLabel = "dev.dbengine.managed=1"

// Up brings up the full stack: docker network, MinIO (object storage) with its
// WAL bucket, and the primary "main" branch (which archives WAL to MinIO).
func Up() error {
	if err := Provision(); err != nil {
		return err
	}
	if err := ensureNetwork(); err != nil {
		return err
	}
	if !objStoreRunning() {
		quiet("docker", "rm", "-f", objStore)
		if err := run("docker", "run", "-d",
			"--name", objStore, "--network", network,
			"--label", managedLabel,
			"-e", "MINIO_ROOT_USER="+minioUser(),
			"-e", "MINIO_ROOT_PASSWORD="+minioPass(),
			"-p", "9000:9000", "-p", "9001:9001",
			"-v", objStoreVolume+":/data",
			minioImage(), "server", "/data", "--console-address", ":9001",
		); err != nil {
			return err
		}
	}
	// Create the WAL bucket (idempotent). The wait is bounded: if the object
	// store never answers, this used to retry for ever, printing one connection
	// error per second and never saying what was wrong.
	if err := run("docker", "run", "--rm", "--network", network,
		"--entrypoint", "sh", mcImage(), "-c",
		fmt.Sprintf("for i in $(seq 1 %d); do mc alias set local http://%s:9000 %s %s >/dev/null 2>&1 && exec mc mb -p local/%s; sleep 1; done; "+
			"echo \"could not reach the object store at %s:9000 after %ds\" >&2; exit 1",
			objStoreWait, objStore, minioUser(), minioPass(), walBucket, objStore, objStoreWait),
	); err != nil {
		return fmt.Errorf("preparing the %s bucket: %w", walBucket, err)
	}
	return Init()
}

// Down stops the object store and all Postgres containers (branches + main).
// ZFS datasets and the object store's volume are preserved.
//
// Containers are found by the managed label rather than by name: a container
// left behind by an earlier version (named for whatever the product was called
// then) would otherwise survive, holding the ZFS mounts and the ports.
func Down() error {
	out, _ := capture("docker", "ps", "-a", "--filter", "label="+managedLabel, "--format", "{{.Names}}")
	names := strings.Fields(out)
	// Containers created before the label existed, by name.
	legacy, _ := capture("docker", "ps", "-a", "--format", "{{.Names}}") // legacy: pre-label naming
	for _, n := range strings.Fields(legacy) {
		if n == objStore || strings.HasPrefix(n, containerPrefix) {
			names = append(names, n)
		}
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		quiet("docker", "rm", "-f", n)
	}
	return nil
}

// Backup takes a base backup of the current primary and pushes it to object
// storage. It follows the primary pointer rather than always using pg-main:
// after `fox ha failover` main is stopped and the promoted standby holds every
// write, so a backup of main would be stale — or would simply fail.
func Backup() error {
	primary := PrimaryContainer()
	if primary != container("main") {
		fmt.Printf("backing up %s, which is serving main since the failover\n", primary)
	}
	return run("docker", "exec",
		"-e", "PGHOST=localhost", "-e", "PGUSER="+pgUser,
		"-e", "PGPASSWORD="+pgPass(), "-e", "PGDATABASE="+pgDatabase,
		primary, "wal-g", "backup-push", "/var/lib/postgresql/data/pgdata")
}

// BackupList lists base backups in object storage. It reads them from a
// throwaway container (listBaseBackups does the same for its own JSON), so the
// listing works whichever container is primary and even with the stack down --
// the backups are in object storage, not in any one container.
func BackupList() error {
	args := append([]string{"run", "--rm", "--network", network}, walgEnv()...)
	args = append(args, pgImage(), "wal-g", "backup-list", "--detail")
	return run("docker", args...)
}

// Restore performs point-in-time recovery into a disposable container on port
// 5433. ts is a timestamp within the archived WAL window, or "latest".
func Restore(ts string) error {
	name := "restore"
	backup, err := restoreBackupName(ts)
	if err != nil {
		return err
	}
	if backup != "LATEST" {
		fmt.Printf("starting from base backup %s (the newest one that precedes %s)\n", backup, ts)
	}
	quiet("docker", "rm", "-f", container(name))
	args := []string{"run", "-d",
		"--name", container(name), "--network", network,
		"--label", managedLabel,
	}
	// The same per-install object-store credentials the primary archives WAL
	// with — the store rejects anything else, so a hardcoded pair cannot fetch.
	args = append(args, walgEnv()...)
	args = append(args,
		"-e", "PGDATA=/var/lib/postgresql/data/pgdata",
		"-e", "RECOVERY_TARGET_TIME="+ts,
		"-e", "BACKUP_NAME="+backup,
		"-p", "5433:5432",
		// The script is carried in the binary and run with `bash -c`, as
		// BranchBeforeEntry does, so installs whose image predates it still get
		// the chosen base backup instead of the image's LATEST-only entrypoint.
		"--entrypoint", "bash",
		pgImage(), "-c", restorePITRScript,
	)
	if err := run("docker", args...); err != nil {
		return err
	}
	if err := waitRecovered(name); err != nil {
		return err
	}
	fmt.Printf("restored to %q, ready as container %s (port 5433). Query it with:\n"+
		"  sudo docker exec %s psql -U dbadmin -d appdb -c 'SELECT ...'\n",
		ts, container(name), container(name))
	return nil
}

func waitRecovered(name string) error {
	for i := 0; i < 40; i++ {
		if exec.Command("sudo", "docker", "exec", container(name),
			"pg_isready", "-h", "localhost", "-U", pgUser, "-d", pgDatabase).Run() == nil {
			out, _ := exec.Command("sudo", "docker", "exec",
				"-e", "PGPASSWORD="+pgPass(), container(name),
				"psql", "-h", "localhost", "-U", pgUser, "-d", pgDatabase,
				"-tAc", "SELECT pg_is_in_recovery();").Output()
			if strings.TrimSpace(string(out)) == "f" {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("restore did not complete in time")
}

// Status prints primary readiness, stored backups, and branches.
func Status() error {
	primary := PrimaryContainer()
	if primary == container("main") {
		fmt.Println("=== main readiness ===")
	} else {
		// After a failover the promoted standby serves main, so probing pg-main
		// would report the stopped container and look like an outage.
		fmt.Printf("=== main readiness (served by %s since the failover) ===\n", primary)
	}
	_ = run("docker", "exec", primary, "pg_isready", "-U", pgUser, "-d", pgDatabase)
	fmt.Println("\n=== base backups ===")
	_ = BackupList()
	fmt.Println("\n=== branches ===")
	return List()
}

// PsqlShell opens an interactive psql session on a branch.
func PsqlShell(name string) error {
	cmd := exec.Command("sudo", "docker", "exec", "-it",
		"-e", "PGPASSWORD="+pgPass(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// --- Agent Branch API support: one branch per agent ---

// Info describes an agent's branch and how to connect to it.
type Info struct {
	Agent  string `json:"agent,omitempty"`
	Branch string `json:"branch"`
	Host   string `json:"host"`
	Port   string `json:"port"`
	DSN    string `json:"dsn"`
	Status string `json:"status"`
}

func agentBranch(id string) string { return "agent-" + id }

func dsn(host, port string) string {
	return fmt.Sprintf("postgresql://%s:%s@%s:%s/%s", pgUser, pgPass(), host, port, pgDatabase)
}

// containerIP returns a container's IP on the foxbyte docker network. The
// in-guest gateway routes to it directly, so branch Postgres needs no published
// host port and stays unreachable from outside the VM.
func containerIP(cont string) (string, error) {
	out, err := capture("docker", "inspect", "-f",
		fmt.Sprintf("{{.NetworkSettings.Networks.%s.IPAddress}}", network), cont)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(out)
	if ip == "" {
		return "", fmt.Errorf("container %q has no IP on the %q network", cont, network)
	}
	return ip, nil
}

// parsePublishedPort extracts the host port from `docker port` output such as
// "0.0.0.0:32781\n[::]:32781". Retained for FOX_DEBUG_PORTS tooling.
func parsePublishedPort(out string) (string, error) {
	line := out
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		line = out[:i]
	}
	i := strings.LastIndex(line, ":")
	if i < 0 || i+1 >= len(line) {
		return "", fmt.Errorf("could not parse published port from %q", out)
	}
	return strings.TrimSpace(line[i+1:]), nil
}

// CreateAgentBranch gives agent id its own instant branch and returns how to
// connect to it.
func CreateAgentBranch(agentID string) (Info, error) {
	// Cap concurrent agent branches so an agent loop can't exhaust the pool
	// (each branch is a full Postgres). 0 disables the cap.
	if max := agentMax(); max > 0 {
		if existing, err := ListAgentBranches(); err == nil && len(existing) >= max {
			return Info{}, fmt.Errorf("agent branch limit reached (%d) — delete some or raise FOX_AGENT_MAX", max)
		}
	}
	name := agentBranch(agentID)
	if err := Create(name, "main"); err != nil {
		return Info{}, err
	}
	ip, err := containerIP(container(name))
	if err != nil {
		return Info{}, err
	}
	// Default this branch's attribution to the agent, so its Blackbox records
	// direct connections as agent activity even without the Gateway in the path.
	actor := "agent-" + strings.ReplaceAll(agentID, "'", "''")
	_ = psqlStdin(name, fmt.Sprintf(
		"ALTER DATABASE %s SET bb.actor = '%s'; ALTER DATABASE %s SET bb.actor_kind = 'agent';",
		pgDatabase, actor, pgDatabase))
	// The compatibility switch keeps the old superuser DSN over the docker
	// network, which only resolves inside the VM.
	if AgentSuperuser() {
		return Info{Agent: agentID, Branch: name, Host: ip, Port: "5432", DSN: dsn(ip, "5432"), Status: "ready"}, nil
	}
	// The agent logs in as its own non-superuser role, named like its ledger actor
	// ("agent-<id>"): it is bound by the guardrail and the ledger's append-only
	// protection, and its changes are attributed to an identity it cannot change.
	// The role's password is derived from the install secret so the Gateway can
	// log in as this role (see agent_access.go) without it being stored.
	if err := ensureLoginRole(name, name, AgentRolePassword(name)); err != nil {
		return Info{}, fmt.Errorf("creating the agent's database role: %w", err)
	}
	// The DSN goes through the Gateway, so it works from the host as well as
	// inside the VM, over TLS, with a key that opens this branch and nothing
	// else. Without the key the branch would be unreachable, so a failure here
	// takes the branch down with it rather than returning a DSN nobody can use.
	key, err := mintAgentKey(name)
	if err != nil {
		_ = Delete(name)
		return Info{}, fmt.Errorf("minting the agent's branch-scoped key: %w", err)
	}
	host, port := splitGatewayHostPort()
	return Info{Agent: agentID, Branch: name, Host: host, Port: port, DSN: agentGatewayDSN(name, key), Status: "ready"}, nil
}

// DeleteAgentBranch tears down agent id's branch and revokes the key issued
// with it, so the credential cannot outlive the database it was scoped to.
//
// Reset deliberately does not do this: a reset keeps the branch (and so the
// key's scope), and the agent goes on using the DSN it was given.
func DeleteAgentBranch(agentID string) error {
	name := agentBranch(agentID)
	revokeAgentKeys(name) // best-effort; reports its own failure
	return Delete(name)
}

// BackendAddr returns host:port where a branch's Postgres is reachable, used by
// the wire-protocol proxy to route connections. For "main" it resolves the
// container currently serving as primary (which changes after an HA failover).
func BackendAddr(name string) (string, error) {
	if name == "" {
		name = "main"
	}
	cont := container(name)
	if name == "main" {
		cont = PrimaryContainer()
	}
	ip, err := containerIP(cont)
	if err != nil {
		return "", err
	}
	return ip + ":5432", nil
}

// primaryFile records which branch container currently serves as the "main"
// primary ("main" normally, "standby" after a failover).
func primaryFile() string { return brand.StatePath("primary") }

// PrimaryContainer is the container currently acting as the "main" primary.
func PrimaryContainer() string { return container(primaryBranch()) }

// primaryBranch is the branch name now serving as primary -- "main" unless a
// failover pointed it elsewhere. Callers that need a branch name (to run SQL,
// to name it in a message) use this; those that need a container use
// PrimaryContainer.
func primaryBranch() string {
	if b, err := os.ReadFile(primaryFile()); err == nil {
		if n := strings.TrimSpace(string(b)); n != "" {
			return n
		}
	}
	return "main"
}

// setPrimary records the branch name now serving as primary.
func setPrimary(name string) error {
	_ = os.MkdirAll(filepath.Dir(primaryFile()), 0o755)
	return os.WriteFile(primaryFile(), []byte(name), 0o644)
}

// BranchInfo describes a branch for the control-plane API / dashboard.
type BranchInfo struct {
	Name        string `json:"name"`
	Primary     bool   `json:"primary"`
	Agent       bool   `json:"agent"`
	State       string `json:"state"` // running | exited | created | absent
	Used        string `json:"used"`  // copy-on-write delta (human)
	Refer       string `json:"refer"` // logical size referenced (human)
	Connections int    `json:"connections"`
	Port        string `json:"port"`
}

// Branches returns structured info for every branch (including main), enriched
// with container state, connections, and copy-on-write size.
func Branches() ([]BranchInfo, error) {
	usages, err := activeStorage().usage()
	if err != nil {
		return nil, err
	}
	var infos []BranchInfo
	for _, u := range usages {
		name := u.Name
		if strings.Contains(name, "/") {
			continue // only direct children
		}
		bi := BranchInfo{
			Name:    name,
			Used:    u.Used,
			Refer:   u.Refer,
			Primary: name == "main",
			Agent:   strings.HasPrefix(name, "agent-"),
			State:   ContainerState(name),
		}
		if bi.State == "running" {
			bi.Port = "5432" // in-container port; branches are reached via the gateway
			if c, err := ActiveConnections(name); err == nil {
				bi.Connections = c
			}
		}
		infos = append(infos, bi)
	}
	return infos, nil
}

// Storage summarises pool usage for the dashboard.
type Storage struct {
	Used  string `json:"used"`
	Avail string `json:"avail"`
}

// StorageInfo reports how much of the copy-on-write substrate is in use.
func StorageInfo() Storage {
	used, avail, err := activeStorage().capacity()
	if err != nil {
		return Storage{}
	}
	return Storage{Used: used, Avail: avail}
}

// --- auto-suspend / auto-resume ---

// ContainerState returns "running", "exited"/"created", or "absent".
func ContainerState(name string) string {
	out, err := capture("docker", "inspect", "-f", "{{.State.Status}}", container(name))
	if err != nil {
		return "absent"
	}
	return out
}

// Suspend stops a branch's container. The ZFS dataset (its data) is preserved,
// so it can be resumed later with no data loss. The primary and the HA standby
// can't be suspended (see suspendRefusal).
func Suspend(name string) error {
	if err := suspendRefusal(name, PrimaryContainer(), ContainerState("standby") != "absent"); err != nil {
		return err
	}
	return run("docker", "stop", container(name))
}

// suspendRefusal says why a branch must not be suspended: the gateway never wakes
// the primary (that could revive a stepped-down one), and the HA standby is
// managed by `fox ha` — after a failover it is the primary itself.
func suspendRefusal(name, primary string, haEnabled bool) error {
	switch {
	case name == "main":
		return fmt.Errorf("refusing to suspend the primary branch 'main': the gateway won't wake it (stop everything with `fox stop`)")
	case container(name) == primary:
		return fmt.Errorf("refusing to suspend %q: it is serving 'main' since `fox ha failover`", name)
	case name == "standby" && haEnabled:
		return fmt.Errorf("refusing to suspend the HA standby: manage it with `fox ha` (e.g. `fox ha disable`)")
	}
	return nil
}

// Resume starts a suspended branch container and waits until it is ready.
func Resume(name string) error {
	if err := run("docker", "start", container(name)); err != nil {
		return err
	}
	return waitReady(name)
}

// EnsureRunning makes sure a branch is running (resuming it if suspended) and
// returns its current backend address. Errors if the branch does not exist.
func EnsureRunning(name string) (string, error) {
	if name == "main" {
		// The primary's lifecycle is managed by `up`/`ha`. Never auto-start it
		// here — that could revive a stepped-down old primary after a failover
		// and cause split-brain. Just route to the current primary.
		return BackendAddr("main")
	}
	switch ContainerState(name) {
	case "running":
		// already up
	case "absent":
		// No container. If the dataset survives (e.g. after a full stop),
		// recreate the container on it; otherwise the branch truly doesn't exist.
		if !activeStorage().exists(name) {
			return "", fmt.Errorf("branch %q does not exist", name)
		}
		if err := startContainer(name, name == "main"); err != nil {
			return "", err
		}
		if err := waitReady(name); err != nil {
			return "", err
		}
		reconcileGuard(name)
	default: // exited, created, paused, ...
		if err := Resume(name); err != nil {
			return "", err
		}
		reconcileGuard(name)
	}
	return BackendAddr(name)
}

// Wake ensures a branch is running (resuming or recreating as needed).
func Wake(name string) error {
	_, err := EnsureRunning(name)
	return err
}

// ActiveConnections returns the number of client connections currently open to a
// branch (used to avoid suspending a branch that is in use).
func ActiveConnections(name string) (int, error) {
	out, err := capture("docker", "exec", "-e", "PGPASSWORD="+pgPass(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc",
		"SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid();")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(out))
}

// SuspendableBranches lists running branches eligible for auto-suspend (every
// pg-* container except the primary "main" and the disposable "restore").
func SuspendableBranches() ([]string, error) {
	out, err := capture("docker", "ps", "--filter", "name=pg-", "--format", "{{.Names}}")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, n := range strings.Fields(out) {
		bn := strings.TrimPrefix(n, containerPrefix)
		if bn == "main" || bn == "restore" || bn == "standby" {
			continue // primary, restore target, and HA standby never auto-suspend
		}
		names = append(names, bn)
	}
	return names, nil
}

// agentMax is the maximum number of concurrent agent branches (default 50; 0
// disables the cap). Set FOX_AGENT_MAX to override.
func agentMax() int {
	if v := brand.Getenv("AGENT_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 50
}

// ReapAgentBranches deletes agent branches whose container is older than maxAge
// (0 disables). Returns how many were reaped. Abandoned agent sandboxes would
// otherwise accumulate and hold pool space forever.
func ReapAgentBranches(maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		return 0, nil
	}
	// -a: a suspended agent branch still holds its storage, so it must be
	// reaped like a running one (the Gateway suspends idle branches, so an
	// abandoned sandbox is usually stopped, not running).
	out, err := capture("docker", "ps", "-a", "--filter", "name=pg-agent-", "--format", "{{.Names}}")
	if err != nil {
		return 0, err
	}
	reaped := 0
	for _, cont := range strings.Fields(out) {
		createdStr, err := capture("docker", "inspect", "-f", "{{.Created}}", cont)
		if err != nil {
			continue
		}
		created, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(createdStr))
		if err != nil {
			continue
		}
		if time.Since(created) <= maxAge {
			continue
		}
		agentID := strings.TrimPrefix(strings.TrimPrefix(cont, containerPrefix), "agent-")
		if err := DeleteAgentBranch(agentID); err == nil {
			reaped++
		}
	}
	return reaped, nil
}

// ListAgentBranches lists the agent branches, running or suspended. A suspended
// branch still exists and still holds storage, and the Gateway wakes it on
// connect, so leaving it out would hide it from the cap, from the reaper and
// from anyone asking what exists.
func ListAgentBranches() ([]Info, error) {
	out, err := capture("docker", "ps", "-a", "--filter", "name=pg-agent-", "--format", "{{.Names}}")
	if err != nil {
		return nil, err
	}
	var infos []Info
	for _, n := range strings.Fields(out) {
		bn := strings.TrimPrefix(n, containerPrefix)
		// The DSN carries no key: it is shown once, when the branch is created.
		// The legacy switch keeps the old superuser DSN over the docker network.
		d := agentGatewayDSN(bn, "")
		host, port := splitGatewayHostPort()
		if AgentSuperuser() {
			ip, _ := containerIP(n)
			d, host, port = dsn(ip, "5432"), ip, "5432"
		}
		status := "ready"
		if ContainerState(bn) != "running" {
			status = "suspended"
		}
		infos = append(infos, Info{
			Agent:  strings.TrimPrefix(bn, "agent-"),
			Branch: bn, Host: host, Port: port, DSN: d, Status: status,
		})
	}
	return infos, nil
}
