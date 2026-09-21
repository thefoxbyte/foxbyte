// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Blackbox 2.0: branch from just before a ledger entry.
//
// Given a ledger entry on main, BranchBeforeEntry builds a new branch holding
// main exactly as it was the moment before that change committed: it restores
// the newest base backup that finished before the change and replays archived
// WAL up to — but not including — the change's transaction (the xid recorded in
// bb.ledger_ext). Entries from before the 2.0 capture existed have no xid, so
// the entry's timestamp is used instead.
//
// The new branch is an ordinary branch afterwards (same container, gateway
// routing, suspend/resume and delete as any other). main is never modified;
// the only thing asked of it is a WAL segment switch so the change's commit is
// archived before recovery looks for it.
//
// This takes minutes, not seconds: a base backup is fetched and WAL replayed.

//go:embed restore_before.sh
var restoreBeforeScript string

// Errors a caller (REST, MCP) may want to tell apart.
var (
	ErrEntryNotFound  = errors.New("ledger entry not found")
	ErrBranchExists   = errors.New("branch already exists")
	ErrInvalidRequest = errors.New("invalid request")
	ErrNoBaseBackup   = errors.New("no usable base backup")
)

// BeforeEntryResult describes the branch BranchBeforeEntry created.
type BeforeEntryResult struct {
	Branch       string `json:"branch"`
	Source       string `json:"source"`
	EntryID      int64  `json:"entry_id"`
	CommandTag   string `json:"command_tag"`
	Object       string `json:"object_identity"`
	Statement    string `json:"statement"`
	TargetKind   string `json:"target_kind"` // "xid" (exact) or "time" (entry recorded before 2.0 capture)
	Target       string `json:"target"`
	BaseBackup   string `json:"base_backup"`
	LastLedgerID int64  `json:"last_ledger_id"` // newest ledger entry present on the new branch
	Seconds      int    `json:"seconds"`
}

// beforeEntry is the ledger entry being branched before.
type beforeEntry struct {
	ID             int64
	Status         string
	CommandTag     string
	ObjectIdentity string
	Statement      string
	At             time.Time
	XID            int64  // 0 when not captured
	LSN            uint64 // 0 when not captured
}

// walgBackup is one entry of `wal-g backup-list --json --detail`.
type walgBackup struct {
	Name       string      `json:"backup_name"`
	StartTime  time.Time   `json:"start_time"`
	FinishTime time.Time   `json:"finish_time"`
	FinishLSN  json.Number `json:"finish_lsn"`
	SystemID   json.Number `json:"system_identifier"`
	// Compressed size as stored, when wal-g reports it (--detail does).
	CompressedSize json.Number `json:"compressed_size"`
}

var (
	// The same rule the control plane applies to branch names.
	beforeNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	backupNameRe = regexp.MustCompile(`^base_[0-9A-F]{24}(_D_[0-9A-F]{24})?$`)
	targetTimeRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d{1,6})?\+00$`)
	targetXIDRe  = regexp.MustCompile(`^\d+$`)

	// One branch-before at a time: each is a full restore.
	branchBeforeMu sync.Mutex
)

// DefaultBeforeName is the branch name used when none is given.
func DefaultBeforeName(src string, entryID int64) string {
	return fmt.Sprintf("%s-before-%d", src, entryID)
}

func validateBeforeName(name string) error {
	if !beforeNameRe.MatchString(name) {
		return fmt.Errorf("%w: invalid branch name %q (use lowercase letters, digits, dashes)", ErrInvalidRequest, name)
	}
	switch {
	case name == "main" || name == "restore" || name == "standby":
		return fmt.Errorf("%w: %q is a reserved branch name", ErrInvalidRequest, name)
	case strings.HasPrefix(name, "agent-"):
		return fmt.Errorf("%w: names starting with agent- are reserved for agent branches", ErrInvalidRequest)
	}
	return nil
}

// entryQuery reads one ledger entry with its captured xid and WAL position (as
// a byte offset), as a single JSON line.
func entryQuery(entryID int64, withExt bool) string {
	xid, lsn, join := "NULL::bigint", "NULL::text", ""
	if withExt {
		xid, lsn = "e.xid", "(e.lsn - '0/0'::pg_lsn)::text"
		join = " LEFT JOIN bb.ledger_ext e ON e.ledger_id = l.id"
	}
	return fmt.Sprintf(`SELECT json_build_object('id', l.id, 'status', l.status, 'command_tag', l.command_tag,
  'object_identity', l.object_identity, 'statement', l.statement,
  'at', to_char(l.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'xid', %s, 'lsn', %s)
FROM bb.schema_ledger l%s WHERE l.id = %d`, xid, lsn, join, entryID)
}

func parseEntryJSON(line string) (beforeEntry, error) {
	var j struct {
		ID             int64   `json:"id"`
		Status         *string `json:"status"`
		CommandTag     *string `json:"command_tag"`
		ObjectIdentity *string `json:"object_identity"`
		Statement      *string `json:"statement"`
		At             string  `json:"at"`
		XID            *int64  `json:"xid"`
		LSN            *string `json:"lsn"`
	}
	if err := json.Unmarshal([]byte(line), &j); err != nil {
		return beforeEntry{}, fmt.Errorf("reading the ledger entry: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, j.At)
	if err != nil {
		return beforeEntry{}, fmt.Errorf("reading the ledger entry time %q: %w", j.At, err)
	}
	s := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	e := beforeEntry{ID: j.ID, Status: s(j.Status), CommandTag: s(j.CommandTag),
		ObjectIdentity: s(j.ObjectIdentity), Statement: s(j.Statement), At: at}
	if j.XID != nil {
		e.XID = *j.XID
	}
	if j.LSN != nil && *j.LSN != "" {
		if e.LSN, err = strconv.ParseUint(*j.LSN, 10, 64); err != nil {
			return beforeEntry{}, fmt.Errorf("reading the ledger entry WAL position %q: %w", *j.LSN, err)
		}
	}
	return e, nil
}

// recoveryTarget returns the recovery target for an entry: its transaction id
// when captured (exact), otherwise its timestamp. recovery_target_xid takes the
// 32-bit transaction id, so the epoch txid_current() includes is dropped.
func recoveryTarget(e beforeEntry) (kind, value string) {
	if e.XID > 0 {
		return "xid", strconv.FormatUint(uint64(e.XID)&0xffffffff, 10)
	}
	return "time", e.At.UTC().Format("2006-01-02 15:04:05.999999") + "+00"
}

// parseBackups decodes `wal-g backup-list --json --detail` output, tolerating
// log lines before the JSON (which can contain brackets themselves, as in
// "List backups from storages: [default]") and an empty listing.
func parseBackups(out []byte) ([]walgBackup, error) {
	off := 0
	for _, line := range strings.SplitAfter(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			var bs []walgBackup
			if err := json.Unmarshal(out[off:], &bs); err != nil {
				return nil, fmt.Errorf("reading the base backup list: %w", err)
			}
			return bs, nil
		}
		off += len(line)
	}
	return nil, nil
}

// pickBaseBackup chooses the newest base backup of this database (same system
// identifier) that finished before the entry's change: by WAL position when the
// entry's position was captured, otherwise by time. Recovery can only start
// from a backup that is already consistent before its target.
func pickBaseBackup(bs []walgBackup, systemID string, e beforeEntry) (walgBackup, error) {
	var best walgBackup
	found := false
	for _, b := range bs {
		if !backupNameRe.MatchString(b.Name) {
			continue
		}
		if systemID != "" && b.SystemID.String() != systemID {
			continue // a backup of an earlier, re-initialised database
		}
		if e.LSN > 0 {
			fin, err := strconv.ParseUint(b.FinishLSN.String(), 10, 64)
			if err != nil || fin > e.LSN {
				continue
			}
		} else if !b.FinishTime.Before(e.At) {
			continue
		}
		if !found || b.FinishTime.After(best.FinishTime) {
			best, found = b, true
		}
	}
	if !found {
		return walgBackup{}, fmt.Errorf("%w: no base backup of this database finished before ledger entry %d (%s) — "+
			"take one with `fox backup create`; only changes made after a base backup can be branched before",
			ErrNoBaseBackup, e.ID, e.At.UTC().Format(time.RFC3339))
	}
	return best, nil
}

// walArchived reports whether lastArchived (pg_stat_archiver.last_archived_wal)
// is at or past segment. History and .partial files compare by their first 24
// characters; anything shorter is not a WAL segment.
func walArchived(lastArchived, segment string) bool {
	if len(lastArchived) < 24 || len(segment) < 24 {
		return false
	}
	return lastArchived[:24] >= segment[:24]
}

// walArchiveFile records, in main's dataset but outside PGDATA, where this
// cluster's WAL and base backups live in the bucket. It is absent on every
// install that has never been through `fox pg upgrade`, which archives to the
// bucket's root as it always has.
//
// An upgrade starts a new cluster whose WAL numbering begins again, so its
// segment names would collide with the old cluster's in the same place — and a
// rollback would find its own archive overwritten. Each upgraded cluster gets a
// prefix of its own, written into main's dataset so it follows the data: after
// a rollback the old main has no such file, and archives to the root again.
const walArchiveFile = "wal-archive-prefix"

var walPrefixRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// walgPrefixFor turns the file's contents into a WALG_S3_PREFIX: the bucket's
// root for no file, or for anything that is not a plain path segment.
func walgPrefixFor(contents string) string {
	seg := strings.TrimSpace(contents)
	if !walPrefixRe.MatchString(seg) {
		return "s3://" + walBucket
	}
	return "s3://" + walBucket + "/" + seg
}

// walgPrefix is this install's archive location, read from main's dataset
// whichever branch is primary: after a failover the standby serves main, but
// its data is a copy of main's PGDATA and does not carry the file.
func walgPrefix() string {
	out, err := capture("cat", filepath.Join(mountpoint("main"), walArchiveFile))
	if err != nil {
		return walgPrefixFor("")
	}
	return walgPrefixFor(out)
}

func walgEnv() []string { return walgEnvFor(walgPrefix()) }

func walgEnvFor(prefix string) []string {
	return []string{
		"-e", "WALG_S3_PREFIX=" + prefix,
		"-e", "AWS_ACCESS_KEY_ID=" + minioUser(),
		"-e", "AWS_SECRET_ACCESS_KEY=" + minioPass(),
		"-e", "AWS_ENDPOINT=" + objStoreEndpoint,
		"-e", "AWS_S3_FORCE_PATH_STYLE=true",
		"-e", "AWS_REGION=us-east-1",
	}
}

// listBaseBackups lists base backups from a throwaway container, so it works
// whichever container is primary and whatever environment it was started with.
func listBaseBackups() ([]walgBackup, error) {
	args := append([]string{"docker", "run", "--rm", "--network", network}, walgEnv()...)
	args = append(args, pgImage(), "wal-g", "backup-list", "--json", "--detail")
	out, err := exec.Command("sudo", args...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "No backups found") {
			return nil, nil
		}
		return nil, fmt.Errorf("listing base backups: %w", err)
	}
	return parseBackups(out)
}

// flushWALArchive makes sure every WAL record written so far — including the
// entry's commit — is archived, by switching to a new WAL segment and waiting
// for the archiver to ship the old one.
func flushWALArchive(primary string) error {
	lines, err := ledgerLines(primary, "SELECT current_setting('archive_mode') || '|' || pg_walfile_name(pg_current_wal_lsn())")
	if err != nil || len(lines) == 0 {
		return fmt.Errorf("reading the primary's WAL position: %v", err)
	}
	f := strings.SplitN(lines[0], "|", 2)
	if len(f) != 2 || f[0] == "off" {
		return fmt.Errorf("the primary is not archiving WAL, so there is no history to restore from")
	}
	segment := f[1]
	if _, err := ledgerLines(primary, "SELECT pg_switch_wal()"); err != nil {
		return fmt.Errorf("switching WAL segment: %w", err)
	}
	deadline := time.Now().Add(envDurationOr("FOX_WAL_ARCHIVE_WAIT", 2*time.Minute))
	for {
		lines, err := ledgerLines(primary, "SELECT coalesce(last_archived_wal, '') || '|' || coalesce(last_failed_wal, '') FROM pg_stat_archiver")
		if err == nil && len(lines) > 0 {
			st := strings.SplitN(lines[0]+"|", "|", 3)
			if walArchived(st[0], segment) {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("WAL segment %s was not archived in time (last archived %q, last failed %q)", segment, st[0], st[1])
			}
		} else if time.Now().After(deadline) {
			return fmt.Errorf("WAL segment %s was not archived in time: %v", segment, err)
		}
		time.Sleep(time.Second)
	}
}

// containerLogTail returns the last lines of a container's output, for errors.
func containerLogTail(name string, n int) string {
	out, _ := exec.Command("sudo", "docker", "logs", "--tail", strconv.Itoa(n), container(name)).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// waitPromoted waits for a restore container to finish recovery and promote,
// failing early if the container stops (for example when the target is never
// reached in the archived WAL).
func waitPromoted(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		switch st := ContainerState(name); st {
		case "running", "created", "restarting":
			out, _ := exec.Command("sudo", "docker", "exec", "-e", "PGPASSWORD="+pgPass(), container(name),
				"psql", "-h", "localhost", "-U", pgUser, "-d", pgDatabase, "-tAc", "SELECT pg_is_in_recovery()").Output()
			if strings.TrimSpace(string(out)) == "f" {
				return nil
			}
		default:
			return fmt.Errorf("the restore stopped (%s) before reaching its target:\n%s", st, containerLogTail(name, 15))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the restore did not finish within %s (set FOX_BRANCH_BEFORE_TIMEOUT to wait longer):\n%s",
				timeout, containerLogTail(name, 15))
		}
		time.Sleep(2 * time.Second)
	}
}

// BranchBeforeEntry creates branch newName (default "<src>-before-<id>") holding
// src exactly as it was just before ledger entry entryID committed. Only main
// can be branched from, because only the primary archives WAL. logf, if not
// nil, receives progress messages.
func BranchBeforeEntry(src string, entryID int64, newName string, logf func(format string, a ...any)) (BeforeEntryResult, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	started := time.Now()
	if src == "" {
		src = "main"
	}
	if src != "main" {
		return BeforeEntryResult{}, fmt.Errorf("%w: only main can be branched before an entry — it is the only branch that archives WAL", ErrInvalidRequest)
	}
	if entryID <= 0 {
		return BeforeEntryResult{}, fmt.Errorf("%w: entry id must be a positive ledger id", ErrInvalidRequest)
	}
	if newName == "" {
		newName = DefaultBeforeName(src, entryID)
	}
	if err := validateBeforeName(newName); err != nil {
		return BeforeEntryResult{}, err
	}

	branchBeforeMu.Lock()
	defer branchBeforeMu.Unlock()

	store := activeStorage()
	if store.exists(newName) || ContainerState(newName) != "absent" {
		return BeforeEntryResult{}, fmt.Errorf("%w: %q", ErrBranchExists, newName)
	}
	primary := strings.TrimPrefix(PrimaryContainer(), containerPrefix)

	// 1. The entry, with its transaction id and WAL position when captured.
	ext, _, err := ledgerV2Tables(primary)
	if err != nil {
		return BeforeEntryResult{}, err
	}
	lines, err := ledgerLines(primary, entryQuery(entryID, ext))
	if err != nil {
		return BeforeEntryResult{}, err
	}
	if len(lines) == 0 {
		return BeforeEntryResult{}, fmt.Errorf("%w: no entry %d in %s's ledger", ErrEntryNotFound, entryID, src)
	}
	e, err := parseEntryJSON(lines[0])
	if err != nil {
		return BeforeEntryResult{}, err
	}
	if e.Status == "BLOCKED" {
		return BeforeEntryResult{}, fmt.Errorf("%w: entry %d was BLOCKED — that change never happened, so there is nothing to branch before", ErrInvalidRequest, entryID)
	}
	kind, target := recoveryTarget(e)
	if kind == "time" {
		logf("entry %d has no captured transaction id (recorded before Blackbox 2.0 capture); using its time %s", entryID, target)
	}

	// 2. Make sure the change's commit is archived, then pick the base backup.
	logf("archiving the primary's current WAL segment")
	if err := flushWALArchive(primary); err != nil {
		return BeforeEntryResult{}, err
	}
	sys, err := ledgerLines(primary, "SELECT system_identifier::text FROM pg_control_system()")
	if err != nil || len(sys) == 0 {
		return BeforeEntryResult{}, fmt.Errorf("reading the primary's system identifier: %v", err)
	}
	backups, err := listBaseBackups()
	if err != nil {
		return BeforeEntryResult{}, err
	}
	b, err := pickBaseBackup(backups, sys[0], e)
	if err != nil {
		return BeforeEntryResult{}, err
	}
	if kind == "xid" && !targetXIDRe.MatchString(target) ||
		kind == "time" && !targetTimeRe.MatchString(target) {
		return BeforeEntryResult{}, fmt.Errorf("unexpected recovery target %q", target)
	}
	logf("restoring base backup %s (finished %s), then replaying WAL to just before %s %s",
		b.Name, b.FinishTime.UTC().Format(time.RFC3339), kind, target)

	// 3. Restore into a new, empty branch. Anything created from here on is
	// removed again if a later step fails.
	if err := ensureNetwork(); err != nil {
		return BeforeEntryResult{}, err
	}
	if err := store.createEmpty(newName); err != nil {
		return BeforeEntryResult{}, fmt.Errorf("creating storage for %q: %w", newName, err)
	}
	fail := func(err error) (BeforeEntryResult, error) {
		quiet("docker", "rm", "-f", container(newName))
		if derr := store.destroy(newName); derr != nil {
			err = fmt.Errorf("%w (and removing the partial branch failed: %v)", err, derr)
		}
		return BeforeEntryResult{}, err
	}
	args := append([]string{"docker", "run", "-d", "--name", container(newName), "--network", network}, walgEnv()...)
	args = append(args,
		"-e", "PGDATA=/var/lib/postgresql/data/pgdata",
		"-e", "BACKUP_NAME="+b.Name,
		"-e", "RECOVERY_TARGET_KIND="+kind,
		"-e", "RECOVERY_TARGET="+target,
		"-v", mountpoint(newName)+":/var/lib/postgresql/data",
		"--entrypoint", "bash",
		pgImage(), "-c", restoreBeforeScript)
	if out, err := exec.Command("sudo", args...).CombinedOutput(); err != nil {
		return fail(fmt.Errorf("starting the restore: %v: %s", err, strings.TrimSpace(string(out))))
	}
	if err := waitPromoted(newName, envDurationOr("FOX_BRANCH_BEFORE_TIMEOUT", 15*time.Minute)); err != nil {
		return fail(err)
	}

	// 4. The change must not be there.
	present, err := ledgerLines(newName, fmt.Sprintf("SELECT count(*) FROM bb.schema_ledger WHERE id = %d", entryID))
	if err != nil {
		return fail(fmt.Errorf("checking the restored ledger: %w", err))
	}
	if len(present) == 0 || present[0] != "0" {
		return fail(fmt.Errorf("the restored branch still contains ledger entry %d; not keeping it", entryID))
	}
	var last int64
	if l, err := ledgerLines(newName, "SELECT coalesce(max(id), 0) FROM bb.schema_ledger"); err == nil && len(l) > 0 {
		last, _ = strconv.ParseInt(l[0], 10, 64)
	}

	// 5. Drop the recovery settings and serve it as an ordinary branch.
	for _, g := range []string{"restore_command", "recovery_target_xid", "recovery_target_time",
		"recovery_target_inclusive", "recovery_target_action", "archive_mode"} {
		if _, err := ledgerLines(newName, "ALTER SYSTEM RESET "+g); err != nil {
			return fail(fmt.Errorf("clearing recovery setting %s: %w", g, err))
		}
	}
	logf("recovered; starting %q as a normal branch", newName)
	quiet("docker", "stop", "-t", "60", container(newName))
	if err := startContainer(newName, false); err != nil {
		return fail(err)
	}
	if err := waitReady(newName); err != nil {
		return fail(err)
	}
	reconcileGuard(newName)

	return BeforeEntryResult{
		Branch: newName, Source: src, EntryID: entryID,
		CommandTag: e.CommandTag, Object: e.ObjectIdentity, Statement: e.Statement,
		TargetKind: kind, Target: target, BaseBackup: b.Name,
		LastLedgerID: last, Seconds: int(time.Since(started).Seconds()),
	}, nil
}
