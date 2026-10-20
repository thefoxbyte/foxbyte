// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// ---- setting the target ----

// CheckTarget reaches a target's bucket and reports its Object Lock default
// retention ("" when the bucket has none). It uses the target's own
// credentials, before anything is saved.
func CheckTarget(t Target) (lock string, err error) {
	env := envFile("mc-check.env", mcEnvContent(t))
	defer os.Remove(env)
	out, err := captureCombined("docker", "run", "--rm", "--network", network, "--env-file", env,
		"--entrypoint", "sh", mcImage(), "-c",
		// Reaching the bucket is required; asking for its lock is not — a bucket
		// without Object Lock answers that question with an error.
		fmt.Sprintf("mc ls t/%s >/dev/null || exit 3; mc retention info --default t/%s 2>&1; exit 0", t.Bucket, t.Bucket))
	if err != nil {
		return "", fmt.Errorf("cannot reach %s with those keys: %s", t.Root(), strings.TrimSpace(out))
	}
	out = strings.TrimSpace(out)
	if strings.Contains(strings.ToLower(out), "not") || out == "" {
		return "", nil // no Object Lock configuration
	}
	return out, nil
}

// SetBackupTarget moves the WAL archive and base backups to t: it checks the
// bucket, saves the target, restarts main so its archive_command uses it,
// takes the first base backup there, and copies the anchors across. The old
// target's backups stay where they are; restores read from the target in
// force, so a point before the move is restored after moving back.
func SetBackupTarget(t Target, allowHTTP bool) error {
	if t.Remote() {
		if err := t.Validate(allowHTTP); err != nil {
			return err
		}
	}
	if st := ContainerState("standby"); st != "absent" {
		return fmt.Errorf("high availability is on: its standby archives too — run `%s ha disable` first", brand.CLI)
	}
	if t.Remote() {
		fmt.Printf("Checking %s …\n", t.Root())
		lock, err := CheckTarget(t)
		if err != nil {
			return err
		}
		if lock == "" {
			fmt.Println("  reachable. The bucket has no Object Lock retention: anyone holding its keys can delete the backups.")
			fmt.Println("  For backups that cannot be deleted, create the bucket with Object Lock and a default retention.")
		} else {
			fmt.Printf("  reachable, with Object Lock: %s\n", firstLine(lock))
		}
	}
	if err := SaveTarget(t); err != nil {
		return err
	}
	fmt.Printf("Backups now go to %s.\n", t.Describe())
	// main's archive settings are fixed when its container starts.
	fmt.Println("Restarting main so it archives there …")
	removeContainer(PrimaryContainer())
	// Up takes the first base backup on a target that has none (ensureFirstBackup).
	if err := Up(); err != nil {
		return fmt.Errorf("restarting main: %w", err)
	}
	if newest, err := NewestBackup(); err != nil || newest.IsZero() {
		return fmt.Errorf("the target is set, but it holds no base backup yet (%v) — take one with `%s backup create`", err, brand.CLI)
	}
	if n, err := MirrorAnchors(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: copying anchors to the target: %v\n", err)
	} else if n > 0 {
		fmt.Printf("Copied %d anchor(s) to the target.\n", n)
	}
	return nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

// ---- anchors off the machine (audit v2 G17) ----

const mirroredSuffix = ".mirrored"

func anchorBase() string {
	base := strings.TrimSpace(brand.Getenv("ANCHOR_DIR"))
	if base == "" {
		base = brand.StatePath("anchors")
	}
	return base
}

// MirrorAnchors copies every anchor not yet copied — each branch's and the
// security log's — off this machine, and marks each one copied. Two places, and
// either may be absent:
//
//   - the backup target's bucket, under <target>/anchors/, as it always has;
//     protected only by whatever retention that bucket has by default;
//   - the anchor target (anchortarget.go), each anchor locked in COMPLIANCE mode
//     for the target's retention, so that nobody can delete or rewrite it.
//
// It returns how many copies it made. A failure at one place does not stop the
// other.
func MirrorAnchors() (int, error) {
	var n int
	var errs []error
	if t := target(); t.Remote() {
		c, err := mirrorAnchorsTo(t, mcEnvFile(), mirroredSuffix, "")
		n += c
		if err != nil {
			errs = append(errs, fmt.Errorf("backup target: %w", err))
		}
	}
	at, ok, err := CurrentAnchorTarget()
	if err != nil {
		errs = append(errs, fmt.Errorf("anchor target: %w", err))
	} else if ok {
		c, err := mirrorAnchorsTo(at.Target, envFile("mc-anchor.env", mcEnvContent(at.Target)), lockedSuffix, retentionFlags(at.RetentionDays))
		n += c
		if err != nil {
			errs = append(errs, fmt.Errorf("anchor target: %w", err))
		}
	}
	return n, errors.Join(errs...)
}

// mirrorAnchorsTo copies the anchors that have no <suffix> marker to t's
// <root>/anchors/<dir>/, passing cpFlags to mc cp, and writes the marker for
// each copied.
func mirrorAnchorsTo(t Target, env, suffix, cpFlags string) (int, error) {
	base := anchorBase()
	dirs, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dir := filepath.Join(base, d.Name())
		files, _ := os.ReadDir(dir)
		var pending []string
		for _, f := range files {
			name := f.Name()
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			if _, err := os.Stat(filepath.Join(dir, name+suffix)); err == nil {
				continue
			}
			pending = append(pending, name)
		}
		if len(pending) == 0 {
			continue
		}
		dest := strings.TrimPrefix(t.Root(), "s3://") + "/anchors/" + d.Name() + "/"
		var cmds []string
		for _, name := range pending {
			cmds = append(cmds, strings.Join(strings.Fields(fmt.Sprintf("mc cp --quiet %s /anchors/%s t/%s%s", cpFlags, name, dest, name)), " "))
		}
		if out, err := captureCombined("docker", "run", "--rm", "--network", network, "--env-file", env,
			"-v", dir+":/anchors:ro", "--entrypoint", "sh", mcImage(), "-c", "set -e; "+strings.Join(cmds, "; ")); err != nil {
			return n, fmt.Errorf("%s: %s", d.Name(), strings.TrimSpace(out))
		}
		for _, name := range pending {
			_ = os.WriteFile(filepath.Join(dir, name+suffix), nil, 0o444)
			n++
		}
	}
	return n, nil
}

// ---- the schedule (audit v2 G19) ----

// backupInterval is FOX_BACKUP_INTERVAL: how old the newest base backup may
// get before the control plane takes another (24h by default; "off" stops the
// schedule).
func backupInterval() time.Duration {
	v := strings.ToLower(strings.TrimSpace(brand.Getenv("BACKUP_INTERVAL")))
	switch v {
	case "off", "0", "false", "no":
		return 0
	}
	if d, err := time.ParseDuration(v); err == nil && d >= time.Minute {
		return d
	}
	return 24 * time.Hour
}

// backupRetain is FOX_BACKUP_RETAIN: how many full base backups to keep, with
// the WAL they need (7 by default, never fewer than 1).
func backupRetain() int {
	if n, err := strconv.Atoi(strings.TrimSpace(brand.Getenv("BACKUP_RETAIN"))); err == nil && n >= 1 {
		return n
	}
	return 7
}

// NewestBackup is the finish time of the newest base backup of this cluster
// (zero when there is none).
func NewestBackup() (time.Time, error) { return newestBackupWithin(execQuick) }

// newestBackupWithin is NewestBackup bounded by d, for a caller that would
// rather have no answer than wait for one.
func newestBackupWithin(d time.Duration) (time.Time, error) {
	bs, err := backupsWithin(d)
	if err != nil || len(bs) == 0 {
		return time.Time{}, err
	}
	return time.Parse("2006-01-02T15:04:05Z", bs[0].FinishedAt)
}

// BackupHealth summarises the newest backup for status displays: its age, and
// whether it is older than twice the schedule (or missing).
type BackupHealth struct {
	Newest   string `json:"newest,omitempty"`
	AgeHours int    `json:"age_hours"`
	Stale    bool   `json:"stale"`
	Target   string `json:"target"`
	Remote   bool   `json:"remote"`
	Schedule string `json:"schedule"`
	// Unknown separates "there are no backups" from "nobody could be asked".
	// They read the same in every earlier version of this struct — an empty
	// Newest — and they are opposite findings: one is a fresh install with
	// nothing to restore, the other is an install whose backups may be perfectly
	// fine behind a store that cannot be reached. Why is in Err.
	Unknown bool   `json:"unknown,omitempty"`
	Err     string `json:"error,omitempty"`
}

// CurrentBackupHealth reads the newest backup and judges it.
func CurrentBackupHealth() BackupHealth { return backupHealthWithin(execQuick) }

// CurrentBackupHealthProbe is the same judgement for a caller that must answer
// quickly whatever the state of the install — `fox check`. It gives the listing
// d (the probe tier when that is not positive) rather than the minutes a
// command doing real work is allowed, and says so when that was not enough.
func CurrentBackupHealthProbe(d time.Duration) BackupHealth {
	if d <= 0 {
		d = execProbe
	}
	return backupHealthWithin(d)
}

// backupHealthWithin judges the newest backup, giving the listing at most d.
func backupHealthWithin(d time.Duration) BackupHealth {
	return backupHealth(target(), objStoreRunning, func() (time.Time, error) { return newestBackupWithin(d) })
}

// backupHealth is the judgement, given the target, a way to ask whether the
// local object store is up, and a way to read the newest backup. Functions
// rather than values so neither question is put unless it decides the answer —
// and so this is testable without a pool, which the state behind it is not.
func backupHealth(t Target, localStoreUp func() bool, newestBackup func() (time.Time, error)) BackupHealth {
	h := BackupHealth{Target: t.Describe(), Remote: t.Remote(), Schedule: "off"}
	iv := backupInterval()
	if iv > 0 {
		h.Schedule = "every " + iv.String()
	}
	// The local object store is a container of this install's own. With it gone
	// the bucket is not there to answer, and asking anyway spends the whole
	// deadline discovering that — so the reason is reported instead of waited
	// for. A remote target is still asked: answering with the stack down is the
	// point of having one.
	if !t.Remote() && !localStoreUp() {
		h.Stale, h.Unknown = true, true
		h.Err = "the local object store is not running, so the backups it holds cannot be listed"
		return h
	}
	newest, err := newestBackup()
	if err != nil {
		// Stale as well, which is what every earlier version said about a
		// listing that failed: a reader that does not know about Unknown keeps
		// the judgement it had.
		h.Stale, h.Unknown = true, true
		h.Err = firstLine(err.Error())
		return h
	}
	if newest.IsZero() {
		h.Stale = true
		return h
	}
	h.Newest = newest.UTC().Format(time.RFC3339)
	age := time.Since(newest)
	h.AgeHours = int(age.Hours())
	limit := 2 * iv
	if iv == 0 {
		limit = 48 * time.Hour
	}
	h.Stale = age > limit
	return h
}

// Prune keeps the newest keep full base backups and the WAL they need, and
// deletes older ones. With an Object Lock bucket, objects still under
// retention stay whatever this asks.
func Prune(keep int) error {
	if keep < 1 {
		keep = 1
	}
	args := append([]string{"run", "--rm", "--network", network}, walgEnv()...)
	args = append(args, pgImage(), "wal-g", "delete", "retain", "FULL", strconv.Itoa(keep), "--confirm")
	return run("docker", args...)
}

// StartBackupScheduler takes a base backup whenever the newest is older than
// FOX_BACKUP_INTERVAL, then prunes to FOX_BACKUP_RETAIN, checking every ten
// minutes. Point-in-time restore reaches back only as far as the oldest base
// backup it can start from, and before this backups were taken only when
// someone ran `fox backup create`.
func StartBackupScheduler() {
	iv := backupInterval()
	if iv == 0 {
		log.Printf("backups: schedule off (FOX_BACKUP_INTERVAL)")
		return
	}
	check := 10 * time.Minute
	if iv < check {
		check = iv
	}
	log.Printf("backups: a base backup when the newest is older than %s; keeping %d", iv, backupRetain())
	go func() {
		time.Sleep(time.Minute) // let the stack settle after a start
		for {
			backupIfDue(iv)
			time.Sleep(check)
		}
	}()
}

func backupIfDue(iv time.Duration) {
	if ContainerState(strings.TrimPrefix(PrimaryContainer(), containerPrefix)) != "running" {
		return
	}
	newest, err := NewestBackup()
	if err != nil {
		log.Printf("backups: listing: %v", err)
		return
	}
	if !newest.IsZero() && time.Since(newest) < iv {
		return
	}
	log.Printf("backups: taking a scheduled base backup")
	if err := Backup(); err != nil {
		log.Printf("backups: scheduled backup failed: %v", err)
		return
	}
	if err := Prune(backupRetain()); err != nil {
		log.Printf("backups: pruning to %d: %v", backupRetain(), err)
	}
	if _, err := MirrorAnchors(); err != nil {
		log.Printf("backups: copying anchors to the target: %v", err)
	}
}

// ensureFirstBackup takes a base backup when this cluster has none, so a new
// install can restore to a point in time from its first minutes, not only
// after someone remembers `fox backup create`.
func ensureFirstBackup() {
	newest, err := NewestBackup()
	if err != nil || !newest.IsZero() {
		return
	}
	fmt.Println("Taking the first base backup, so point-in-time restore has a starting point …")
	if err := Backup(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: the first base backup failed: %v — take one with `%s backup create`\n", err, brand.CLI)
	}
}
