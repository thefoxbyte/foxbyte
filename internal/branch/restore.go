// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	_ "embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Point-in-time restore (fox restore --to).
//
// Recovery can only start from a base backup that is already consistent before
// the point being asked for. The restore used to fetch LATEST whatever the
// target was, so a timestamp earlier than the newest base backup could not be
// reached at all: Postgres would refuse with "recovery ended before target
// reached" (or start after the point asked for). The backup is chosen here
// instead, the same way BranchBeforeEntry chooses one.

//go:embed restore_pitr.sh
var restorePITRScript string

// restoreTimeLayouts are the shapes a target timestamp may be written in. A
// timestamp with no zone is read as UTC, which is what the Postgres containers
// run in, so it means the same instant here and in recovery_target_time.
var restoreTimeLayouts = []string{
	"2006-01-02 15:04:05.999999-07",
	"2006-01-02 15:04:05.999999-07:00",
	"2006-01-02T15:04:05.999999Z07:00",
	"2006-01-02 15:04:05.999999",
	"2006-01-02T15:04:05.999999",
	"2006-01-02 15:04",
	"2006-01-02T15:04",
	"2006-01-02",
}

// parseRestoreTime reads a target timestamp. ok is false when it cannot be
// read, in which case the restore falls back to the newest base backup, as it
// always did, rather than refusing a timestamp Postgres itself might accept.
func parseRestoreTime(ts string) (at time.Time, ok bool) {
	s := strings.TrimSpace(ts)
	for _, l := range restoreTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// pickBackupForTime chooses the newest base backup of this database that had
// finished by at. Unlike pickBaseBackup it selects on time alone: a restore
// target is a timestamp, with no ledger entry and so no WAL position.
func pickBackupForTime(bs []walgBackup, systemID string, at time.Time) (walgBackup, error) {
	var best walgBackup
	found := false
	for _, b := range bs {
		if !backupNameRe.MatchString(b.Name) {
			continue
		}
		if systemID != "" && b.SystemID.String() != systemID {
			continue // a backup of an earlier, re-initialised database
		}
		if b.FinishTime.After(at) {
			continue
		}
		if !found || b.FinishTime.After(best.FinishTime) {
			best, found = b, true
		}
	}
	if !found {
		return walgBackup{}, fmt.Errorf("%w: no base backup had finished by %s%s — "+
			"a restore can only reach a point that a base backup precedes",
			ErrNoBaseBackup, at.UTC().Format(time.RFC3339), oldestBackupNote(bs))
	}
	return best, nil
}

// oldestBackupNote names the oldest base backup's time, so a refusal says what
// the archive does reach instead of only what it does not.
func oldestBackupNote(bs []walgBackup) string {
	var oldest time.Time
	for _, b := range bs {
		if !backupNameRe.MatchString(b.Name) {
			continue
		}
		if oldest.IsZero() || b.FinishTime.Before(oldest) {
			oldest = b.FinishTime
		}
	}
	if oldest.IsZero() {
		return " (there are no base backups; take one with `fox backup create`)"
	}
	return " (the oldest is from " + oldest.UTC().Format(time.RFC3339) + ")"
}

// primarySystemID reads the running primary's database system identifier, so
// backups of an earlier database with the same bucket are skipped. An empty
// string means "don't filter" — the primary may legitimately be stopped.
func primarySystemID() string {
	lines, err := ledgerLines(primaryBranch(), "SELECT system_identifier::text FROM pg_control_system()")
	if err != nil || len(lines) == 0 {
		return ""
	}
	if _, err := strconv.ParseUint(strings.TrimSpace(lines[0]), 10, 64); err != nil {
		return ""
	}
	return strings.TrimSpace(lines[0])
}

// restoreBackupName decides which base backup a restore starts from: the newest
// one that had finished by the target time, or LATEST for "latest" (and for a
// timestamp that cannot be read here, which behaves as it did before).
func restoreBackupName(ts string) (string, error) {
	if strings.EqualFold(strings.TrimSpace(ts), "latest") {
		return "LATEST", nil
	}
	at, ok := parseRestoreTime(ts)
	if !ok {
		fmt.Printf("note: %q was not read as a timestamp here, so the restore starts from the newest base backup\n", ts)
		return "LATEST", nil
	}
	bs, err := listBaseBackups()
	if err != nil {
		return "", err
	}
	b, err := pickBackupForTime(bs, primarySystemID(), at)
	if err != nil {
		return "", err
	}
	return b.Name, nil
}

// BackupInfo is one base backup as the API reports it: when it finished, how
// big it is, and the earliest point a restore that starts from it can reach.
type BackupInfo struct {
	Name       string `json:"name"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at"`
	SizeBytes  int64  `json:"size_bytes,omitempty"`
	Newest     bool   `json:"newest,omitempty"`
}

// Backups lists the base backups in object storage, newest first. Read-only,
// and read from a throwaway container, so it answers whichever container is
// primary and even with the stack down.
func Backups() ([]BackupInfo, error) {
	bs, err := listBaseBackups()
	if err != nil {
		return nil, err
	}
	sysID := primarySystemID()
	out := []BackupInfo{}
	for _, b := range bs {
		if !backupNameRe.MatchString(b.Name) {
			continue
		}
		if sysID != "" && b.SystemID.String() != sysID {
			continue // a backup of an earlier, re-initialised database
		}
		size, _ := b.CompressedSize.Int64()
		out = append(out, BackupInfo{
			Name:       b.Name,
			StartedAt:  formatBackupTime(b.StartTime),
			FinishedAt: formatBackupTime(b.FinishTime),
			SizeBytes:  size,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FinishedAt > out[j].FinishedAt })
	if len(out) > 0 {
		out[0].Newest = true
	}
	return out, nil
}

func formatBackupTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}
