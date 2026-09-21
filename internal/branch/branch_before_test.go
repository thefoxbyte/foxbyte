// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseEntryJSON(t *testing.T) {
	e, err := parseEntryJSON(`{"id":42,"status":"APPLIED","command_tag":"CREATE TABLE","object_identity":"public.t",` +
		`"statement":"CREATE TABLE t(x int)\n","at":"2026-09-14T08:45:23.405548Z","xid":4294967301,"lsn":"5217714176"}`)
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != 42 || e.Status != "APPLIED" || e.XID != 4294967301 || e.LSN != 5217714176 || e.ObjectIdentity != "public.t" {
		t.Fatalf("unexpected entry: %+v", e)
	}
	if !e.At.Equal(time.Date(2026, 9, 14, 8, 45, 23, 405548000, time.UTC)) {
		t.Fatalf("at = %v", e.At)
	}

	// Pre-2.0 entries: no capture row, NULL columns.
	e, err = parseEntryJSON(`{"id":7,"status":"FLAGGED","command_tag":null,"object_identity":null,"statement":null,` +
		`"at":"2026-01-02T03:04:05.000000Z","xid":null,"lsn":null}`)
	if err != nil {
		t.Fatal(err)
	}
	if e.XID != 0 || e.LSN != 0 || e.CommandTag != "" {
		t.Fatalf("unexpected legacy entry: %+v", e)
	}

	if _, err := parseEntryJSON(`{"id":1,"at":"yesterday"}`); err == nil {
		t.Fatal("bad timestamp accepted")
	}
}

func TestRecoveryTarget(t *testing.T) {
	// txid_current() carries the epoch in the high 32 bits; recovery wants the xid.
	kind, v := recoveryTarget(beforeEntry{XID: 1<<32 + 5})
	if kind != "xid" || v != "5" {
		t.Fatalf("xid target = %s %s", kind, v)
	}
	kind, v = recoveryTarget(beforeEntry{XID: 777})
	if kind != "xid" || v != "777" {
		t.Fatalf("xid target = %s %s", kind, v)
	}
	at := time.Date(2026, 9, 14, 10, 0, 1, 250000000, time.FixedZone("x", 3600))
	kind, v = recoveryTarget(beforeEntry{At: at})
	if kind != "time" || v != "2026-09-14 09:00:01.25+00" || !targetTimeRe.MatchString(v) {
		t.Fatalf("time target = %s %s", kind, v)
	}
	_, v = recoveryTarget(beforeEntry{At: time.Date(2026, 9, 14, 9, 0, 1, 0, time.UTC)})
	if v != "2026-09-14 09:00:01+00" || !targetTimeRe.MatchString(v) {
		t.Fatalf("whole-second time target = %s", v)
	}
}

const backupListOut = `INFO: 2026/09/14 11:44:20.028111 List backups from storages: [default]
[{"backup_name":"base_000000010000000100000022","time":"2026-09-14T08:45:23.5Z","finish_time":"2026-09-14T08:45:23.405548Z","finish_lsn":4865392896,"system_identifier":7677633060494876718},
 {"backup_name":"base_000000010000000100000024","finish_time":"2026-09-14T08:45:44.189019Z","finish_lsn":4898947328,"system_identifier":7677633060494876718},
 {"backup_name":"base_00000001000000010000002D","finish_time":"2026-09-14T09:35:09.45069Z","finish_lsn":5049942272,"system_identifier":7677633060494876718},
 {"backup_name":"base_00000001000000000000001A","finish_time":"2026-09-14T09:50:00Z","finish_lsn":436207872,"system_identifier":1111111111111111111}]`

func TestParseBackups(t *testing.T) {
	bs, err := parseBackups([]byte(backupListOut))
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 4 || bs[0].Name != "base_000000010000000100000022" || bs[0].SystemID.String() != "7677633060494876718" {
		t.Fatalf("parsed %+v", bs)
	}
	if bs, err := parseBackups([]byte("INFO: No backups found\n")); err != nil || len(bs) != 0 {
		t.Fatalf("empty listing: %v %v", bs, err)
	}
	if _, err := parseBackups([]byte("[{nope")); err == nil {
		t.Fatal("broken JSON accepted")
	}
}

func TestPickBaseBackup(t *testing.T) {
	bs, _ := parseBackups([]byte(backupListOut))
	const sys = "7677633060494876718"

	// By WAL position: the newest backup that finished at or before the entry.
	b, err := pickBaseBackup(bs, sys, beforeEntry{ID: 1, LSN: 4900000000, At: time.Now()})
	if err != nil || b.Name != "base_000000010000000100000024" {
		t.Fatalf("lsn pick = %v %v", b.Name, err)
	}
	// A backup of another database is never used, even when it is newer.
	b, err = pickBaseBackup(bs, sys, beforeEntry{ID: 1, LSN: 6000000000, At: time.Now()})
	if err != nil || b.Name != "base_00000001000000010000002D" {
		t.Fatalf("system id filter = %v %v", b.Name, err)
	}
	// By time, when the entry predates 2.0 capture.
	b, err = pickBaseBackup(bs, sys, beforeEntry{ID: 1, At: time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)})
	if err != nil || b.Name != "base_000000010000000100000024" {
		t.Fatalf("time pick = %v %v", b.Name, err)
	}
	// Nothing finished before the change.
	_, err = pickBaseBackup(bs, sys, beforeEntry{ID: 9, LSN: 100, At: time.Now()})
	if !errors.Is(err, ErrNoBaseBackup) || !strings.Contains(err.Error(), "fox backup create") {
		t.Fatalf("no backup error = %v", err)
	}
	_, err = pickBaseBackup(nil, sys, beforeEntry{ID: 9, At: time.Now()})
	if !errors.Is(err, ErrNoBaseBackup) {
		t.Fatalf("empty list error = %v", err)
	}
	// Names that are not plain base backups are skipped.
	odd := []walgBackup{{Name: "base_1'; DROP", FinishTime: time.Unix(0, 0), FinishLSN: "1", SystemID: sys}}
	if _, err := pickBaseBackup(odd, sys, beforeEntry{LSN: 10, At: time.Now()}); !errors.Is(err, ErrNoBaseBackup) {
		t.Fatalf("odd name accepted: %v", err)
	}
}

func TestWalArchived(t *testing.T) {
	cases := []struct {
		last, seg string
		want      bool
	}{
		{"000000010000000100000036", "000000010000000100000036", true},
		{"000000010000000100000037", "000000010000000100000036", true},
		{"000000010000000100000035", "000000010000000100000036", false},
		{"000000010000000100000036.partial", "000000010000000100000036", true},
		{"00000002.history", "000000010000000100000036", false},
		{"", "000000010000000100000036", false},
	}
	for _, c := range cases {
		if got := walArchived(c.last, c.seg); got != c.want {
			t.Errorf("walArchived(%q, %q) = %v", c.last, c.seg, got)
		}
	}
}

func TestValidateBeforeName(t *testing.T) {
	for _, n := range []string{"main-before-12", "fix-1", "a"} {
		if err := validateBeforeName(n); err != nil {
			t.Errorf("%q rejected: %v", n, err)
		}
	}
	for _, n := range []string{"", "main", "restore", "standby", "agent-x", "Bad", "a/b", "-x", strings.Repeat("a", 42)} {
		if err := validateBeforeName(n); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%q accepted", n)
		}
	}
	if DefaultBeforeName("main", 606) != "main-before-606" {
		t.Fatal("default name changed")
	}
}

func TestEntryQuery(t *testing.T) {
	q := entryQuery(5, true)
	if !strings.Contains(q, "LEFT JOIN bb.ledger_ext e") || !strings.Contains(q, "WHERE l.id = 5") {
		t.Fatalf("with ext: %s", q)
	}
	q = entryQuery(5, false)
	if strings.Contains(q, "ledger_ext") || !strings.Contains(q, "NULL::bigint") {
		t.Fatalf("without ext: %s", q)
	}
}

func TestRestoreBeforeScript(t *testing.T) {
	for _, want := range []string{
		"recovery_target_inclusive = off",
		"recovery_target_action = 'promote'",
		`recovery_target_xid = '$RECOVERY_TARGET'`,
		`recovery_target_time = '$RECOVERY_TARGET'`,
		`wal-g backup-fetch "$PGDATA" "$BACKUP_NAME"`,
		"recovery.signal",
		"archive_mode = off",
	} {
		if !strings.Contains(restoreBeforeScript, want) {
			t.Errorf("restore script lost %q", want)
		}
	}
	if strings.Contains(restoreBeforeScript, "LATEST") {
		t.Error("restore script must fetch the chosen backup, not LATEST")
	}
}
