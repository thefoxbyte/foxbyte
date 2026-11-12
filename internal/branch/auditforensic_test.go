// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func settingsIn(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old := auditSettingsPath
	auditSettingsPath = func() string { return filepath.Join(dir, "audit-settings.json") }
	t.Cleanup(func() { auditSettingsPath = old })
}

func storeIn(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	old := AuditStoreDir
	AuditStoreDir = func() string { return dir }
	t.Cleanup(func() { AuditStoreDir = old })
}

func TestRetentionSettings(t *testing.T) {
	settingsIn(t)
	t.Setenv("FOX_AUDIT_RETENTION_DAYS", "")
	if AuditRetentionDays() != 365 || ForensicRetentionDays() != 30 {
		t.Fatalf("defaults: %d %d", AuditRetentionDays(), ForensicRetentionDays())
	}
	if err := SetAuditRetention(90, false); err != nil || AuditRetentionDays() != 90 {
		t.Fatalf("90 days: %v %d", err, AuditRetentionDays())
	}
	if err := SetAuditRetention(120, true); err == nil {
		t.Error("statement text cannot outlive its records")
	}
	if err := SetAuditRetention(7, true); err != nil || ForensicRetentionDays() != 7 {
		t.Errorf("7 days of text: %v %d", err, ForensicRetentionDays())
	}
	if err := SetAuditRetention(5, false); err != nil || ForensicRetentionDays() != 5 {
		t.Errorf("records cut to 5 days cut text with them: %v %d", err, ForensicRetentionDays())
	}
	for _, bad := range []int{0, -1, 3651} {
		if SetAuditRetention(bad, false) == nil {
			t.Errorf("%d days should be refused", bad)
		}
	}
	// The setting wins over the variable, which wins over the default.
	settingsIn(t)
	t.Setenv("FOX_AUDIT_RETENTION_DAYS", "200")
	if AuditRetentionDays() != 200 {
		t.Errorf("the variable: %d", AuditRetentionDays())
	}
}

func TestForensicGrants(t *testing.T) {
	settingsIn(t)
	if ForensicFor("main") {
		t.Fatal("default mode by default")
	}
	s := LoadAuditSettings()
	s.Forensic["feature"] = ForensicGrant{By: "bob", Reason: "incident 42"}
	if err := saveAuditSettings(s); err != nil {
		t.Fatal(err)
	}
	if !ForensicFor("feature") || ForensicFor("main") {
		t.Error("one branch only")
	}
	s.Forensic[""] = ForensicGrant{By: "bob", Reason: "all"}
	_ = saveAuditSettings(s)
	if !ForensicFor("main") {
		t.Error("the whole install")
	}
	if _, err := SetForensic("main", true, "bob", "  "); err == nil || !strings.Contains(err.Error(), "--reason") {
		t.Errorf("a reason is required: %v", err)
	}
	if _, err := SetForensic("../x", true, "bob", "why"); err == nil {
		t.Error("a bad branch name is refused")
	}
}

// Text is kept beside the chain: read back onto its record while kept and
// matching, gone after a purge or retention, and a changed text is found by
// verify, while the chain itself still holds.
func TestForensicText(t *testing.T) {
	storeIn(t)
	settingsIn(t)
	recs := chainOf(t, lineForensic, lineObject)
	recs[0].Text = "UPDATE orders SET a = 1, b = 'x'"
	if recs[0].TextSHA == "" || recs[1].TextSHA != "" {
		t.Fatalf("only the forensic record has a text hash: %+v", recs)
	}
	if err := appendForensic("2026-11-04", recs); err != nil {
		t.Fatal(err)
	}
	size, err := appendDay("2026-11-04", recs)
	if err != nil {
		t.Fatal(err)
	}
	// The day file holds the hash, never the text.
	day, _ := readDay("2026-11-04")
	if day[0].Text != "" || day[0].TextSHA != recs[0].TextSHA {
		t.Fatalf("the chain holds the hash only: %+v", day[0])
	}
	s := auditState{Raw: map[string]rawPos{}, Days: map[string]int64{"2026-11-04": size}, Seq: 2, Head: recs[1].Hash}
	_ = saveAuditState(s)

	entries := []AuditEntry{{AuditRecord: day[0]}, {AuditRecord: day[1]}}
	attachTexts(entries)
	if entries[0].Text != "UPDATE orders SET a = 1, b = 'x'" || entries[0].TextGone || entries[1].Text != "" {
		t.Fatalf("attached: %+v", entries)
	}
	if rep, _ := VerifyAudit(); !rep.Intact {
		t.Fatalf("verify: %+v", rep)
	}

	// A text changed after it was kept.
	_ = rewriteForensic("2026-11-04", []forensicText{{Seq: 1, Branch: "main", Login: "bob", Text: "UPDATE orders SET a = 2"}})
	if rep, _ := VerifyAudit(); rep.Intact || !strings.Contains(strings.Join(rep.Problems, " "), "not the text it recorded") {
		t.Errorf("a changed text: %+v", rep)
	}
	_ = rewriteForensic("2026-11-04", []forensicText{{Seq: 1, Branch: "main", Login: "bob", Text: recs[0].Text}})

	// Purged for a person: the text goes, the record stays, the chain holds.
	n, err := PurgeForensic("bob")
	if err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if _, err := os.Stat(forensicPath("2026-11-04")); !os.IsNotExist(err) {
		t.Error("a day with no text left is removed")
	}
	entries = []AuditEntry{{AuditRecord: day[0]}}
	attachTexts(entries)
	if entries[0].Text != "" || !entries[0].TextGone {
		t.Errorf("after a purge the record says its text is gone: %+v", entries[0])
	}
	if rep, _ := VerifyAudit(); !rep.Intact {
		t.Errorf("the chain holds after a purge: %+v", rep)
	}
	if _, err := PurgeForensic(""); err == nil {
		t.Error("a purge needs a login")
	}

	// Retention: whole days.
	_ = appendForensic("2026-10-01", recs)
	_ = appendForensic("2026-11-04", recs)
	if n, err := pruneForensic("2026-10-05"); err != nil || n != 1 || len(forensicDays()) != 1 {
		t.Errorf("prune: %d %v %v", n, err, forensicDays())
	}
}

// The Aadhaar report's logs part reads a branch's texts, only those it keeps,
// each with its record's time, or its day's when the record is not there.
func TestScanForensicTexts(t *testing.T) {
	storeIn(t)
	settingsIn(t)
	recs := chainOf(t, lineForensic, lineObject)
	recs[0].Text = "UPDATE people SET uid = '2345 6789 0124'"
	if err := appendForensic("2026-11-04", recs); err != nil {
		t.Fatal(err)
	}
	if _, err := appendDay("2026-11-04", recs); err != nil {
		t.Fatal(err)
	}
	// A day with a text whose record is not in the store, and one on another
	// branch.
	if err := rewriteForensic("2026-11-05", []forensicText{
		{Seq: 99, Branch: recs[0].Branch, Login: "eve", Text: "SELECT 'uid 2345 6789 0124'"},
		{Seq: 100, Branch: "other", Login: "eve", Text: "SELECT 'uid 2345 6789 0124'"},
		{Seq: 101, Branch: recs[0].Branch, Login: "eve", Text: "SELECT 1"},
	}); err != nil {
		t.Fatal(err)
	}
	var got []ForensicText
	n, err := ScanForensicTexts(recs[0].Branch, func(s string) bool { return strings.Contains(s, "2345") }, func(f ForensicText) {
		got = append(got, f)
	})
	if err != nil || n != 3 || len(got) != 2 {
		t.Fatalf("n=%d err=%v %+v", n, err, got)
	}
	want, _ := time.Parse(time.RFC3339Nano, recs[0].Time)
	if got[0].Seq != recs[0].Seq || !got[0].At.Equal(want) || got[0].Text != recs[0].Text {
		t.Errorf("first: %+v (record at %s)", got[0], recs[0].Time)
	}
	if got[1].Seq != 99 || got[1].Login != "eve" || got[1].At.Format("2006-01-02T15:04") != "2026-11-05T00:00" {
		t.Errorf("second: %+v", got[1])
	}
}
