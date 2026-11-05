// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Fixing is Enterprise; the report is not.
func TestHardeningFixesAreEnterprise(t *testing.T) {
	edition.SetEntitlement(nil)
	t.Cleanup(func() { edition.SetEntitlement(nil) })
	if _, err := PlanHardeningFix("main", "log.connections"); !errors.Is(err, ErrNotLicensed) {
		t.Fatalf("a preview without a licence: %v", err)
	}
	if _, err := ApplyHardeningFix("main", "log.connections", "cli:me"); !errors.Is(err, ErrNotLicensed) {
		t.Fatalf("a fix without a licence: %v", err)
	}
	if _, _, err := PlanHardeningProfile("main", "strict"); !errors.Is(err, ErrNotLicensed) {
		t.Fatalf("a profile without a licence: %v", err)
	}
	checks := []HardeningCheck{{ID: "log.connections", Status: HardenFail}}
	fixable("main", checks)
	if checks[0].Fixable {
		t.Fatal("offered as fixable without a licence")
	}
}

// A profile takes the failing checks of its levels: those with a fix, and
// the rest left to a person; passing ones and the other level are left alone.
func TestProfileFixes(t *testing.T) {
	old1, old2 := planHardeningFix, applyHardeningFix
	t.Cleanup(func() { planHardeningFix, applyHardeningFix = old1, old2 })
	SetHardeningFixer(func(_ string, c HardeningCheck) (HardeningFix, bool, error) {
		if strings.HasPrefix(c.ID, "fix.") {
			return HardeningFix{ID: c.ID, Level: c.Level}, true, nil
		}
		return HardeningFix{}, false, nil
	}, nil)
	checks := []HardeningCheck{
		{ID: "fix.a", Level: "basic", Status: HardenFail},
		{ID: "fix.b", Level: "strict", Status: HardenFail},
		{ID: "fix.c", Level: "basic", Status: HardenPass},
		{ID: "person.d", Level: "basic", Status: HardenFail},
		{ID: "fix.e", Level: "basic", Status: HardenManual},
	}
	ids := func(fs []HardeningFix) string {
		var s []string
		for _, f := range fs {
			s = append(s, f.ID)
		}
		return strings.Join(s, " ")
	}
	fixes, manual, err := profileFixes("main", checks, hardeningProfiles["baseline"])
	if err != nil || ids(fixes) != "fix.a" || len(manual) != 1 || manual[0].ID != "person.d" {
		t.Fatalf("baseline: %v %v %v", ids(fixes), manual, err)
	}
	if fixes, _, _ := profileFixes("main", checks, hardeningProfiles["strict"]); ids(fixes) != "fix.a fix.b" {
		t.Fatalf("strict: %v", ids(fixes))
	}
	if strings.Join(HardeningProfiles(), " ") != "baseline strict" {
		t.Fatalf("profiles: %v", HardeningProfiles())
	}
}

// The profile applied is kept against the branch, and the security log's
// line says what changed and whether it held.
func TestHardeningRecordAndLogLine(t *testing.T) {
	dir := t.TempDir()
	old := hardeningStatePath
	hardeningStatePath = func() string { return filepath.Join(dir, "hardening.json") }
	t.Cleanup(func() { hardeningStatePath = old })
	if err := recordProfile("main", "strict", "cli:ada"); err != nil {
		t.Fatal(err)
	}
	if p := loadProfiles()["main"]; p.Profile != "strict" || p.By != "cli:ada" || p.At == "" {
		t.Fatalf("recorded: %+v", p)
	}
	r := HardeningFixResult{Fix: HardeningFix{ID: "conn.idle", Changes: []string{"idle_in_transaction_session_timeout: 0 → 10min"}},
		Before: HardeningCheck{Status: HardenFail}, After: HardeningCheck{Status: HardenPass}}
	if got := r.FixLogLine(); got != "conn.idle: idle_in_transaction_session_timeout: 0 → 10min (fail → pass)" {
		t.Fatalf("log line: %q", got)
	}
	r.Error = "it still fails"
	if got := r.FixLogLine(); !strings.HasSuffix(got, " — it still fails") {
		t.Fatalf("log line: %q", got)
	}
}
