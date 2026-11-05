// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Fixing what the hardening report finds (points 3.3 and 3.4): one check at a
// time, or every check of a profile at once, each after a preview of what it
// will change. Enterprise; enterprise/hardening knows the fixes. The report
// itself (hardening.go) is free.
//
// A fix is offered only where it is safe to make without a person deciding
// more than "yes": a setting, a grant, a file's mode. What could lock someone
// out or stop an application (taking a superuser away, rewriting pg_hba.conf,
// turning the audit log on, which restarts main) stays manual, with the
// command to run. Settings go in with ALTER SYSTEM and a reload, as the audit
// policy does, so they live in the branch's own data directory: a branch made
// afterwards has them, one made before does not, and a standby keeps its own.
// Each fix checks again afterwards, and says when something still overrides
// it.

// HardeningFix is what fixing one check will change.
type HardeningFix struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Level   string   `json:"level"`
	Changes []string `json:"changes"` // for a person: "log_connections: off → on"
	SQL     []string `json:"sql"`     // what runs, for a reviewer; empty when it is not SQL
	Note    string   `json:"note,omitempty"`
}

// HardeningFixResult is a fix made, and the check before and after.
type HardeningFixResult struct {
	Fix    HardeningFix   `json:"fix"`
	Before HardeningCheck `json:"before"`
	After  HardeningCheck `json:"after"`
	Error  string         `json:"error,omitempty"`
}

// The profiles (3.4): which levels of check each one fixes.
var hardeningProfiles = map[string][]string{
	"baseline": {"basic"},
	"strict":   {"basic", "strict"},
}

// HardeningProfiles lists the profiles' names.
func HardeningProfiles() []string {
	names := make([]string, 0, len(hardeningProfiles))
	for n := range hardeningProfiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// The paid half, supplied by enterprise/hardening in an Enterprise build and
// nil in a Standard one: the plan for a check that fails (false when it has no
// safe fix), and making it.
var (
	planHardeningFix  func(branch string, c HardeningCheck) (HardeningFix, bool, error)
	applyHardeningFix func(branch, actor string, f HardeningFix) error
)

// SetHardeningFixer installs them. Called from enterprise/hardening's init,
// and from nowhere else.
func SetHardeningFixer(plan func(string, HardeningCheck) (HardeningFix, bool, error), apply func(string, string, HardeningFix) error) {
	planHardeningFix, applyHardeningFix = plan, apply
}

// ErrNoHardeningFix is a check with nothing to fix: it passes, or its fix is
// for a person to make.
var ErrNoHardeningFix = errors.New("no fix to make")

func requireHardeningFixer() error {
	if err := requireFeature(edition.Hardening); err != nil {
		return err
	}
	if planHardeningFix == nil {
		return notLicensed{edition.Hardening}
	}
	return nil
}

// fixable marks the checks a fix can be made for, when this install can make
// them: the report says which, so the console can offer them.
func fixable(name string, checks []HardeningCheck) {
	if requireHardeningFixer() != nil {
		return
	}
	for i := range checks {
		if checks[i].Status != HardenFail {
			continue
		}
		if _, ok, err := planHardeningFix(name, checks[i]); err == nil && ok {
			checks[i].Fixable = true
		}
	}
}

// PlanHardeningFix is the preview: what fixing one check would change.
func PlanHardeningFix(name, id string) (HardeningFix, error) {
	if err := requireHardeningFixer(); err != nil {
		return HardeningFix{}, err
	}
	c, err := hardeningCheckNow(name, id)
	if err != nil {
		return HardeningFix{}, err
	}
	return planFor(name, c)
}

func planFor(name string, c HardeningCheck) (HardeningFix, error) {
	if c.Status != HardenFail {
		return HardeningFix{}, fmt.Errorf("%w: %s is %s", ErrNoHardeningFix, c.ID, c.Status)
	}
	f, ok, err := planHardeningFix(name, c)
	if err != nil {
		return HardeningFix{}, err
	}
	if !ok {
		return HardeningFix{}, fmt.Errorf("%w: %s is for a person to fix: %s", ErrNoHardeningFix, c.ID, c.Fix)
	}
	return f, nil
}

// ApplyHardeningFix fixes one check, and checks it again.
func ApplyHardeningFix(name, id, actor string) (HardeningFixResult, error) {
	if err := requireHardeningFixer(); err != nil {
		return HardeningFixResult{}, err
	}
	before, err := hardeningCheckNow(name, id)
	if err != nil {
		return HardeningFixResult{}, err
	}
	f, err := planFor(name, before)
	if err != nil {
		return HardeningFixResult{}, err
	}
	return applyOne(name, actor, f, before), nil
}

func applyOne(name, actor string, f HardeningFix, before HardeningCheck) HardeningFixResult {
	res := HardeningFixResult{Fix: f, Before: before}
	if err := applyHardeningFix(name, actor, f); err != nil {
		res.Error = err.Error()
	}
	if after, err := hardeningCheckNow(name, f.ID); err == nil {
		res.After = after
		if res.Error == "" && after.Status == HardenFail {
			res.Error = "it still fails: " + after.Evidence + " — something sets it after this (the command line, or a file the server reads first)"
		}
	}
	return res
}

// PlanHardeningProfile is the preview of a profile: the fix for every check
// of its levels that fails and has one. The checks that fail and need a
// person are listed too, so nothing is hidden by a profile.
func PlanHardeningProfile(name, profile string) (fixes []HardeningFix, manual []HardeningCheck, err error) {
	if err := requireHardeningFixer(); err != nil {
		return nil, nil, err
	}
	levels, ok := hardeningProfiles[profile]
	if !ok {
		return nil, nil, fmt.Errorf("%w: the profiles are %v, not %q", ErrInvalidRequest, HardeningProfiles(), profile)
	}
	rep, err := ProduceHardening(name)
	if err != nil {
		return nil, nil, err
	}
	return profileFixes(name, rep.Checks, levels)
}

// profileFixes is the choice a profile makes: of the checks of its levels
// that fail, those with a fix, and those left to a person.
func profileFixes(name string, checks []HardeningCheck, levels []string) (fixes []HardeningFix, manual []HardeningCheck, err error) {
	in := map[string]bool{}
	for _, l := range levels {
		in[l] = true
	}
	for _, c := range checks {
		if !in[c.Level] || c.Status != HardenFail {
			continue
		}
		f, ok, err := planHardeningFix(name, c)
		switch {
		case err != nil:
			return nil, nil, err
		case ok:
			fixes = append(fixes, f)
		default:
			manual = append(manual, c)
		}
	}
	return fixes, manual, nil
}

// ApplyHardeningProfile makes every fix of a profile, one after another: one
// that fails does not stop the others, and each is checked again. The profile
// is recorded against the branch, so the report says which was applied.
func ApplyHardeningProfile(name, profile, actor string) ([]HardeningFixResult, error) {
	fixes, _, err := PlanHardeningProfile(name, profile)
	if err != nil {
		return nil, err
	}
	rep, err := ProduceHardening(name)
	if err != nil {
		return nil, err
	}
	before := map[string]HardeningCheck{}
	for _, c := range rep.Checks {
		before[c.ID] = c
	}
	var out []HardeningFixResult
	for _, f := range fixes {
		out = append(out, applyOne(name, actor, f, before[f.ID]))
	}
	if err := recordProfile(name, profile, actor); err != nil {
		return out, err
	}
	return out, nil
}

// hardeningCheckNow reads one check as it stands now.
func hardeningCheckNow(name, id string) (HardeningCheck, error) {
	rep, err := ProduceHardening(name)
	if err != nil {
		return HardeningCheck{}, err
	}
	for _, c := range rep.Checks {
		if c.ID == id {
			return c, nil
		}
	}
	return HardeningCheck{}, fmt.Errorf("%w: no check %q (%s hardening lists them)", ErrInvalidRequest, id, brand.CLI)
}

// AppliedProfile is the last profile applied to a branch.
type AppliedProfile struct {
	Profile string `json:"profile"`
	By      string `json:"by"`
	At      string `json:"at"` // RFC 3339
}

var hardeningStatePath = func() string { return brand.StatePath("hardening.json") }

func loadProfiles() map[string]AppliedProfile {
	m := map[string]AppliedProfile{}
	if b, err := os.ReadFile(hardeningStatePath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func recordProfile(name, profile, actor string) error {
	m := loadProfiles()
	m[name] = AppliedProfile{Profile: profile, By: actor, At: time.Now().UTC().Format(time.RFC3339)}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := hardeningStatePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, hardeningStatePath())
}

// FixLogLine is the security log's line for a fix.
func (r HardeningFixResult) FixLogLine() string {
	s := fmt.Sprintf("%s: %s", r.Fix.ID, joinChanges(r.Fix.Changes))
	if r.Error != "" {
		s += " — " + r.Error
	} else {
		s += fmt.Sprintf(" (%s → %s)", r.Before.Status, r.After.Status)
	}
	return s
}

func joinChanges(cs []string) string {
	if len(cs) == 0 {
		return "no change"
	}
	s := cs[0]
	for _, c := range cs[1:] {
		s += "; " + c
	}
	return s
}

// The primitives the fixes are made with, kept narrow: settings, statements
// recorded in the Blackbox, and the data directory's mode.

// SetSystemSettings runs ALTER SYSTEM statements one at a time (they cannot
// share a transaction), then reloads the configuration.
func SetSystemSettings(name string, stmts []string) error {
	var b strings.Builder
	for _, s := range stmts {
		b.WriteString(strings.TrimRight(strings.TrimSpace(s), ";") + ";\n")
	}
	b.WriteString("SELECT pg_reload_conf();\n")
	return psqlQuiet(name, b.String())
}

// RunRecorded runs statements in one transaction as actor, so the Blackbox
// records them under the person who asked.
func RunRecorded(name, actor, tool string, stmts []string) error {
	body := strings.Join(stmts, ";\n") + ";"
	return trackExec(name, trackSQL(actor, tool, body, false))
}

// RunStatements runs statements as the superuser, one at a time, for what
// the Blackbox does not record (roles are the cluster's, not a database's).
func RunStatements(name string, stmts []string) error {
	var b strings.Builder
	for _, s := range stmts {
		b.WriteString(strings.TrimRight(strings.TrimSpace(s), ";") + ";\n")
	}
	return psqlQuiet(name, b.String())
}

// ShowSetting reads one setting's current value.
func ShowSetting(name, setting string) (string, error) {
	out, err := QuerySQL(name, "SELECT current_setting("+QuoteLiteral(setting)+", true)")
	return strings.TrimSpace(out), err
}

// SetDataDirMode makes the data directory readable by its owner only.
func SetDataDirMode(name string) error {
	dir, err := ShowSetting(name, "data_directory")
	if err != nil || dir == "" {
		return fmt.Errorf("reading the data directory: %v", err)
	}
	if out, err := capture("docker", "exec", "-u", "postgres", container(name), "chmod", "700", dir); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out))
	}
	return nil
}
