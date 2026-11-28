// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

var t0 = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

// A request applied on main at t0, its table rewritten an hour later.
func doneRequest() ErasureView {
	rw := t0.Add(time.Hour)
	vac := t0.Add(time.Minute)
	res := ErasureResult{Applied: t0, By: "admin@x", Rows: 1, Verified: true, Vacuumed: &vac, Statistics: &rw,
		Tables:   []ErasureDone{{Schema: "public", Table: "people", Action: ErasureActClear, Rows: 1}},
		Rewrites: []ErasureRewrite{{Schema: "public", Table: "people", State: RewriteDone, At: &rw}},
		Blackbox: &ErasureTextDone{Redacted: 1}, Copies: &ErasureCopiesDone{History: 2}}
	return ErasureView{ErasureRequest: auth.ErasureRequest{ID: 7, State: auth.ErasureApplied, Branch: "main"},
		Result: &res, Branches: []ErasureBranch{}, MadeBefore: []ErasureStale{}}
}

func backup(start, finish time.Time) BackupInfo {
	return BackupInfo{StartedAt: start.Format(time.RFC3339), FinishedAt: finish.Format(time.RFC3339)}
}

// Facts where everything has gone: daily backups, seven kept, all of them
// taken after the rewrite; no audit log, no tar, no other archive.
func cleanFacts() outcomeFacts {
	f := outcomeFacts{Now: t0.Add(30 * 24 * time.Hour), Interval: 24 * time.Hour, Retain: 7, Target: "local",
		Prefixes: []string{""}, Realtime: map[string][]RealtimeSlot{}, Keys: map[string]int{}, ExportsDir: "/state/exports"}
	for i := 7; i >= 1; i-- {
		s := t0.Add(time.Duration(10+i) * 24 * time.Hour)
		f.Backups = append(f.Backups, backup(s, s.Add(10*time.Minute)))
	}
	return f
}

func TestClearsOnIsTheLatestOutcome(t *testing.T) {
	o := reckonOutcomes(doneRequest(), cleanFacts())
	if o.ClearsOn == nil {
		t.Fatalf("no date: never %v, unknown %v", o.Never, o.Unknown)
	}
	b, _ := o.Outcome(OutcomeBackups)
	if b.State != StateMet || b.Date == nil {
		t.Fatalf("backups: %+v", b)
	}
	// The prune after the 7th backup since the rewrite took the last copy.
	want := t0.Add(17*24*time.Hour + 10*time.Minute)
	if !b.Date.Equal(want) || !o.ClearsOn.Equal(want) {
		t.Fatalf("backups met %v, clears on %v, want %v", b.Date, o.ClearsOn, want)
	}
	for _, k := range []string{OutcomeLive, OutcomeFiles, OutcomeLogs, OutcomeBranches} {
		if x, _ := o.Outcome(k); x.State != StateMet {
			t.Fatalf("%s: %+v", k, x)
		}
	}
	if x, _ := o.Outcome(OutcomeVault); x.State != StateNotApplicable {
		t.Fatalf("no vault record: %+v", x)
	}
	if x, _ := o.Outcome(OutcomeDerived); x.State != StateNotTraced {
		t.Fatalf("derived: %+v", x)
	}
}

func TestBackupsPendingUntilThePruneAfterTheNthBackup(t *testing.T) {
	f := cleanFacts()
	rw := t0.Add(time.Hour)
	// Seven kept: five from before the rewrite, two after.
	f.Backups = nil
	for i := 2; i >= 1; i-- {
		s := rw.Add(time.Duration(i) * 24 * time.Hour)
		f.Backups = append(f.Backups, backup(s, s.Add(10*time.Minute)))
	}
	for i := 1; i <= 5; i++ {
		s := t0.Add(-time.Duration(i) * 24 * time.Hour)
		f.Backups = append(f.Backups, backup(s, s.Add(10*time.Minute)))
	}
	f.Now = rw.Add(3 * 24 * time.Hour)
	o := reckonOutcomes(doneRequest(), f)
	b, _ := o.Outcome(OutcomeBackups)
	want := rw.Add(2*24*time.Hour + 10*time.Minute).Add(5 * 24 * time.Hour)
	if b.State != StatePending || !b.Estimated || b.Date == nil || !b.Date.Equal(want) {
		t.Fatalf("backups: %+v, want pending about %v", b, want)
	}
	if o.ClearsOn == nil || !o.ClearsOn.Equal(want) {
		t.Fatalf("clears on %v", o.ClearsOn)
	}
	// Object Lock keeps everything a year: the floor wins.
	f.Lock = LockInfo{Enabled: true, DefaultMode: "COMPLIANCE", DefaultValidity: "1YEARS"}
	b, _ = reckonOutcomes(doneRequest(), f).Outcome(OutcomeBackups)
	if !b.Date.Equal(rw.Add(365 * 24 * time.Hour)) {
		t.Fatalf("with Object Lock: %v", b.Date)
	}
}

func TestClearsOnNeverSaysWhy(t *testing.T) {
	f := cleanFacts()
	v := doneRequest()
	v.MadeBefore = []ErasureStale{{Branch: "dev", Parent: "main"}}
	f.BackupsOff = true
	f.Prefixes, f.Prefix = []string{"", "pg18-20261101t000000z"}, "pg18-20261101t000000z"
	f.TargetsLeft = []TargetLeft{{Root: "s3://old", Until: t0.Add(-48 * time.Hour)}}
	// A tar in the exports folder made before the erasure, one made after,
	// and one written elsewhere.
	f.ServerTars = []TarFile{{Path: "/state/exports/a.tar", Modified: t0.Add(-time.Hour)}, {Path: "/state/exports/b.tar", Modified: t0.Add(time.Hour)}}
	f.Tars = []TarRecord{{Path: "/home/x/c.tar", Place: TarOnServer, Branches: []string{"main"}, Created: t0.Add(-time.Hour), By: "op"}}
	o := reckonOutcomes(v, f)
	if o.ClearsOn != nil {
		t.Fatalf("a date with things left: %v", o.ClearsOn)
	}
	all := strings.Join(o.Never, "\n")
	for _, want := range []string{"dev made before the erasure", "backups are off", "the target's root, kept from before an upgrade",
		"s3://old, the backup target until", "backup target forget s3://old", "/state/exports/a.tar"} {
		if !strings.Contains(all, want) {
			t.Errorf("never does not say %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "b.tar") || strings.Contains(all, "c.tar") {
		t.Errorf("a tar made after it, or one outside the folder, counted:\n%s", all)
	}
	var outside []string
	for _, c := range o.Outside {
		outside = append(outside, c.What)
	}
	if !strings.Contains(strings.Join(outside, "\n"), "/home/x/c.tar") {
		t.Errorf("the tar written elsewhere is not listed outside: %v", outside)
	}
	// Said deleted: the target left no longer counts.
	f.TargetsLeft[0].Gone, f.TargetsLeft[0].GoneBy, f.TargetsLeft[0].Reason = &t0, "admin@x", "bucket emptied"
	if strings.Contains(strings.Join(reckonOutcomes(v, f).Never, "\n"), "s3://old") {
		t.Fatal("a target said deleted still counts")
	}
}

func TestHostTarsAreCountedFromTheHostsListing(t *testing.T) {
	f := cleanFacts()
	v := doneRequest()
	rec := TarRecord{Path: "/Users/a/.fox/exports/x.tar", Place: TarOnHost, Branches: []string{"main"}, Created: t0.Add(-time.Hour)}
	f.Tars = []TarRecord{rec}
	// Never listed by the host: still there as far as FoxByte knows.
	if all := strings.Join(reckonOutcomes(v, f).Never, "\n"); !strings.Contains(all, "x.tar") || !strings.Contains(all, "not listed since") {
		t.Fatalf("an unlisted host tar: %s", all)
	}
	// Listed with it there.
	f.Host = &HostExports{Dir: "/Users/a/.fox/exports", Checked: t0.Add(time.Hour), Tars: []TarFile{{Path: rec.Path, Modified: rec.Created}}}
	if all := strings.Join(reckonOutcomes(v, f).Never, "\n"); !strings.Contains(all, "on the host, as listed") {
		t.Fatalf("a listed host tar: %s", all)
	}
	// Listed since, and gone.
	f.Host.Tars = []TarFile{}
	if o := reckonOutcomes(v, f); len(o.Never) != 0 || o.ClearsOn == nil {
		t.Fatalf("a host tar deleted: never %v", o.Never)
	}
}

func TestAuditRecordsAndExceptions(t *testing.T) {
	f := cleanFacts()
	f.AuditOn, f.AuditDays = true, 365
	v := doneRequest()
	ends := t0.Add(5 * 365 * 24 * time.Hour)
	v.Plan.Tables = []ErasureTable{{Schema: "public", Table: "kyc", Exceptions: []ErasureException{
		{Citation: "PML Rules, Rule 10", Text: "kept five years after the relationship ends", Ends: &ends}}}}
	o := reckonOutcomes(v, f)
	a, _ := o.Outcome(OutcomeAudit)
	if a.State != StatePending || !a.Date.Equal(t0.Add(365*24*time.Hour)) {
		t.Fatalf("audit: %+v", a)
	}
	if o.ClearsOn == nil || !o.ClearsOn.Equal(ends) {
		t.Fatalf("the law's end is the latest: %v", o.ClearsOn)
	}
	// An exception with no end date given leaves the date unknown.
	v.Plan.Tables[0].Exceptions[0].Ends = nil
	o = reckonOutcomes(v, f)
	if o.ClearsOn != nil || len(o.Unknown) != 1 || !strings.Contains(o.Unknown[0], "the end date is not given") {
		t.Fatalf("unknown: %v %v", o.ClearsOn, o.Unknown)
	}
}

func TestOutsideListsWhatFoxByteCannotReach(t *testing.T) {
	f := cleanFacts()
	v := doneRequest()
	ev := func(at time.Time, b string) auth.SecurityEvent {
		return auth.SecurityEvent{At: at.Format(time.RFC3339Nano), Subject: b, Actor: "alice@x", Detail: "branch main, csv, 3 row(s), query 1a2b"}
	}
	f.DataExports = []auth.SecurityEvent{ev(t0.Add(-time.Hour), "main"), ev(t0.Add(time.Hour), "main"), ev(t0.Add(-time.Hour), "other")}
	f.LedgerExports = []auth.SecurityEvent{ev(t0.Add(-2*time.Hour), "main")}
	f.Pipelines = []auth.PipelineTarget{{Branch: "main", Pipeline: "crm"}}
	f.Forwarding = "https://siem.example"
	o := reckonOutcomes(v, f)
	kinds := map[string]int{}
	warn := false
	for _, c := range o.Outside {
		kinds[c.Kind]++
		warn = warn || c.Warn
	}
	if kinds["export"] != 1 || kinds["blackbox"] != 1 || kinds["pipeline"] != 1 || kinds["siem"] != 1 || kinds["state"] != 1 || kinds["disk"] != 1 || !warn {
		t.Fatalf("outside: %+v", o.Outside)
	}
	// Outside FoxByte never holds the date back.
	if o.ClearsOn == nil {
		t.Fatalf("outside held the date: %v", o.Never)
	}
}

func TestARecheckThatFindsThePersonLosesTheOutcome(t *testing.T) {
	o := reckonOutcomes(doneRequest(), cleanFacts())
	applyRecheck(&o, ErasureRecheck{Checked: t0, Branches: []RecheckBranch{{Branch: "main",
		Tables: []RecheckTable{{Schema: "public", Table: "people", Action: ErasureActClear, Keys: 1, Found: 1}}}}})
	x, _ := o.Outcome(OutcomeLive)
	if x.State != StateLost || o.ClearsOn != nil || len(o.Never) != 1 || !strings.Contains(o.Never[0], "1 row(s) of public.people on main") {
		t.Fatalf("lost: %+v, never %v", x, o.Never)
	}
	o = reckonOutcomes(doneRequest(), cleanFacts())
	applyRecheck(&o, ErasureRecheck{Checked: t0, Branches: []RecheckBranch{{Branch: "main", Tables: []RecheckTable{{Schema: "public", Table: "people", Keys: 1}}}}})
	if x, _ := o.Outcome(OutcomeLive); x.State != StateMet || !strings.Contains(strings.Join(x.Evidence, " "), "none holds the person") || o.ClearsOn == nil {
		t.Fatalf("found none: %+v", x)
	}
}

func TestOutcomesWaitForTheApply(t *testing.T) {
	v := doneRequest()
	v.Result = nil
	if o := reckonOutcomes(v, cleanFacts()); len(o.Outcomes) != 0 || o.ClearsOn != nil {
		t.Fatalf("a request not applied: %+v", o)
	}
	v = doneRequest()
	v.Result.Rewrites[0].State, v.Result.Rewrites[0].At = RewritePending, nil
	o := reckonOutcomes(v, cleanFacts())
	if x, _ := o.Outcome(OutcomeFiles); x.State != StateNever || !strings.Contains(x.Why, "dpdp erase rewrite 7") {
		t.Fatalf("a rewrite left: %+v", x)
	}
	if x, _ := o.Outcome(OutcomeBackups); x.State != StateNever || !strings.Contains(x.Why, "a rewrite is still open") {
		t.Fatalf("backups with a rewrite left: %+v", x)
	}
}

func TestLockValidityAndPrefixListing(t *testing.T) {
	for in, want := range map[string]time.Duration{"30DAYS": 30 * 24 * time.Hour, "1YEARS": 365 * 24 * time.Hour, "7d": 7 * 24 * time.Hour} {
		if d, ok := lockValidity(in); !ok || d != want {
			t.Errorf("%s: %v %v", in, d, ok)
		}
	}
	if _, ok := lockValidity(""); ok {
		t.Error("an empty validity read")
	}
	out := "@ [2026-11-01 00:00:00 UTC]     0B basebackups_005/\n@ [2026-11-01 00:00:00 UTC]     0B pg18-20261101t000000z/\n" +
		"pg18-20261101t000000z/ [2026-11-02 00:00:00 UTC]     0B wal_005/\n"
	if got := prefixesInListing(out); len(got) != 2 || got[0] != "" || got[1] != "pg18-20261101t000000z" {
		t.Fatalf("prefixes: %q", got)
	}
}
