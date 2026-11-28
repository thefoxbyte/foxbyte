// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// The outcomes of an erasure request and its one date (F4, Gate 1 step 5;
// design, section 15). Each outcome is read when asked, not stored: a branch
// restored or remade, a backup pruned or a target changed shows at once. The
// date is "clears on": the latest among the outcomes FoxByte meets, a law's
// exceptions included, or "never" while something FoxByte keeps will not go
// by itself, saying what.
//
// Free in every edition: an install whose licence lapsed can still show what
// was done. Searching the branches again (ErasureRecheck) is the engine's.

// The keys of the outcomes, in the order the design lists them.
const (
	OutcomeLive      = "live"      // removed from live queries
	OutcomeFiles     = "files"     // rewritten in the files
	OutcomeLogs      = "logs"      // logs and records cleared
	OutcomeVault     = "vault"     // vault record deleted
	OutcomeDerived   = "derived"   // derived data
	OutcomeBranches  = "branches"  // dependent branches cleared
	OutcomeBackups   = "backups"   // backup and WAL expiry
	OutcomeAudit     = "audit"     // audit records aged out
	OutcomeException = "exception" // a law's retention exception
	OutcomeOutside   = "outside"   // outside FoxByte
)

// The states of an outcome.
const (
	StateMet           = "met"
	StatePending       = "pending"        // will be met, by the date given
	StateNever         = "never"          // will not be met by itself; Why says what it takes
	StateLost          = "lost"           // was met, and a check now finds otherwise
	StateKept          = "kept"           // a law requires it kept: until the date given
	StateNotTraced     = "not traced"     // FoxByte does not follow it
	StateNotApplicable = "not applicable" // nothing of the kind here
	StateOutside       = "outside"        // never met by FoxByte
)

// ErasureOutcome is one outcome: whether it is met, by when, and on what.
type ErasureOutcome struct {
	Key   string     `json:"key"`
	Name  string     `json:"name"`
	State string     `json:"state"`
	Date  *time.Time `json:"date,omitempty"`
	// Estimated says the date is reckoned (the backups': interval × kept),
	// not seen.
	Estimated bool     `json:"estimated,omitempty"`
	Why       string   `json:"why,omitempty"`
	Evidence  []string `json:"evidence"`
}

// ErasureCopyOut is a copy outside FoxByte's reach, listed, never implied
// reached (section 14).
type ErasureCopyOut struct {
	Kind   string     `json:"kind"` // export, blackbox, tar, realtime, pipeline, import, siem, state, disk
	What   string     `json:"what"`
	At     *time.Time `json:"at,omitempty"`
	Branch string     `json:"branch,omitempty"`
	Warn   bool       `json:"warn,omitempty"` // it will bring the person back
}

// ErasureOutcomes is a request's outcomes as read now.
type ErasureOutcomes struct {
	Request  int64            `json:"request"`
	Checked  time.Time        `json:"checked"`
	Outcomes []ErasureOutcome `json:"outcomes"`
	// ClearsOn is the latest date among the outcomes FoxByte meets; nil
	// when it is never (Never says why) or not yet known (Unknown says why).
	ClearsOn *time.Time       `json:"clearsOn,omitempty"`
	Never    []string         `json:"never"`
	Unknown  []string         `json:"unknown"`
	Outside  []ErasureCopyOut `json:"outside"`
	// Recheck is what searching the branches again found (status only).
	Recheck *ErasureRecheck `json:"recheck,omitempty"`
	Notes   []string        `json:"notes"`
}

// Outcome returns the outcome of a key.
func (o ErasureOutcomes) Outcome(key string) (ErasureOutcome, bool) {
	for _, x := range o.Outcomes {
		if x.Key == key {
			return x, true
		}
	}
	return ErasureOutcome{}, false
}

// ---- what the outcomes read --------------------------------------------------

// outcomeFacts is everything the outcomes read beside the request, gathered
// once (gatherOutcomeFacts) so the reckoning itself is a pure function.
type outcomeFacts struct {
	Now time.Time

	BackupsOff  bool
	Interval    time.Duration
	Retain      int
	Backups     []BackupInfo // newest first
	BackupsErr  string
	Lock        LockInfo
	LockErr     string
	Target      string   // the target in force, as named
	Prefix      string   // the archive prefix in force ("" for the root)
	Prefixes    []string // every archive on the target in force
	PrefixErr   string
	TargetsLeft []TargetLeft
	Standby     bool

	Tars       []TarRecord // recorded, oldest first
	ExportsDir string
	ServerTars []TarFile // in this machine's exports folder now
	Host       *HostExports

	AuditOn       bool
	AuditDays     int
	Forwarding    string // the SIEM's address, "" for none
	DataExports   []auth.SecurityEvent
	LedgerExports []auth.SecurityEvent

	Realtime  map[string][]RealtimeSlot
	Keys      map[string]int // realtime keys a branch has
	Pipelines []auth.PipelineTarget
	Imports   []Replication
}

// Swapped by tests.
var gatherOutcomeFacts = realOutcomeFacts

func realOutcomeFacts(s *auth.Store, v ErasureView) outcomeFacts {
	f := outcomeFacts{Now: time.Now().UTC(), Interval: backupInterval(), Retain: backupRetain(),
		Realtime: map[string][]RealtimeSlot{}, Keys: map[string]int{}}
	f.BackupsOff = f.Interval == 0
	if bs, err := Backups(); err != nil {
		f.BackupsErr = err.Error()
	} else {
		f.Backups = bs
	}
	t, err := CurrentTarget()
	if err != nil {
		f.PrefixErr = err.Error()
	} else {
		f.Target = targetRoot(t)
		if t.Remote() {
			if l, err := CheckAnchorBucket(t); err != nil {
				f.LockErr = err.Error()
			} else {
				f.Lock = l
			}
		}
		f.Prefix = currentPrefix()
		if ps, err := archivePrefixes(t); err != nil {
			f.PrefixErr = err.Error()
		} else {
			f.Prefixes = ps
		}
	}
	f.TargetsLeft = TargetsLeft()
	f.Standby = ContainerState("standby") != "absent"
	f.ExportsDir = ExportsDir()
	f.ServerTars = ListTars(f.ExportsDir)
	if h, ok := LoadHostExports(); ok {
		f.Host = &h
	}
	f.AuditOn, f.AuditDays = AuditOn(), AuditRetentionDays()
	if fw := LoadAuditSettings().Forward; fw != nil {
		f.Forwarding = fw.URL
	}
	if s != nil {
		f.Tars, _ = RecordedTars(s)
		f.DataExports, _ = s.SecurityEventsOfKind(auth.EvDataExport)
		f.LedgerExports, _ = s.SecurityEventsOfKind(auth.EvLedgerExport)
		f.Pipelines, _ = s.PipelineTargets()
		for _, b := range affectedBranches(v) {
			if ks, err := s.RealtimeKeysFor(b); err == nil {
				f.Keys[b] = len(ks)
			}
		}
	}
	if RealtimeOn() {
		for _, b := range affectedBranches(v) {
			if sl, err := RealtimeSlots(b); err == nil && len(sl) > 0 {
				f.Realtime[b] = sl
			}
		}
	}
	f.Imports, _ = Replicating()
	return f
}

// affectedBranches are the branches the request erased: main, and every
// branch it was applied to.
func affectedBranches(v ErasureView) []string {
	out := []string{v.Branch}
	for _, b := range v.Branches {
		if b.Result != nil {
			out = append(out, b.Branch)
		}
	}
	return out
}

// appliedOn is when the request was applied on a branch: zero where it was
// not.
func appliedOn(v ErasureView, name string) time.Time {
	if name == v.Branch {
		if v.Result != nil {
			return v.Result.Applied
		}
		return time.Time{}
	}
	for _, b := range v.Branches {
		if b.Branch == name && b.Result != nil {
			return b.Result.Applied
		}
	}
	return time.Time{}
}

// ---- the reckoning -----------------------------------------------------------

// ErasureOutcomesFor reads a request's outcomes now. Free.
func ErasureOutcomesFor(s *auth.Store, v ErasureView) ErasureOutcomes {
	return reckonOutcomes(v, gatherOutcomeFacts(s, v))
}

func reckonOutcomes(v ErasureView, f outcomeFacts) ErasureOutcomes {
	o := ErasureOutcomes{Request: v.ID, Checked: f.Now, Outcomes: []ErasureOutcome{}, Never: []string{}, Unknown: []string{},
		Outside: []ErasureCopyOut{}, Notes: []string{}}
	if v.Result == nil {
		o.Notes = append(o.Notes, "The request is not applied, so it has no outcomes yet.")
		return o
	}
	add := func(x ErasureOutcome) {
		if x.Evidence == nil {
			x.Evidence = []string{}
		}
		o.Outcomes = append(o.Outcomes, x)
	}
	add(liveOutcome(v))
	add(filesOutcome(v))
	add(logsOutcome(v))
	add(vaultOutcome(v))
	add(ErasureOutcome{Key: OutcomeDerived, Name: "Derived data", State: StateNotTraced,
		Evidence: []string{"Derived data (aggregates, models, caches built from the person's rows) is not traced: FoxByte cannot tell what was derived from whom (design, section 10)."}})
	add(branchesOutcome(v))
	add(backupsOutcome(v, f))
	add(auditOutcome(v, f))
	for _, x := range exceptionOutcomes(v) {
		add(x)
	}
	o.Outside = outsideCopies(v, f)
	add(ErasureOutcome{Key: OutcomeOutside, Name: "Outside FoxByte", State: StateOutside,
		Evidence: []string{fmt.Sprintf("%d place(s) listed: FoxByte cannot reach them, and never says it did.", len(o.Outside))}})

	settleClears(&o)
	return o
}

// settleClears reckons the one date from the outcomes: the latest date
// among what FoxByte meets, or none while one is never met (Never) or has no
// date yet (Unknown).
func settleClears(o *ErasureOutcomes) {
	o.Never, o.Unknown, o.ClearsOn = []string{}, []string{}, nil
	var latest time.Time
	for _, x := range o.Outcomes {
		switch x.State {
		case StateNever, StateLost:
			o.Never = append(o.Never, x.Name+": "+x.Why)
		case StatePending, StateKept:
			if x.Date == nil {
				o.Unknown = append(o.Unknown, x.Name+": "+x.Why)
				continue
			}
			if x.Date.After(latest) {
				latest = *x.Date
			}
		case StateMet:
			if x.Date != nil && x.Date.After(latest) {
				latest = *x.Date
			}
		}
	}
	if len(o.Never) == 0 && len(o.Unknown) == 0 && !latest.IsZero() {
		o.ClearsOn = &latest
	}
}

func atTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func day(t time.Time) string { return t.Local().Format("2006-01-02 15:04") }

func liveOutcome(v ErasureView) ErasureOutcome {
	x := ErasureOutcome{Key: OutcomeLive, Name: "Removed from live queries"}
	latest := v.Result.Applied
	if v.Result.Vacuumed != nil && v.Result.Vacuumed.After(latest) {
		latest = *v.Result.Vacuumed
	}
	x.Evidence = append(x.Evidence, fmt.Sprintf("%s: %d row(s) changed at %s%s", v.Branch, v.Result.Rows, day(v.Result.Applied), verifiedNote(*v.Result)))
	var left []string
	for _, b := range v.Branches {
		switch {
		case b.Result != nil:
			x.Evidence = append(x.Evidence, fmt.Sprintf("%s: %d row(s) changed at %s%s", b.Branch, b.Result.Rows, day(b.Result.Applied), verifiedNote(*b.Result)))
			t := b.Result.Applied
			if b.Result.Vacuumed != nil {
				t = *b.Result.Vacuumed
			}
			if t.After(latest) {
				latest = t
			}
		case b.State == BranchPlanned || b.State == BranchSkipped:
			left = append(left, b.Branch)
		}
	}
	if len(left) > 0 {
		x.State, x.Why = StateNever, fmt.Sprintf("not applied yet on %s: run %s dpdp erase apply %d --branch <b>", strings.Join(left, ", "), brand.CLI, v.ID)
		return x
	}
	x.State, x.Date = StateMet, atTime(latest)
	return x
}

func verifiedNote(r ErasureResult) string {
	if r.Verified {
		return "; a search afterwards found none"
	}
	return ""
}

func filesOutcome(v ErasureView) ErasureOutcome {
	x := ErasureOutcome{Key: OutcomeFiles, Name: "Rewritten in the files"}
	var latest time.Time
	var left []string
	each := func(name string, r *ErasureResult) {
		for _, w := range r.Rewrites {
			switch {
			case w.State == RewriteDone && w.At != nil:
				x.Evidence = append(x.Evidence, fmt.Sprintf("%s: %s.%s rewritten at %s", name, w.Schema, w.Table, day(*w.At)))
				if w.At.After(latest) {
					latest = *w.At
				}
			default:
				left = append(left, fmt.Sprintf("%s.%s on %s", w.Schema, w.Table, name))
			}
		}
		if r.Statistics != nil && r.Statistics.After(latest) {
			latest = *r.Statistics
		}
	}
	each(v.Branch, v.Result)
	for _, b := range v.Branches {
		if b.Result != nil {
			each(b.Branch, b.Result)
		}
	}
	if len(left) > 0 {
		x.State, x.Why = StateNever, fmt.Sprintf("%s still to rewrite: run %s dpdp erase rewrite %d", strings.Join(left, ", "), brand.CLI, v.ID)
		return x
	}
	if latest.IsZero() {
		latest = v.Result.Applied
	}
	x.State, x.Date = StateMet, atTime(latest)
	return x
}

func logsOutcome(v ErasureView) ErasureOutcome {
	x := ErasureOutcome{Key: OutcomeLogs, Name: "Logs and records cleared", State: StateMet, Date: atTime(v.Result.Applied)}
	if bb := v.Result.Blackbox; bb != nil {
		x.Evidence = append(x.Evidence, fmt.Sprintf("Blackbox: %d entr(ies) redacted with a seal, %d original text(s) deleted, %d schema change(s) kept as written and flagged",
			bb.Redacted, bb.Originals, len(bb.Flagged)))
	}
	if c := v.Result.Copies; c != nil {
		x.Evidence = append(x.Evidence, fmt.Sprintf("%d query history entr(ies) deleted; %d audit log text(s) removed; %d change request(s) rewritten",
			c.History, c.Forensic, c.Requests))
	}
	if p := v.Plan.Copies; p != nil {
		if len(p.Saved) > 0 {
			x.Evidence = append(x.Evidence, fmt.Sprintf("%d saved quer(ies) holding a value, listed for their owners to delete", len(p.Saved)))
		}
		if len(p.OpenRequests) > 0 {
			x.Evidence = append(x.Evidence, fmt.Sprintf("open change request(s) %s left as they are until decided", idList(p.OpenRequests)))
		}
		if p.RawAudit > 0 && p.RawUntil != nil {
			x.Evidence = append(x.Evidence, fmt.Sprintf("%d raw audit file(s) not yet collected, removed by %s", p.RawAudit, day(*p.RawUntil)))
			if p.RawUntil.After(*x.Date) {
				x.Date = atTime(*p.RawUntil)
			}
		}
	}
	return x
}

func idList(ids []int64) string {
	ss := make([]string, len(ids))
	for i, id := range ids {
		ss[i] = "#" + strconv.FormatInt(id, 10)
	}
	return strings.Join(ss, ", ")
}

func vaultOutcome(v ErasureView) ErasureOutcome {
	x := ErasureOutcome{Key: OutcomeVault, Name: "Vault record deleted"}
	c := v.Result.Copies
	if c == nil || c.Vault+c.VaultKept == 0 {
		x.State = StateNotApplicable
		x.Evidence = []string{"The vault held no record of the values given."}
		return x
	}
	x.State, x.Date = StateMet, atTime(v.Result.Applied)
	x.Evidence = append(x.Evidence, fmt.Sprintf("%d vault record(s) deleted, the vault's log recording each", c.Vault))
	if c.VaultKept > 0 {
		x.Evidence = append(x.Evidence, fmt.Sprintf("%d kept, a law requiring it (see the exceptions)", c.VaultKept))
	}
	return x
}

func branchesOutcome(v ErasureView) ErasureOutcome {
	x := ErasureOutcome{Key: OutcomeBranches, Name: "Dependent branches cleared"}
	latest := mainDone(v)
	for _, b := range v.Branches {
		if b.DoneAt != nil {
			x.Evidence = append(x.Evidence, fmt.Sprintf("%s %s by %s at %s", b.Branch, b.Done, b.DoneBy, day(*b.DoneAt)))
			if b.DoneAt.After(latest) {
				latest = *b.DoneAt
			}
		}
	}
	if len(v.MadeBefore) > 0 {
		var names []string
		for _, m := range v.MadeBefore {
			names = append(names, m.Branch)
		}
		x.State, x.Why = StateNever, fmt.Sprintf("%s made before the erasure still hold(s) the person: remake or delete each (%s dpdp erase status %d)",
			strings.Join(names, ", "), brand.CLI, v.ID)
		return x
	}
	if latest.IsZero() {
		latest = v.Result.Applied
	}
	x.State, x.Date = StateMet, atTime(latest)
	if len(x.Evidence) == 0 {
		x.Evidence = []string{"No branch made before the erasure is left."}
	}
	return x
}

// rewriteDone is when the last of the request's rewrites finished
// everywhere: the archive holds the person in WAL and backups up to then.
func rewriteDone(v ErasureView) (time.Time, bool) {
	latest := doneAt(v.Result)
	if latest.IsZero() {
		return time.Time{}, false
	}
	for _, b := range v.Branches {
		if b.Result == nil {
			continue
		}
		t := doneAt(b.Result)
		if t.IsZero() {
			return time.Time{}, false
		}
		if t.After(latest) {
			latest = t
		}
	}
	return latest, true
}

var validityRe = regexp.MustCompile(`(?i)^\s*(\d+)\s*(day|days|year|years|d|y)\s*$`)

// lockValidity reads an Object Lock default ("30DAYS", "1YEARS").
func lockValidity(s string) (time.Duration, bool) {
	m := validityRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.Atoi(m[1])
	if strings.HasPrefix(strings.ToLower(m[2]), "y") {
		return time.Duration(n) * 365 * 24 * time.Hour, true
	}
	return time.Duration(n) * 24 * time.Hour, true
}

func backupsOutcome(v ErasureView, f outcomeFacts) ErasureOutcome {
	x := ErasureOutcome{Key: OutcomeBackups, Name: "Backup and WAL expiry"}
	r, ok := rewriteDone(v)
	var never []string
	if !ok {
		never = append(never, "a rewrite is still open, and the archive keeps every page until it is done")
	}
	if f.BackupsOff {
		never = append(never, "backups are off ("+brand.EnvName("BACKUP_INTERVAL")+"=off), so no prune will come")
	}
	for _, p := range f.Prefixes {
		if p != f.Prefix {
			name := "the target's root"
			if p != "" {
				name = p
			}
			never = append(never, fmt.Sprintf("the archive at %s, kept from before an upgrade, is never pruned: delete it from %s once no rollback needs it", name, f.Target))
		}
	}
	for _, t := range f.TargetsLeft {
		if t.Gone == nil {
			never = append(never, fmt.Sprintf("%s, the backup target until %s, keeps its backups: once they are deleted, say so with %s backup target forget %s --reason \"…\"",
				t.Root, day(t.Until), brand.CLI, t.Root))
		} else {
			x.Evidence = append(x.Evidence, fmt.Sprintf("%s, left on %s: its backups said deleted by %s on %s (%s)", t.Root, day(t.Until), t.GoneBy, day(*t.Gone), t.Reason))
		}
	}
	never = append(never, tarsHolding(v, f)...)
	if f.PrefixErr != "" {
		x.Evidence = append(x.Evidence, "The backup target's archives could not be listed: "+f.PrefixErr)
	}
	if f.Standby {
		x.Evidence = append(x.Evidence, "The HA standby has no archive of its own: it archives to the same place, and follows main by replication.")
	}
	x.Evidence = append(x.Evidence, fmt.Sprintf("Backups every %s, %d kept (%s, %s)", f.Interval, f.Retain, brand.EnvName("BACKUP_INTERVAL"), brand.EnvName("BACKUP_RETAIN")))
	if len(never) > 0 {
		x.State, x.Why = StateNever, strings.Join(never, "; ")
		return x
	}
	if f.BackupsErr != "" {
		x.State, x.Why = StatePending, "the backups could not be listed now: "+f.BackupsErr
		return x
	}
	// Backups newest first: the oldest kept is the last.
	var after []BackupInfo
	oldest := time.Time{}
	for _, b := range f.Backups {
		st, err := time.Parse(time.RFC3339, b.StartedAt)
		if err != nil {
			continue
		}
		if oldest.IsZero() || st.Before(oldest) {
			oldest = st
		}
		if st.After(r) {
			after = append(after, b)
		}
	}
	if !oldest.IsZero() {
		x.Evidence = append(x.Evidence, "The oldest backup kept started at "+day(oldest))
	}
	floor := time.Time{}
	if f.Lock.Enabled {
		if d, ok := lockValidity(f.Lock.DefaultValidity); ok {
			floor = r.Add(d)
			x.Evidence = append(x.Evidence, fmt.Sprintf("Object Lock on the bucket keeps every object %s after it is written: nothing from before the rewrite can go before %s",
				strings.ToLower(f.Lock.DefaultValidity), day(floor)))
		}
	} else if f.LockErr != "" {
		x.Evidence = append(x.Evidence, "The bucket's Object Lock could not be read: "+f.LockErr)
	}
	if !oldest.IsZero() && oldest.After(r) && !f.Now.Before(floor) {
		// Every backup from before the rewrite is pruned, and the WAL kept
		// starts at the oldest backup kept.
		x.State, x.Date = StateMet, atTime(prunedAt(after, f.Retain, oldest))
		return x
	}
	// Still held: the prune after the N-th backup since the rewrite takes the
	// last of it.
	sort.Slice(after, func(i, j int) bool { return after[i].StartedAt < after[j].StartedAt })
	from, n := r, len(after)
	if n > 0 {
		if t, err := time.Parse(time.RFC3339, after[n-1].FinishedAt); err == nil {
			from = t
		}
	}
	left := f.Retain - n
	if left < 1 {
		left = 1
	}
	due := from.Add(time.Duration(left) * f.Interval)
	if due.Before(floor) {
		due = floor
	}
	x.State, x.Date, x.Estimated = StatePending, atTime(due), true
	x.Why = fmt.Sprintf("held in backups and WAL from before the rewrite of %s until the prune after the %d-th backup since it (%d taken)", day(r), f.Retain, n)
	return x
}

// prunedAt is about when the backups from before the rewrite were pruned:
// after the N-th backup since the rewrite.
func prunedAt(after []BackupInfo, retain int, oldest time.Time) time.Time {
	sort.Slice(after, func(i, j int) bool { return after[i].StartedAt < after[j].StartedAt })
	if retain >= 1 && len(after) >= retain {
		if t, err := time.Parse(time.RFC3339, after[retain-1].FinishedAt); err == nil {
			return t
		}
	}
	return oldest
}

// tarsHolding is each install tar FoxByte keeps that was made before the
// erasure, on a branch it erased: never, while it is there (decided 27
// November 2026). One made with --out elsewhere is listed outside instead.
func tarsHolding(v ErasureView, f outcomeFacts) []string {
	var out []string
	seen := map[string]bool{}
	holds := func(created time.Time, branches []string) bool {
		if len(branches) == 0 {
			return created.Before(v.Result.Applied) // which branches is not known: the earliest erasure
		}
		for _, b := range branches {
			if t := appliedOn(v, b); !t.IsZero() && created.Before(t) {
				return true
			}
		}
		return false
	}
	say := func(path, where string) string {
		return fmt.Sprintf("the install tar %s%s, made before the erasure, holds the person until it is deleted", path, where)
	}
	recorded := map[string]TarRecord{}
	for _, r := range f.Tars {
		recorded[r.Place+"\x00"+r.Path] = r
	}
	// On this machine: the folder as it is now.
	for _, t := range f.ServerTars {
		r, ok := recorded[TarOnServer+"\x00"+t.Path]
		created, branches := t.Modified, []string(nil)
		if ok {
			created, branches = r.Created, r.Branches
		}
		if holds(created, branches) && !seen[t.Path] {
			seen[t.Path] = true
			out = append(out, say(t.Path, ""))
		}
	}
	// On the host: the folder as the host last listed it.
	if f.Host != nil {
		for _, t := range f.Host.Tars {
			r, ok := recorded[TarOnHost+"\x00"+t.Path]
			created, branches := t.Modified, []string(nil)
			if ok {
				created, branches = r.Created, r.Branches
			}
			if holds(created, branches) && !seen[t.Path] {
				seen[t.Path] = true
				out = append(out, say(t.Path, fmt.Sprintf(" (on the host, as listed at %s)", day(f.Host.Checked))))
			}
		}
	}
	// Recorded in a host's folder it has not listed since: still there, as
	// far as FoxByte knows.
	for _, r := range f.Tars {
		if r.Place != TarOnHost || seen[r.Path] || !holds(r.Created, r.Branches) {
			continue
		}
		if f.Host != nil && f.Host.Checked.After(r.Created) && inDir(r.Path, f.Host.Dir) {
			continue // the host listed its folder since, and it was not there
		}
		if f.Host == nil || inDir(r.Path, f.Host.Dir) {
			seen[r.Path] = true
			out = append(out, say(r.Path, " (on the host; not listed since: run "+brand.CLI+" dpdp erase status there)"))
		}
	}
	return out
}

func inDir(path, dir string) bool {
	return dir != "" && filepath.Dir(path) == filepath.Clean(dir)
}

func auditOutcome(v ErasureView, f outcomeFacts) ErasureOutcome {
	x := ErasureOutcome{Key: OutcomeAudit, Name: "Audit records aged out"}
	if !f.AuditOn && f.AuditDays <= 0 {
		x.State, x.Evidence = StateNotApplicable, []string{"The audit log is off."}
		return x
	}
	ends := v.Result.Applied.Add(time.Duration(f.AuditDays) * 24 * time.Hour)
	x.Date = atTime(ends)
	x.Evidence = []string{fmt.Sprintf("The audit log's default-mode records keep no statement text; they are kept under the logging exception for %d day(s), so the last of the person's goes by %s",
		f.AuditDays, day(ends))}
	if !f.AuditOn {
		x.Evidence = append(x.Evidence, "The audit log is off now; records collected while it was on are kept for the same time.")
	}
	if f.Now.Before(ends) {
		x.State = StatePending
		x.Why = "kept for the audit log's retention"
		return x
	}
	x.State = StateMet
	return x
}

func exceptionOutcomes(v ErasureView) []ErasureOutcome {
	var out []ErasureOutcome
	each := func(name string, p *ErasurePlan) {
		if p == nil {
			return
		}
		for _, t := range p.Tables {
			for _, e := range t.Exceptions {
				place := t.Schema + "." + t.Table
				if e.Column != "" {
					place += "." + e.Column
				}
				x := ErasureOutcome{Key: OutcomeException, Name: "Retention exception: " + place + " on " + name, State: StateKept,
					Evidence: []string{"Kept under " + e.Citation + ": " + e.Text}}
				if e.Ends != nil {
					x.Date = atTime(*e.Ends)
					x.Why = "a law requires it kept until " + day(*e.Ends)
				} else {
					x.Why = "kept under " + e.Citation + "; the end date is not given: give the event's date with --event when the request is made"
				}
				out = append(out, x)
			}
		}
	}
	each(v.Branch, &v.Plan)
	for _, b := range v.Branches {
		if b.Result != nil {
			each(b.Branch, b.Plan)
		}
	}
	return out
}

// outsideCopies lists what FoxByte made or feeds that it cannot reach
// (section 14).
func outsideCopies(v ErasureView, f outcomeFacts) []ErasureCopyOut {
	out := []ErasureCopyOut{}
	affected := map[string]bool{}
	for _, b := range affectedBranches(v) {
		affected[b] = true
	}
	before := func(e auth.SecurityEvent) (time.Time, bool) {
		t, err := time.Parse(time.RFC3339Nano, e.At)
		if err != nil || !affected[e.Subject] {
			return t, false
		}
		ap := appliedOn(v, e.Subject)
		return t, !ap.IsZero() && t.Before(ap)
	}
	for _, e := range f.DataExports {
		if t, ok := before(e); ok {
			out = append(out, ErasureCopyOut{Kind: "export", Branch: e.Subject, At: atTime(t),
				What: fmt.Sprintf("a query result exported by %s (%s); FoxByte cannot tell whether it held the person", e.Actor, e.Detail)})
		}
	}
	for _, e := range f.LedgerExports {
		if t, ok := before(e); ok {
			out = append(out, ErasureCopyOut{Kind: "blackbox", Branch: e.Subject, At: atTime(t),
				What: fmt.Sprintf("the Blackbox of %s exported by %s, every statement's text with it", e.Subject, e.Actor)})
		}
	}
	for _, r := range f.Tars {
		inFolder := (r.Place == TarOnServer && inDir(r.Path, f.ExportsDir)) || (r.Place == TarOnHost && (f.Host == nil || inDir(r.Path, f.Host.Dir)))
		if inFolder || !r.Created.Before(v.Result.Applied) {
			continue
		}
		where := ""
		if r.Place == TarOnHost {
			where = " on the host"
		}
		out = append(out, ErasureCopyOut{Kind: "tar", At: atTime(r.Created),
			What: fmt.Sprintf("an install tar written%s to %s by %s (branches %s), outside FoxByte's exports folder", where, r.Path, r.By, strings.Join(r.Branches, ", "))})
	}
	for b, sl := range f.Realtime {
		for _, s := range sl {
			out = append(out, ErasureCopyOut{Kind: "realtime", Branch: b,
				What: fmt.Sprintf("realtime slot %s: its subscribers were sent the person's rows as they changed, and it retains %s of WAL until consumed", s.Name, humanBytes(uint64(max(s.WALBytes, 0))))})
		}
	}
	for b, n := range f.Keys {
		if n > 0 && len(f.Realtime[b]) == 0 {
			out = append(out, ErasureCopyOut{Kind: "realtime", Branch: b,
				What: fmt.Sprintf("%d realtime key(s) may have subscribed to %s and been sent the person's rows", n, b)})
		}
	}
	for _, p := range f.Pipelines {
		if affected[p.Branch] {
			out = append(out, ErasureCopyOut{Kind: "pipeline", Branch: p.Branch, Warn: true,
				What: fmt.Sprintf("pipeline %q loads %s: its source holds the person and will bring them back on its next run", p.Pipeline, p.Branch)})
		}
	}
	for _, r := range f.Imports {
		if r.Replicating && affected[r.Branch] {
			out = append(out, ErasureCopyOut{Kind: "import", Branch: r.Branch, Warn: true,
				What: fmt.Sprintf("a continuous import into %s: its source holds the person and will bring them back", r.Branch)})
		}
	}
	if f.Forwarding != "" {
		out = append(out, ErasureCopyOut{Kind: "siem", What: "the audit log's text forwarded to " + f.Forwarding + ", outside FoxByte"})
	}
	out = append(out,
		ErasureCopyOut{Kind: "state", What: "backups of the state directory (" + brand.StateDir() + "), which hold query history and the account store"},
		ErasureCopyOut{Kind: "disk", What: "freed disk blocks, which FoxByte cannot read or wipe (design, section 3)"})
	sort.SliceStable(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}
