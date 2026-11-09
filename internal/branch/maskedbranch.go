// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Masked branches (F5, Gate 1 step 5; design, section 12).
//
// `fox branch create <name> --masked [--from main]` makes a branch whose
// marked columns hold their masks in place of the real values, for people and
// agents who should never see those: a copy to develop and test on.
//
//  1. The branch is recorded as being masked before it exists, so it is closed
//     from its first moment: the Gateway, the console, the API, MCP and the
//     agents refuse it (checkBranchOpen); only the engine connects. Its
//     container never mounts the masking key.
//  2. Enterprise's MaskBranch overwrites every marked column with the mask a
//     masked reader sees (from the shadows and views the copy came with),
//     checks every row now holds exactly that, removes the masks' machinery,
//     starts the Blackbox afresh (its statements were the source's), rewrites
//     the masked tables' and the statistics' files, and removes the WAL from
//     before.
//  3. It verifies: no WAL segment from before is left, nothing of the old
//     Blackbox, and the personal-data scan finds no masked category in a
//     column without a rule. Only then is the branch opened.
//  4. A run that fails, or stops part way, leaves the branch closed and says
//     why; running the command again starts over from the source.
//
// On an open masked branch nobody is masked: the data is. The Blackbox keeps
// numbering after the source's last entry, and the record keeps that entry,
// so a change request from the branch carries only what was done on it.

// MaskedBranch is one masked branch: where it came from, how far its making
// got, and what it found.
type MaskedBranch struct {
	Name     string `json:"name"`
	From     string `json:"from"`
	By       string `json:"by"`
	Started  string `json:"started"`
	Finished string `json:"finished,omitempty"`
	State    string `json:"state"`          // making | open | failed
	Step     string `json:"step,omitempty"` // while making, or where it failed
	Error    string `json:"error,omitempty"`
	// Problems are what verification found, each a sentence.
	Problems []string `json:"problems,omitempty"`
	// Fork is the source's last Blackbox entry when the branch was copied:
	// what a change request from it is measured from.
	Fork  int64      `json:"fork"`
	Rules []MaskRule `json:"rules"` // what was masked
	// Tables and Rows masked in place.
	Tables int   `json:"tables"`
	Rows   int64 `json:"rows"`
	// Inherited: made of a masked branch, whose data was masked already.
	Inherited bool `json:"inherited,omitempty"`
	PID       int  `json:"pid,omitempty"` // the process making it
}

// The states.
const (
	MaskedMaking = "making"
	MaskedOpen   = "open"
	MaskedFailed = "failed"
)

// ErrBranchClosed is the refusal for a masked branch not yet open.
var ErrBranchClosed = errors.New("closed")

// ErrNothingToMask is a masked branch asked of a source with no rules.
var ErrNothingToMask = errors.New("nothing to mask")

var maskedBranchPath = func() string { return brand.StatePath("masked-branches.json") }

var maskedBranches struct {
	sync.Mutex
	mod    time.Time
	size   int64
	byName map[string]MaskedBranch
}

// loadMaskedBranches reads the records, again whenever the file changes: the
// CLI makes a branch while the Gateway runs.
func loadMaskedBranches() map[string]MaskedBranch {
	maskedBranches.Lock()
	defer maskedBranches.Unlock()
	st, err := os.Stat(maskedBranchPath())
	if err != nil {
		maskedBranches.byName, maskedBranches.mod, maskedBranches.size = nil, time.Time{}, 0
		return nil
	}
	if maskedBranches.byName != nil && st.ModTime().Equal(maskedBranches.mod) && st.Size() == maskedBranches.size {
		return maskedBranches.byName
	}
	m := map[string]MaskedBranch{}
	if b, err := os.ReadFile(maskedBranchPath()); err == nil {
		var list []MaskedBranch
		if json.Unmarshal(b, &list) == nil {
			for _, r := range list {
				m[r.Name] = r
			}
		}
	}
	maskedBranches.byName, maskedBranches.mod, maskedBranches.size = m, st.ModTime(), st.Size()
	return m
}

var maskedBranchWrite sync.Mutex

func saveMaskedBranches(m map[string]MaskedBranch) error {
	list := make([]MaskedBranch, 0, len(m))
	for _, r := range m {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := maskedBranchPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, maskedBranchPath())
}

// putMaskedBranch keeps a record, replacing one of its name.
func putMaskedBranch(r MaskedBranch) error {
	maskedBranchWrite.Lock()
	defer maskedBranchWrite.Unlock()
	m := map[string]MaskedBranch{}
	for k, v := range loadMaskedBranches() {
		m[k] = v
	}
	m[r.Name] = r
	return saveMaskedBranches(m)
}

// forgetMaskedBranch drops a deleted branch's record.
func forgetMaskedBranch(name string) {
	if _, ok := loadMaskedBranches()[name]; !ok {
		return
	}
	maskedBranchWrite.Lock()
	defer maskedBranchWrite.Unlock()
	m := map[string]MaskedBranch{}
	for k, v := range loadMaskedBranches() {
		if k != name {
			m[k] = v
		}
	}
	_ = saveMaskedBranches(m)
}

// MaskedBranchOf reads a branch's record.
func MaskedBranchOf(name string) (MaskedBranch, bool) {
	r, ok := loadMaskedBranches()[name]
	return r, ok
}

// IsMaskedBranch reports whether a branch is a masked branch, open or not.
func IsMaskedBranch(name string) bool {
	_, ok := MaskedBranchOf(name)
	return ok
}

// maskedBranchOpen reports whether a branch is a masked branch, made and
// verified: its data holds the masks, so nobody is masked on it.
func maskedBranchOpen(name string) bool {
	r, ok := MaskedBranchOf(name)
	return ok && r.State == MaskedOpen
}

// MaskedBranches lists the records, by name. Free.
func MaskedBranches() []MaskedBranch {
	out := []MaskedBranch{}
	for _, r := range loadMaskedBranches() {
		out = append(out, withLiveness(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// withLiveness says when a making has stopped: its process is gone.
func withLiveness(r MaskedBranch) MaskedBranch {
	if r.State == MaskedMaking && r.PID > 0 && !processAlive(r.PID) {
		r.State = MaskedFailed
		if r.Error == "" {
			r.Error = "stopped part way, at " + r.Step
		}
	}
	return r
}

// processAlive asks whether the process making a masked branch is still
// there (maskedbranch_unix.go). A variable so the tests can say.
var processAlive = pidAlive

// MaskedBranchFork is the source's last Blackbox entry when a masked branch
// was copied, for a change request from it (enterprise/promote).
func MaskedBranchFork(name string) (int64, bool) {
	r, ok := MaskedBranchOf(name)
	if !ok || r.State != MaskedOpen {
		return 0, false
	}
	return r.Fork, true
}

// checkBranchOpen refuses a masked branch not yet open, saying why and what
// to do: every way a client reaches a branch asks it (EnsureRunning, the
// API's branch routes, the engine's agent sessions).
func checkBranchOpen(name string) error {
	r, ok := MaskedBranchOf(name)
	if !ok || r.State == MaskedOpen {
		return nil
	}
	r = withLiveness(r)
	if r.State == MaskedMaking {
		return fmt.Errorf("%w: branch %q is being masked (%s), and opens once it is masked and verified", ErrBranchClosed, name, r.Step)
	}
	why := r.Error
	if len(r.Problems) > 0 {
		why = strings.Join(r.Problems, "; ")
	}
	return fmt.Errorf("%w: branch %q was not masked (%s), so it stays closed: %s branch create %s --masked --from %s starts again, or %s branch delete %s",
		ErrBranchClosed, name, why, brand.CLI, name, r.From, brand.CLI, name)
}

// CheckBranchOpen is checkBranchOpen for the control plane and the agents.
func CheckBranchOpen(name string) error { return checkBranchOpen(name) }

// maskBranchTimeout bounds one step of a making: masking a large table in
// place, or rewriting its files, takes minutes.
func maskBranchTimeout() time.Duration {
	if v, err := time.ParseDuration(brand.Getenv("MASK_BRANCH_TIMEOUT")); err == nil && v > 0 {
		return v
	}
	return 2 * time.Hour
}

// MaskedBranchSQL runs a script on a branch being masked, as the engine, a
// statement at a time (VACUUM must be one of its own), and returns what the
// last statement printed. For enterprise/masking.
func MaskedBranchSQL(name, sql string) (string, error) {
	cmd, ctx, cancel := sudoCmd(maskBranchTimeout(), "docker", "exec", "-i",
		"--env-file", pgEnvFile(), container(name),
		"psql", "-X", "-q", "-tA", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1")
	defer cancel()
	// Notices (a drop cascading, an object not there) are no news, and would
	// land in what is read back.
	cmd.Stdin = strings.NewReader("SET client_min_messages = warning;\n" + sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), execErr(ctx, maskBranchTimeout(), "psql", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out))))
	}
	return string(out), nil
}

// MaskedBranchWork is what Enterprise reports of a making.
type MaskedBranchWork struct {
	Tables   int
	Rows     int64
	Problems []string
}

// CreateMasked makes a masked branch of from (main when ""). say, when not
// nil, is told each step. A name whose earlier making failed or stopped is
// made again from the start; one that is open is refused. A source with no
// rules is refused with ErrNothingToMask. A failure leaves the branch closed,
// its record saying why. Enterprise.
func CreateMasked(name, from, actor string, say func(string)) (MaskedBranch, error) {
	rec, err := createMasked(name, from, actor, say)
	// A reservation (ReserveMasked) the making never got past is taken back:
	// nothing was made.
	if err != nil && rec.Name == "" {
		if r, ok := MaskedBranchOf(name); ok && r.Step == reservedStep && r.PID == os.Getpid() {
			forgetMaskedBranch(name)
		}
	}
	return rec, err
}

// reservedStep is a masked branch asked for and not yet started.
const reservedStep = "waiting to start"

// ReserveMasked records a masked branch as being made before its making
// starts, so it is closed from the moment it is asked for: the API answers
// before the work in the background has begun.
func ReserveMasked(name, from, actor string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if old, ok := MaskedBranchOf(name); ok && withLiveness(old).State == MaskedMaking {
		return fmt.Errorf("%w: branch %q is being masked now (%s)", ErrInvalidRequest, name, old.Step)
	}
	if from == "" {
		from = "main"
	}
	return putMaskedBranch(MaskedBranch{Name: name, From: from, By: actor, Started: time.Now().UTC().Format(time.RFC3339),
		State: MaskedMaking, Step: reservedStep, PID: os.Getpid()})
}

func createMasked(name, from, actor string, say func(string)) (MaskedBranch, error) {
	if err := requireMasker(); err != nil {
		return MaskedBranch{}, err
	}
	if masker.MaskBranch == nil {
		return MaskedBranch{}, ErrMaskingNotLicensed
	}
	if from == "" {
		from = "main"
	}
	if err := checkName(name); err != nil {
		return MaskedBranch{}, err
	}
	if err := checkName(from); err != nil {
		return MaskedBranch{}, err
	}
	if say == nil {
		say = func(string) {}
	}
	if old, ok := MaskedBranchOf(name); ok && !(old.Step == reservedStep && old.PID == os.Getpid()) {
		if withLiveness(old).State == MaskedMaking {
			return MaskedBranch{}, fmt.Errorf("%w: branch %q is being masked now (%s)", ErrInvalidRequest, name, old.Step)
		}
		if old.State == MaskedOpen {
			return MaskedBranch{}, fmt.Errorf("branch %q already exists", name)
		}
		// Never opened: started again from the source.
		say("the earlier making of " + name + " did not finish: starting again from " + from)
		if activeStorage().exists(name) {
			if err := Delete(name); err != nil {
				return MaskedBranch{}, err
			}
		}
		forgetMaskedBranch(name)
	}
	if !activeStorage().exists(from) {
		return MaskedBranch{}, fmt.Errorf("%w: %q", ErrParentNotFound, from)
	}
	if activeStorage().exists(name) {
		return MaskedBranch{}, fmt.Errorf("branch %q already exists", name)
	}
	if err := checkBranchOpen(from); err != nil {
		return MaskedBranch{}, err
	}
	// A masked branch's copy is masked already.
	if maskedBranchOpen(from) {
		say(from + " is a masked branch: its copy is masked already")
		if err := Create(name, from); err != nil {
			return MaskedBranch{}, err
		}
		r, _ := MaskedBranchOf(name)
		return r, nil
	}
	if _, err := EnsureRunning(from); err != nil {
		return MaskedBranch{}, err
	}
	rules, err := MaskRulesOn(from)
	if err != nil {
		return MaskedBranch{}, err
	}
	if len(rules) == 0 {
		return MaskedBranch{}, fmt.Errorf("%w: %s has no masking rules, so a masked branch of it would hold everything it holds: set rules first (%s mask rule … --branch %s)",
			ErrNothingToMask, from, brand.CLI, from)
	}
	ready, err := masker.MaskTables(from)
	if err != nil {
		return MaskedBranch{}, err
	}
	readyAt := map[string]bool{}
	for _, t := range ready {
		readyAt[t] = true
	}
	for _, r := range rules {
		if !readyAt[r.Table] && !readyAt[r.Schema+"."+r.Table] {
			return MaskedBranch{}, fmt.Errorf("%w: %s.%s's masks on %s are not made yet: %s mask setup --branch %s makes them",
				ErrInvalidRequest, r.Schema, r.Table, from, brand.CLI, from)
		}
	}
	fork := int64(0)
	if l, err := ledgerLines(from, "SELECT coalesce(max(id), 0) FROM bb.schema_ledger"); err == nil && len(l) > 0 {
		fork, _ = strconv.ParseInt(strings.TrimSpace(l[0]), 10, 64)
	}
	rec := MaskedBranch{Name: name, From: from, By: actor, Started: time.Now().UTC().Format(time.RFC3339),
		State: MaskedMaking, Step: "copying " + from, Fork: fork, Rules: rules, PID: os.Getpid()}
	step := func(s string) error {
		rec.Step = s
		say(s)
		return putMaskedBranch(rec)
	}
	fail := func(err error, problems []string) (MaskedBranch, error) {
		rec.State, rec.Error, rec.Problems, rec.PID = MaskedFailed, err.Error(), problems, 0
		rec.Finished = time.Now().UTC().Format(time.RFC3339)
		_ = putMaskedBranch(rec)
		return rec, fmt.Errorf("%w: %s stays closed: %v", ErrBranchClosed, name, err)
	}
	// Closed before it exists.
	if err := step("copying " + from); err != nil {
		return MaskedBranch{}, err
	}
	if err := Create(name, from); err != nil {
		forgetMaskedBranch(name)
		return MaskedBranch{}, err
	}
	work, err := masker.MaskBranch(name, rec, func(s string) { _ = step(s) })
	rec.Tables, rec.Rows = work.Tables, work.Rows
	if err != nil {
		return fail(err, work.Problems)
	}
	if len(work.Problems) > 0 {
		return fail(fmt.Errorf("verification found %d problem(s)", len(work.Problems)), work.Problems)
	}
	rec.State, rec.Step, rec.PID = MaskedOpen, "", 0
	rec.Finished = time.Now().UTC().Format(time.RFC3339)
	if err := putMaskedBranch(rec); err != nil {
		return rec, err
	}
	// The roles made on the copy were the source's; on this branch nobody is
	// masked, so each is made again when next used.
	forgetBranchRoles(name)
	say(name + " is masked and verified, and open")
	return rec, nil
}

// inheritMasked records a branch made of an open masked branch as one too:
// its data was masked already. Before its container starts, so it never
// mounts the key.
func inheritMasked(name, parent string) error {
	p, ok := MaskedBranchOf(parent)
	if !ok {
		return nil
	}
	if p.State != MaskedOpen {
		return checkBranchOpen(parent)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return putMaskedBranch(MaskedBranch{Name: name, From: parent, By: "copy of " + parent, Started: now, Finished: now,
		State: MaskedOpen, Fork: p.Fork, Rules: p.Rules, Inherited: true})
}

// maskedStateOf is a branch's masked state for the branch list, "" when it is
// not a masked branch.
func maskedStateOf(name string) string {
	r, ok := MaskedBranchOf(name)
	if !ok {
		return ""
	}
	return withLiveness(r).State
}
