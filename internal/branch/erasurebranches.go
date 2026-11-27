// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Erasure on every branch (F4, Gate 1 step 2; docs/FOX_F4_Erasure_Design.md,
// section 6).
//
// A request is planned on main and on every branch, and applied to all of
// them at once (decided 26 Nov): main first, then each branch in its own
// transaction, its rows matched again there. A branch whose plan has changed
// since it was shown, or that has a problem, is skipped and said so, and is
// applied on its own afterwards (ApplyErasureBranch). Making or planning a
// request wakes a suspended branch, so its rows are shown before anything is
// applied (decided 26 Nov); it suspends again when idle.
//
// A masked branch holds masks, not the person's values: it is found by main's
// row keys as well as by value. A masked branch being made, or one that
// failed, cannot be erased and is listed.
//
// However a branch is erased, one made before its parent's erasure still
// holds the person's old blocks in the snapshot it was cloned from (section
// 3, E9): it is listed, for an admin to remake from the erased parent or to
// delete. That list is read with the request, not stored, so a branch remade
// or deleted through any door is seen as it is.

// ErasureBranch is one branch's part of a request.
type ErasureBranch struct {
	Branch string     `json:"branch"`
	Parent string     `json:"parent"`
	Made   *time.Time `json:"made,omitempty"`
	Masked bool       `json:"masked"`
	// State: planned, applied, skipped (applied on its own later), listed
	// (it cannot be erased; Why says why) or gone (deleted since).
	State       string         `json:"state"`
	Why         string         `json:"why,omitempty"`
	Plan        *ErasurePlan   `json:"plan,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Result      *ErasureResult `json:"result,omitempty"`
	// Done is what an admin did to it from the request: remade or deleted.
	Done   string     `json:"done,omitempty"`
	DoneBy string     `json:"doneBy,omitempty"`
	DoneAt *time.Time `json:"doneAt,omitempty"`
}

// The states of a branch's part.
const (
	BranchPlanned = "planned"
	BranchApplied = "applied"
	BranchSkipped = "skipped"
	BranchListed  = "listed"
	BranchGone    = "gone"
)

// ErasureStale is a branch made before its parent's erasure: its files still
// hold the person until it is remade or deleted.
type ErasureStale struct {
	Branch string     `json:"branch"`
	Parent string     `json:"parent"`
	Made   *time.Time `json:"made,omitempty"`
	Owner  string     `json:"owner,omitempty"`
	Why    string     `json:"why"`
}

// BranchAge is a branch older than FOX_BRANCH_MAX_AGE.
type BranchAge struct {
	Branch string    `json:"branch"`
	Made   time.Time `json:"made"`
	Days   int       `json:"days"`
	// Personal: whether it holds confirmed personal data, when that could be
	// read (a branch not running is not woken to find out).
	Personal *bool `json:"personal,omitempty"`
}

// EnvBranchMaxAge is the age past which a branch is flagged (decision 6): off
// unless set; 90d is the documents' suggestion.
const EnvBranchMaxAge = "BRANCH_MAX_AGE"

// BranchMaxAge reads FOX_BRANCH_MAX_AGE: "90d", "12w", "720h"; 0 when off.
func BranchMaxAge() time.Duration {
	return parseAge(brand.Getenv(EnvBranchMaxAge))
}

func parseAge(v string) time.Duration {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "off" || v == "0" {
		return 0
	}
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if n, err := strconv.Atoi(strings.TrimSuffix(v, suffix)); err == nil && strings.HasSuffix(v, suffix) && n > 0 {
			return time.Duration(n) * unit
		}
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return 0
}

// erasingLock is the lock an erasure of a branch holds, and a copy of the
// branch takes while it clones: no branch is copied from one whose rows are
// being erased and whose files are being rewritten (section 6). An '@' is in
// no branch's name (checkName), so its file is no branch's.
func erasingLock(name string) string { return "erasing@" + name }

// withErasingLock runs fn holding name's erasing lock.
func withErasingLock(name string, fn func() error) error {
	unlock, err := lockBranch(erasingLock(name), "erased")
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// erasureBranchNames are the branches a request covers besides main: every
// branch, the HA standby apart (it follows main by replication).
var erasureBranchNames = func() ([]BranchInfo, error) {
	infos, err := Branches()
	if err != nil {
		return nil, err
	}
	out := infos[:0]
	for _, b := range infos {
		if b.Name != "main" && b.Name != "standby" {
			out = append(out, b)
		}
	}
	return out, nil
}

// branchFacts are a branch's parent and making time, variables so a test
// need not have a storage layer.
var (
	branchParentOf = func(name string) string {
		if p := BranchParent(name); p != "" {
			return p
		}
		return "main"
	}
	branchMadeOf   = func(name string) (time.Time, bool) { return branchMadeAt(name) }
	wakeForErase   = func(name string) error { _, err := EnsureRunning(name); return err }
	branchExistsF  = Exists
	resetForErase  = Reset
	deleteForErase = Delete
)

// planBranches plans every branch. prior's applied branches are kept as they
// are; seed is main's rows by key, for the masked branches.
func planBranches(eng *ErasureEngine, prior []ErasureBranch, values []ErasureValue, events map[string]string,
	actor string, seed ErasureSeed, refs []string) []ErasureBranch {
	kept := map[string]ErasureBranch{}
	for _, b := range prior {
		if b.State == BranchApplied {
			kept[b.Branch] = b
		}
	}
	infos, err := erasureBranchNames()
	out := []ErasureBranch{}
	if err != nil {
		return append(out, ErasureBranch{Branch: "(every branch)", State: BranchListed, Why: "the branches could not be listed: " + err.Error()})
	}
	seen := map[string]bool{}
	for _, info := range infos {
		seen[info.Name] = true
		if b, ok := kept[info.Name]; ok {
			out = append(out, b)
			continue
		}
		e := ErasureBranch{Branch: info.Name, Parent: branchParentOf(info.Name), Masked: info.Masked != ""}
		if t, ok := branchMadeOf(info.Name); ok {
			e.Made = &t
		}
		switch info.Masked {
		case MaskedMaking:
			e.State, e.Why = BranchListed, "a masked branch being made: it is erased once it is open (plan the request again then)"
			out = append(out, e)
			continue
		case MaskedFailed:
			e.State, e.Why = BranchListed, "a masked branch whose making failed: it is never opened; delete it ("+brand.CLI+" branch delete "+info.Name+")"
			out = append(out, e)
			continue
		}
		if err := wakeForErase(info.Name); err != nil {
			e.State, e.Why = BranchListed, "it could not be started, so it was not searched: "+firstLine(err.Error())
			out = append(out, e)
			continue
		}
		var s ErasureSeed
		if e.Masked {
			s = seed
		}
		plan, fp, _, err := eng.Plan(info.Name, values, events, actor, s, refs)
		if err != nil {
			e.State, e.Why = BranchListed, "it could not be planned: "+firstLine(err.Error())
			out = append(out, e)
			continue
		}
		e.State, e.Plan, e.Fingerprint = BranchPlanned, &plan, fp
		out = append(out, e)
	}
	for _, b := range prior {
		if !seen[b.Branch] && b.State == BranchApplied {
			out = append(out, b)
		}
	}
	return out
}

// resultSeed is the rows an apply changed, by key, for a masked branch.
func resultSeed(r *ErasureResult) ErasureSeed {
	if r == nil {
		return nil
	}
	out := ErasureSeed{}
	for _, t := range r.Tables {
		k := t.Schema + "." + t.Table
		for _, key := range t.Keys {
			out[k] = append(out[k], string(key))
		}
	}
	return out
}

// mainDone is when main's erasure finished in its files: applied and every
// table rewritten. Zero while a rewrite is left.
func mainDone(v ErasureView) time.Time {
	return doneAt(v.Result)
}

func doneAt(r *ErasureResult) time.Time {
	if r == nil || r.RewritesPending() > 0 {
		return time.Time{}
	}
	if r.Statistics != nil {
		return *r.Statistics
	}
	return r.Applied
}

// applyBranches applies the request to each planned branch, or to only the
// one named (a planned or skipped one), saving the request after each.
func applyBranches(s *auth.Store, eng *ErasureEngine, v ErasureView, values []ErasureValue, actor, only string, refs []string) error {
	seed := resultSeed(v.Result)
	save := func() error {
		bj, _ := json.Marshal(v.Branches)
		_, err := s.SaveErasureBranches(v.ID, string(bj))
		return err
	}
	var last error
	for i := range v.Branches {
		e := &v.Branches[i]
		switch {
		case only != "" && e.Branch != only:
			continue
		case only == "" && e.State != BranchPlanned:
			continue
		case only != "" && e.State != BranchPlanned && e.State != BranchSkipped:
			return fmt.Errorf("%w: %s is %s in request %d", ErrErasureState, e.Branch, e.State, v.ID)
		}
		last = applyOneBranch(eng, v, e, values, actor, seed, refs)
		// The Aadhaar log report's places in the Blackbox entries it redacted.
		if e.State == BranchApplied && e.Result != nil && e.Result.Blackbox != nil {
			_, _ = s.DeleteAadhaarLogPlaces("blackbox", e.Branch, e.Result.Blackbox.IDs)
		}
		if err := save(); err != nil {
			return err
		}
	}
	if only != "" {
		return last
	}
	// Branches made since the plan, before main's erasure finished: they hold
	// the person, and no plan of theirs was shown.
	infos, err := erasureBranchNames()
	if err != nil {
		return nil
	}
	known := map[string]bool{}
	for _, b := range v.Branches {
		known[b.Branch] = true
	}
	done := mainDone(v)
	added := false
	for _, info := range infos {
		if known[info.Name] {
			continue
		}
		e := ErasureBranch{Branch: info.Name, Parent: branchParentOf(info.Name), Masked: info.Masked != "", State: BranchSkipped,
			Why: fmt.Sprintf("made since the plan: plan the request again (%s dpdp erase plan %d), then apply it here with --branch %s", brand.CLI, v.ID, info.Name)}
		if t, ok := branchMadeOf(info.Name); ok {
			e.Made = &t
			if !done.IsZero() && t.After(done) && e.Parent == "main" {
				continue // made from main after its erasure: nothing of the person in it
			}
		}
		v.Branches = append(v.Branches, e)
		added = true
	}
	if added {
		return save()
	}
	return nil
}

// applyOneBranch applies the request to one branch and records how it went
// in e. The error is why it was skipped.
func applyOneBranch(eng *ErasureEngine, v ErasureView, e *ErasureBranch, values []ErasureValue, actor string, seed ErasureSeed, refs []string) error {
	skip := func(why string, err error) error {
		e.State, e.Why = BranchSkipped, why
		return err
	}
	if !branchExistsF(e.Branch) {
		e.State, e.Why = BranchGone, "deleted since the plan"
		return nil
	}
	if e.Plan == nil {
		return skip("it has no plan: plan the request again", fmt.Errorf("%w: %s has no plan", ErrErasureState, e.Branch))
	}
	if e.Plan.Blocked {
		return skip("its plan has a problem: "+firstProblem(*e.Plan), fmt.Errorf("%w: %s: %s", ErrErasureBlocked, e.Branch, firstProblem(*e.Plan)))
	}
	if err := wakeForErase(e.Branch); err != nil {
		return skip("it could not be started: "+firstLine(err.Error()), err)
	}
	var s ErasureSeed
	if e.Masked {
		s = seed
	}
	err := withErasingLock(e.Branch, func() error {
		plan, fp, res, err := eng.Apply(e.Branch, ErasureApply{ID: v.ID, UID: v.UID, Values: values, Events: v.Events,
			Fingerprint: e.Fingerprint, Actor: actor, Seed: s, VaultRefs: refs})
		if errors.Is(err, ErrErasurePlanChanged) {
			e.Plan, e.Fingerprint = &plan, fp
			return err
		}
		if err != nil {
			return err
		}
		res = eng.Settle(e.Branch, plan, res, nil)
		e.State, e.Why, e.Result = BranchApplied, "", &res
		return nil
	})
	switch {
	case errors.Is(err, ErrErasurePlanChanged):
		return skip(fmt.Sprintf("its plan changed since it was shown: review it (%s dpdp erase show %d), then apply it with --branch %s",
			brand.CLI, v.ID, e.Branch), err)
	case err != nil:
		return skip("applying it failed, and nothing was changed there: "+firstLine(err.Error()), err)
	}
	return nil
}

// ApplyErasureBranch applies an applied request to one branch it skipped, or
// one planned again since (ReplanErasure).
func ApplyErasureBranch(s *auth.Store, id int64, name string, values []ErasureValue, actor string) (ErasureView, error) {
	eng, v, err := openErasure(s, id, values)
	if err != nil {
		return v, err
	}
	if v.State != auth.ErasureApplied {
		return v, fmt.Errorf("%w: request %d is %s; a branch is applied on its own once main is", ErrErasureState, id, v.State)
	}
	found := false
	for _, b := range v.Branches {
		found = found || b.Branch == name
	}
	if !found {
		return v, fmt.Errorf("%w: %s is not in request %d; plan it again first (%s dpdp erase plan %d)", ErrInvalidRequest, name, id, brand.CLI, id)
	}
	refs, _ := erasureVaultRefs(s, eng, values, actor)
	aerr := applyBranches(s, eng, v, values, actor, name, refs)
	nv, err := GetErasure(s, id)
	if err != nil {
		return nv, err
	}
	return nv, aerr
}

// rewriteBranch is RewriteErasureOn for a branch other than main.
func rewriteBranch(s *auth.Store, id int64, name string, tables []string, actor string) (ErasureView, error) {
	eng, err := erasureEngine()
	if err != nil {
		return ErasureView{}, err
	}
	v, err := GetErasure(s, id)
	if err != nil {
		return v, err
	}
	var e *ErasureBranch
	for i := range v.Branches {
		if v.Branches[i].Branch == name {
			e = &v.Branches[i]
		}
	}
	if e == nil || e.State != BranchApplied || e.Result == nil || e.Plan == nil {
		return v, fmt.Errorf("%w: request %d has not been applied to %s", ErrErasureState, id, name)
	}
	only := tables
	if len(only) == 0 {
		for _, w := range e.Result.Rewrites {
			if w.State != RewriteDone {
				only = append(only, w.Schema+"."+w.Table)
			}
		}
	}
	for _, t := range only {
		if !hasRewrite(*e.Result, t) {
			return v, fmt.Errorf("%w: %s is not a table request %d changed on %s", ErrInvalidRequest, t, id, name)
		}
	}
	if len(only) == 0 {
		return v, nil
	}
	if err := withErasingLock(name, func() error {
		res := eng.Settle(name, *e.Plan, *e.Result, only)
		e.Result = &res
		return nil
	}); err != nil {
		return v, err
	}
	bj, _ := json.Marshal(v.Branches)
	if _, err := s.SaveErasureBranches(id, string(bj)); err != nil {
		return v, err
	}
	return GetErasure(s, id)
}

// madeBefore lists the branches whose files still hold the person: made
// before their parent's erasure finished, or from a parent that does. Only
// for an applied request; a planned one has erased nothing yet.
func madeBefore(s *auth.Store, v ErasureView) []ErasureStale {
	out := []ErasureStale{}
	if v.State != auth.ErasureApplied {
		return out
	}
	infos, err := erasureBranchNames()
	if err != nil {
		return append(out, ErasureStale{Branch: "(every branch)", Why: "the branches could not be listed: " + err.Error()})
	}
	finished := map[string]time.Time{"main": mainDone(v)}
	// A parent whose erasure changed no row never held the person, so its
	// old blocks hold none of them either.
	changed := map[string]bool{"main": v.Result != nil && v.Result.Rows > 0}
	for _, b := range v.Branches {
		if b.State == BranchApplied {
			finished[b.Branch] = doneAt(b.Result)
			changed[b.Branch] = b.Result != nil && b.Result.Rows > 0
		}
	}
	parent := map[string]string{}
	made := map[string]time.Time{}
	for _, info := range infos {
		parent[info.Name] = branchParentOf(info.Name)
		if t, ok := branchMadeOf(info.Name); ok {
			made[info.Name] = t
		}
	}
	owners := map[string]int64{}
	if s != nil {
		owners, _ = s.BranchOwners()
	}
	memo := map[string]string{}
	var why func(name string, depth int) string
	why = func(name string, depth int) string {
		if name == "main" {
			if finished["main"].IsZero() && changed["main"] {
				return "main's rewrite is not finished, so its files still hold the person"
			}
			return ""
		}
		if w, ok := memo[name]; ok {
			return w
		}
		if depth > 32 {
			return ""
		}
		p := parent[name]
		if p == "" {
			p = "main"
		}
		w := ""
		pw := why(p, depth+1)
		t, haveMade := made[name]
		pf := finished[p]
		switch {
		case pw != "":
			w = "made from " + p + ", which still holds the person"
		case !pf.IsZero() && !changed[p]:
			// p was erased and changed nothing: nothing of the person came from it.
		case pf.IsZero() && p == "main" && !changed["main"]:
		case pf.IsZero():
			w = "made from " + p + ", where the erasure has not finished"
		case !haveMade:
			w = "when it was made cannot be read, so it is taken as made before " + p + "'s erasure"
		case t.Before(pf):
			w = fmt.Sprintf("made %s, before %s's erasure finished (%s): the snapshot it was copied from keeps the person's old blocks",
				t.UTC().Format("2006-01-02 15:04"), p, pf.UTC().Format("2006-01-02 15:04"))
		}
		memo[name] = w
		return w
	}
	for _, info := range infos {
		w := why(info.Name, 0)
		if w == "" {
			continue
		}
		e := ErasureStale{Branch: info.Name, Parent: parent[info.Name], Why: w}
		if t, ok := made[info.Name]; ok {
			e.Made = &t
		}
		if uid, ok := owners[info.Name]; ok && s != nil {
			e.Owner = s.EmailOf(uid)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Branch < out[j].Branch })
	return out
}

// OldBranches are the branches older than FOX_BRANCH_MAX_AGE, oldest first;
// none when it is off. Free: it is a warning, never an action (decision 6).
func OldBranches() []BranchAge {
	out := []BranchAge{}
	max := BranchMaxAge()
	if max <= 0 {
		return out
	}
	infos, err := erasureBranchNames()
	if err != nil {
		return out
	}
	now := time.Now()
	for _, info := range infos {
		t, ok := branchMadeOf(info.Name)
		if !ok || now.Sub(t) <= max {
			continue
		}
		a := BranchAge{Branch: info.Name, Made: t, Days: int(now.Sub(t).Hours() / 24)}
		if info.State == "running" {
			if rep, err := PersonalDataFindings(info.Name); err == nil {
				held := false
				for _, f := range rep.Findings {
					held = held || f.State == PIIConfirmed
				}
				a.Personal = &held
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Made.Before(out[j].Made) })
	return out
}

// RemakeErasureBranch remakes a branch the request lists as made before the
// erasure, from its parent, and records it on the request. Its work is
// discarded: an admin's decision, never FoxByte's (section 6).
func RemakeErasureBranch(s *auth.Store, id int64, name, actor string) (ErasureView, error) {
	return doToStale(s, id, name, actor, "remade", func(parent string) error { return resetForErase(name, parent) })
}

// DeleteErasureBranch deletes a branch the request lists as made before the
// erasure, and records it on the request.
func DeleteErasureBranch(s *auth.Store, id int64, name, actor string) (ErasureView, error) {
	return doToStale(s, id, name, actor, "deleted", func(string) error {
		if err := deleteForErase(name); err != nil {
			return err
		}
		if s != nil {
			_ = s.ForgetBranchRequests(name)
		}
		return nil
	})
}

func doToStale(s *auth.Store, id int64, name, actor, what string, do func(parent string) error) (ErasureView, error) {
	v, err := GetErasure(s, id)
	if err != nil {
		return v, err
	}
	var st *ErasureStale
	for i := range v.MadeBefore {
		if v.MadeBefore[i].Branch == name {
			st = &v.MadeBefore[i]
		}
	}
	if st == nil {
		return v, fmt.Errorf("%w: request %d does not list %s as made before the erasure", ErrInvalidRequest, id, name)
	}
	parent := st.Parent
	if parent == "" {
		parent = "main"
	}
	if err := do(parent); err != nil {
		return v, err
	}
	now := time.Now().UTC()
	marked := false
	for i := range v.Branches {
		if v.Branches[i].Branch == name {
			v.Branches[i].Done, v.Branches[i].DoneBy, v.Branches[i].DoneAt = what, actor, &now
			marked = true
		}
	}
	if !marked {
		v.Branches = append(v.Branches, ErasureBranch{Branch: name, Parent: parent, State: BranchListed,
			Why: "made since the plan", Done: what, DoneBy: actor, DoneAt: &now})
	}
	bj, _ := json.Marshal(v.Branches)
	if _, err := s.SaveErasureBranches(id, string(bj)); err != nil {
		return v, err
	}
	return GetErasure(s, id)
}

// BranchesLeft counts the branches not yet erased: planned, skipped or
// listed, not gone.
func (v ErasureView) BranchesLeft() int {
	n := 0
	for _, b := range v.Branches {
		if (b.State == BranchPlanned || b.State == BranchSkipped || b.State == BranchListed) && b.Done == "" {
			n++
		}
	}
	return n
}
