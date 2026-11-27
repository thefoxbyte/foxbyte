// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Restores and erasure requests (F4, Gate 1 step 4; design, section 12;
// decision 4). A copy of a branch from before an erasure was applied there
// holds the person again. Each door that makes such a copy asks guardRestore
// first:
//
//   - `fox restore --to` and `fox ledger revert --to` (the restore copy);
//   - `fox blackbox branch-before <entry>` (CLI, API; MCP is refused outright,
//     as erasure is a person's decision, not an agent's);
//   - `fox backup restore` of an export tar;
//   - `fox pg upgrade --rollback`, to the datasets an upgrade kept.
//
// The copy is refused, saying which requests it would undo, unless an admin
// gives `--after-erasure reapply --reason "…"`. Then the decision is recorded
// on each request and in the security log, and the copy stays closed until
// each request is applied to it again by the row keys it kept (no value is
// asked: none is kept), its Blackbox entries redacted by the ids it kept, and
// its tables rewritten. The guard is in every edition; re-applying runs the
// Enterprise erasure engine, and without it the restore is refused, saying
// why (decided 27 Nov 2026). A copy of a branch the request has no record of
// is applied main's row keys, and the request says so (decided 27 Nov).
//
// The weekly restore check is exempt (section 12): it reads one probe row,
// and is removed; nobody connects to it.

// AfterErasure is an admin's decision at a restore door.
type AfterErasure struct {
	Reapply bool   // --after-erasure reapply
	Reason  string // --reason, recorded on each request
	Actor   string // who decided
}

// ErrErasureRestore is a restore refused because it would undo an erasure.
var ErrErasureRestore = errors.New("it would undo an erasure")

// ParseAfterErasure reads `--after-erasure reapply` and `--reason "…"`.
// Only reapply is a decision: the person never comes back by a restore.
func ParseAfterErasure(value, reason, actor string) (AfterErasure, error) {
	switch value {
	case "":
		return AfterErasure{Reason: reason, Actor: actor}, nil
	case "reapply":
		return AfterErasure{Reapply: true, Reason: strings.TrimSpace(reason), Actor: actor}, nil
	}
	return AfterErasure{}, fmt.Errorf("%w: --after-erasure takes reapply, not %q: an erased person never comes back by a restore", ErrInvalidRequest, value)
}

// restoreStore opens the install's store, for a door with none at hand.
var restoreStore = func() (*auth.Store, error) { return auth.OpenFromEnv() }

// undone is one request a copy would undo, with the record the re-apply
// follows: the source branch's own plan and result, or main's.
type undone struct {
	view   ErasureView
	plan   ErasurePlan
	result ErasureResult
	keys   string    // whose row keys: the source branch, or main
	since  time.Time // when the erasure was applied there
}

// undoneBy picks the requests a copy of source from at would bring back. A
// request applying now is returned with a zero result: it cannot be
// re-applied until it is done. at zero is "not known", which is before all.
func undoneBy(views []ErasureView, source string, at time.Time) []undone {
	var out []undone
	for _, v := range views {
		switch v.State {
		case auth.ErasureApplying:
			out = append(out, undone{view: v, keys: v.Branch, since: v.Claimed})
			continue
		case auth.ErasureApplied:
		default:
			continue
		}
		if v.Result == nil {
			continue
		}
		u := undone{view: v, plan: v.Plan, result: *v.Result, keys: v.Branch, since: v.Result.Applied}
		if source != v.Branch {
			for _, b := range v.Branches {
				if b.Branch == source && b.State == BranchApplied && b.Plan != nil && b.Result != nil {
					u.plan, u.result, u.keys, u.since = *b.Plan, *b.Result, source, b.Result.Applied
				}
			}
		}
		// A request that changed nothing there has nothing to apply again:
		// the copy holds nobody it erased.
		if len(u.result.Tables) == 0 && (u.result.Blackbox == nil || len(u.result.Blackbox.IDs)+len(u.result.Blackbox.OriginalIDs) == 0) {
			continue
		}
		if at.IsZero() || at.Before(u.since) {
			out = append(out, u)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].since.Before(out[j].since) })
	return out
}

// restoreGuard is a door's check, and then its re-apply.
type restoreGuard struct {
	s       *auth.Store
	ownS    bool
	door    string
	source  string
	point   string
	after   AfterErasure
	hits    []undone
	records []int64 // one per hit, once opened
	target  string
	closes  bool // the target is a branch, closed until done
}

// guardRestore asks whether a copy of source from at (named point, for the
// record) would undo a request, and if so whether the admin decided to go
// ahead. nil, nil: nothing is undone, the door goes on as it always did.
func guardRestore(door, source string, at time.Time, point string, after AfterErasure) (*restoreGuard, error) {
	s, err := restoreStore()
	if err != nil {
		return nil, fmt.Errorf("reading the erasure requests before the restore: %w", err)
	}
	g, err := guardRestoreWith(s, door, source, at, point, after)
	if g == nil {
		s.Close()
	} else {
		g.ownS = true
	}
	return g, err
}

func guardRestoreWith(s *auth.Store, door, source string, at time.Time, point string, after AfterErasure) (*restoreGuard, error) {
	views, err := ListErasures(s)
	if err != nil {
		return nil, fmt.Errorf("reading the erasure requests before the restore: %w", err)
	}
	hits := undoneBy(views, source, at)
	if len(hits) == 0 {
		return nil, nil
	}
	ids := make([]string, len(hits))
	for i, h := range hits {
		ids[i] = fmt.Sprintf("#%d (applied %s)", h.view.ID, h.since.Local().Format("2006-01-02 15:04"))
		if h.view.State == auth.ErasureApplying {
			return nil, fmt.Errorf("%w: erasure request #%d is being applied now; restore once it is done, so it can be applied again to the copy",
				ErrErasureRestore, h.view.ID)
		}
	}
	what := fmt.Sprintf("a copy of %s from %s would bring back the person of erasure request %s", source, point, strings.Join(ids, ", "))
	if !after.Reapply {
		return nil, fmt.Errorf("%w: %s. Nothing was restored. An admin may go ahead with --after-erasure reapply --reason \"…\": "+
			"the erasure is applied to the copy again, by the rows it changed, before the copy opens (or restore to a time after it)",
			ErrErasureRestore, what)
	}
	if after.Reason == "" {
		return nil, fmt.Errorf("%w: %s; say why with --reason \"…\", recorded on each request", ErrInvalidRequest, what)
	}
	if after.Actor == "" {
		return nil, fmt.Errorf("%w: %s, and no one is named to decide it", ErrInvalidRequest, what)
	}
	if _, err := erasureEngine(); err != nil {
		return nil, fmt.Errorf("%w: %s, and applying it again to the copy needs FoxByte Enterprise (%v). Nothing was restored; a restore to a time after the erasure needs nothing",
			ErrErasureRestore, what, err)
	}
	return &restoreGuard{s: s, door: door, source: source, point: point, after: after, hits: hits}, nil
}

// requests are the hits' numbers, for messages.
func (g *restoreGuard) requests() string {
	ids := make([]string, len(g.hits))
	for i, h := range g.hits {
		ids[i] = fmt.Sprintf("#%d", h.view.ID)
	}
	return strings.Join(ids, ", ")
}

// open records the decision on each request and in the security log, and,
// for a branch, closes it until the re-apply is done. Before the copy is made.
func (g *restoreGuard) open(target string, closes bool) error {
	g.target, g.closes = target, closes
	if closes {
		if err := markReapplying(target, g.door, g.hitIDs()); err != nil {
			return fmt.Errorf("closing %s until the erasure is applied again: %w", target, err)
		}
	}
	for _, h := range g.hits {
		id, err := g.s.AddErasureRestore(auth.ErasureRestore{RequestID: h.view.ID, Door: g.door, Source: g.source, Target: target,
			Point: g.point, By: g.after.Actor, Reason: g.after.Reason})
		if err != nil {
			return fmt.Errorf("recording the restore on erasure request #%d: %w", h.view.ID, err)
		}
		g.records = append(g.records, id)
	}
	g.s.Audit(auth.EvErasureRestore, g.after.Actor, target, "",
		fmt.Sprintf("%s of %s from %s past erasure request(s) %s; applied again before it opens", g.door, g.source, g.point, g.requests()))
	return nil
}

func (g *restoreGuard) hitIDs() []int64 {
	out := make([]int64, len(g.hits))
	for i, h := range g.hits {
		out[i] = h.view.ID
	}
	return out
}

// ReapplyDone is what applying a request again to a copy did.
type ReapplyDone struct {
	Request  int64         `json:"request"`
	Keys     string        `json:"keys"` // whose row keys: the source branch, or main
	Result   ErasureResult `json:"result"`
	Blackbox bool          `json:"blackbox"` // its Blackbox entries redacted by id
	Notes    []string      `json:"notes"`
}

// reapply applies each request again to the target, oldest first, then opens
// it. A failure keeps a branch closed and says so; the caller removes a
// restore copy.
func (g *restoreGuard) reapply() ([]ReapplyDone, error) {
	eng, err := erasureEngine()
	if err != nil {
		return nil, g.fail(0, err)
	}
	var out []ReapplyDone
	for i, h := range g.hits {
		d := ReapplyDone{Request: h.view.ID, Keys: h.keys, Notes: []string{}}
		a := ErasureReapply{ID: h.view.ID, UID: h.view.UID, Actor: fmt.Sprintf("erasure request #%d, applied again after a restore", h.view.ID),
			Plan: h.plan, Done: h.result.Tables}
		if h.keys == g.source {
			// The copy is of the very branch the request redacted: the same
			// entries, by the same ids.
			if h.result.Blackbox != nil {
				a.Redact, a.Originals = h.result.Blackbox.IDs, h.result.Blackbox.OriginalIDs
			}
			d.Blackbox = true
		} else {
			d.Notes = append(d.Notes, fmt.Sprintf("The request has no record of %s, so main's rows were applied by their keys; its Blackbox was not redacted, "+
				"its entries not being main's.", g.source))
		}
		res, err := eng.Reapply(g.target, a)
		if err != nil {
			return out, g.fail(i, err)
		}
		var all []string
		for _, w := range res.Rewrites {
			all = append(all, w.Schema+"."+w.Table)
		}
		if len(all) > 0 {
			res = eng.Settle(g.target, a.Plan, res, all)
		}
		d.Result = res
		dj, _ := json.Marshal(d)
		_ = g.s.FinishErasureRestore(g.records[i], auth.RestoreDone, string(dj), "")
		out = append(out, d)
	}
	if g.closes {
		if err := unmarkReapplying(g.target); err != nil {
			return out, fmt.Errorf("the erasure was applied again to %s, but opening it failed: %w", g.target, err)
		}
	}
	return out, nil
}

// fail records the re-apply's failure from hit i on, and keeps a branch
// closed, saying why.
func (g *restoreGuard) fail(from int, err error) error {
	for i := from; i < len(g.records); i++ {
		_ = g.s.FinishErasureRestore(g.records[i], auth.RestoreFailed, "", firstLine(err.Error()))
	}
	if g.closes {
		_ = failReapplying(g.target, firstLine(err.Error()))
		return fmt.Errorf("applying erasure request(s) %s again to %s failed, so it stays closed: %w. `%s branch delete %s` removes it",
			g.requests(), g.target, err, brand.CLI, g.target)
	}
	return fmt.Errorf("applying erasure request(s) %s again to %s failed: %w", g.requests(), g.target, err)
}

// abandon records that the copy was never made: the door failed before it.
func (g *restoreGuard) abandon(err error) {
	for _, id := range g.records {
		_ = g.s.FinishErasureRestore(id, auth.RestoreFailed, "", "the restore failed before the copy was made: "+firstLine(err.Error()))
	}
	if g.closes {
		_ = unmarkReapplying(g.target)
	}
}

func (g *restoreGuard) close() {
	if g != nil && g.ownS {
		g.s.Close()
	}
}

// --- branches closed until the erasure is applied again ----------------------

// ReapplyingBranch is a branch restored past an erasure, closed until each
// request is applied to it again; State is reapplying, or failed with Error.
type ReapplyingBranch struct {
	Branch   string    `json:"branch"`
	Door     string    `json:"door"`
	Requests []int64   `json:"requests"`
	Since    time.Time `json:"since"`
	State    string    `json:"state"`
	Error    string    `json:"error,omitempty"`
}

var reapplyingPath = func() string { return brand.StatePath("erasure-reapplying.json") }

var reapplyingMu sync.Mutex

func loadReapplying() map[string]ReapplyingBranch {
	out := map[string]ReapplyingBranch{}
	b, err := os.ReadFile(reapplyingPath())
	if err != nil {
		return out
	}
	var list []ReapplyingBranch
	if json.Unmarshal(b, &list) == nil {
		for _, r := range list {
			out[r.Branch] = r
		}
	}
	return out
}

func saveReapplying(m map[string]ReapplyingBranch) error {
	list := make([]ReapplyingBranch, 0, len(m))
	for _, r := range m {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Branch < list[j].Branch })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := reapplyingPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, reapplyingPath())
}

func editReapplying(fn func(m map[string]ReapplyingBranch)) error {
	reapplyingMu.Lock()
	defer reapplyingMu.Unlock()
	m := loadReapplying()
	fn(m)
	return saveReapplying(m)
}

func markReapplying(name, door string, requests []int64) error {
	return editReapplying(func(m map[string]ReapplyingBranch) {
		m[name] = ReapplyingBranch{Branch: name, Door: door, Requests: requests, Since: time.Now().UTC(), State: auth.RestoreReapplying}
	})
}

func failReapplying(name, why string) error {
	return editReapplying(func(m map[string]ReapplyingBranch) {
		r := m[name]
		r.Branch, r.State, r.Error = name, auth.RestoreFailed, why
		m[name] = r
	})
}

func unmarkReapplying(name string) error {
	return editReapplying(func(m map[string]ReapplyingBranch) { delete(m, name) })
}

// ReapplyingBranches lists the branches closed until an erasure is applied
// to them again. Free.
func ReapplyingBranches() []ReapplyingBranch {
	reapplyingMu.Lock()
	defer reapplyingMu.Unlock()
	m := loadReapplying()
	out := make([]ReapplyingBranch, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Branch < out[j].Branch })
	return out
}

// reapplyingNow reports whether a branch is having an erasure applied to it
// again: the idle reaper leaves it running meanwhile.
func reapplyingNow(name string) bool {
	reapplyingMu.Lock()
	defer reapplyingMu.Unlock()
	r, ok := loadReapplying()[name]
	return ok && r.State == auth.RestoreReapplying
}

// checkReapplied refuses a branch closed until an erasure is applied to it
// again, saying why: checkBranchOpen asks it on every way in.
func checkReapplied(name string) error {
	reapplyingMu.Lock()
	r, ok := loadReapplying()[name]
	reapplyingMu.Unlock()
	if !ok {
		return nil
	}
	reqs := make([]string, len(r.Requests))
	for i, id := range r.Requests {
		reqs[i] = fmt.Sprintf("#%d", id)
	}
	if r.State == auth.RestoreFailed {
		return fmt.Errorf("%w: branch %q was restored past erasure request(s) %s, and applying them again failed (%s), so it stays closed: %s branch delete %s removes it",
			ErrBranchClosed, name, strings.Join(reqs, ", "), r.Error, brand.CLI, name)
	}
	return fmt.Errorf("%w: branch %q was restored past erasure request(s) %s, and opens once they are applied to it again",
		ErrBranchClosed, name, strings.Join(reqs, ", "))
}
