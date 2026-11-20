// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Promoting a branch's schema changes to another branch.
//
// Branching was only half a workflow: you could take a copy of the database, make
// changes on it, and prove what they were — and then there was no way to bring
// them back. "An agent proposes, a human reviews and applies" stopped at the
// proposal, and the diff (DiffLedgers) could only describe the gap.
//
// What is applied is the Blackbox's own record of what happened on the source: the
// statements as they were run, in the order they ran, minus the ones the guardrail
// refused (a blocked change never happened). Nothing is generated from a schema
// comparison, so the target's record ends up holding the same statements the
// source's does, attributed to whoever wrote them, with the approver named beside
// them.
//
// Schema only, unless the person asking says otherwise. The Blackbox records an
// agent's data changes too (INSERT, UPDATE, DELETE, TRUNCATE), and on an
// agent's branch those are usually test rows: replayed on main they would run
// against production rows. So a request leaves them out and lists what it left
// out, and carrying them is a choice made when asking (RequestOptions) and
// shown to whoever approves.

// RequestEntry is one statement in a change request: a Blackbox entry from the
// source, snapshotted when the request was made so a reviewer approves what they
// were shown.
type RequestEntry struct {
	ID         int64  `json:"id"`      // the source's Blackbox entry id
	At         string `json:"at"`      //
	Actor      string `json:"actor"`   // who ran it on the source
	ActorKind  string `json:"kind"`    // human | agent
	CommandTag string `json:"command"` //
	Object     string `json:"object"`  //
	Statement  string `json:"sql"`     //
	Risk       string `json:"risk,omitempty"`
	// SameRun is the entry, earlier in the request, whose statement this one
	// shares: one run of several statements (`CREATE TABLE …; CREATE
	// FUNCTION …`) is one Blackbox entry per change, each holding the whole
	// run's text, and the text runs once, at the first. 0 for an entry whose
	// statement runs on its own.
	SameRun int64 `json:"same_run,omitempty"`
}

// RequestOptions are what the person asking chose.
type RequestOptions struct {
	// IncludeData carries the source's data changes as well as its schema
	// changes. Off by default; a request made with it says so to the approver.
	IncludeData bool
}

// OmittedEntry is a source entry a request left out, and why. The statement is
// not kept: what was left out is for a reviewer to know about, not to apply.
type OmittedEntry struct {
	ID         int64  `json:"id"`
	Actor      string `json:"actor"`
	ActorKind  string `json:"kind"`
	CommandTag string `json:"command"`
	Object     string `json:"object"`
	Reason     string `json:"reason"`
}

// OmittedListed is how many left-out entries a request lists by name. An
// agent's branch can hold thousands of data changes; the count is always
// exact, and the list stops here so the request stays readable.
const OmittedListed = 200

// RequestPlan is what BuildRequest worked out: the entries to apply, where the
// branches part, and what was left out.
type RequestPlan struct {
	Entries      []RequestEntry
	ForkAfterID  int64
	IncludeData  bool
	Omitted      []OmittedEntry // at most OmittedListed of them
	OmittedCount int
}

// RequestKey names the set of source entries a request holds, whatever order
// they are in, so a second open request for exactly the same changes can be
// recognised (auth.OpenChangeRequest).
func RequestKey(entries []RequestEntry) string {
	ids := make([]int64, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
	}
	slices.Sort(ids)
	var b strings.Builder
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatInt(id, 10))
	}
	return b.String()
}

// NewRequest is the store's record of a plan.
func NewRequest(source, target string, p RequestPlan) (auth.NewChangeRequest, error) {
	snapshot, err := MarshalEntries(p.Entries)
	if err != nil {
		return auth.NewChangeRequest{}, err
	}
	omitted := ""
	if len(p.Omitted) > 0 {
		b, err := json.Marshal(p.Omitted)
		if err != nil {
			return auth.NewChangeRequest{}, err
		}
		omitted = string(b)
	}
	return auth.NewChangeRequest{Source: source, Target: target, ForkAfterID: p.ForkAfterID, Entries: snapshot,
		EntryKey: RequestKey(p.Entries), IncludeData: p.IncludeData, Omitted: omitted, OmittedCount: p.OmittedCount}, nil
}

// RequestedDetail is the security log's line about a new request: how much it
// carries, and whether data goes with it.
func RequestedDetail(p RequestPlan) string {
	s := fmt.Sprintf("%d statement(s)", len(p.Entries))
	switch {
	case p.IncludeData:
		s += ", including data changes"
	case p.OmittedCount > 0:
		s += fmt.Sprintf(", %d data change(s) left out", p.OmittedCount)
	}
	return s
}

// UnmarshalOmitted reads what a stored request left out.
func UnmarshalOmitted(s string) ([]OmittedEntry, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []OmittedEntry
	err := json.Unmarshal([]byte(s), &out)
	return out, err
}

// ReplayOnce marks each entry whose statement already runs with an earlier
// one: the same text, recorded in the same transaction on the source (xids,
// by entry id, from bb.ledger_ext). An entry without a recorded transaction is
// never merged, so a branch without the capture table replays as before.
func ReplayOnce(entries []RequestEntry, xids map[int64]int64) {
	first := map[string]int64{}
	for i := range entries {
		e := &entries[i]
		x, ok := xids[e.ID]
		if !ok || x == 0 {
			continue
		}
		k := fmt.Sprintf("%d|%s", x, strings.TrimSpace(e.Statement))
		if f, ok := first[k]; ok {
			e.SameRun = f
		} else {
			first[k] = e.ID
		}
	}
}

// ErrNothingToPromote is returned when the source holds no applicable change.
var ErrNothingToPromote = errors.New("nothing to promote")

// ErrConflict is returned when both branches changed the same object since they
// split. Two people editing the same table is the one case where replaying the
// source's statements is likely to mean something nobody asked for, so it is
// refused rather than guessed at.
var ErrConflict = errors.New("both branches changed the same object since they split")

// ErrBlockedByPolicy is returned when the policy gate would refuse a statement in
// the request. The whole request is refused: applying the rest would leave the
// target in a state that is neither the old schema nor the source's.
var ErrBlockedByPolicy = errors.New("the policy gate blocks a statement in this request")

// ErrNotReplayable is returned when a statement in the request carries
// transaction control or changes who the rest runs or is recorded as: an entry
// holds its author's whole message, and such a statement in it would break the
// one unprivileged transaction a request is applied in. Refused when the request
// is made and again when it is applied.
var ErrNotReplayable = errors.New("a statement in this request cannot be replayed safely")

// ErrAlreadyApplied is returned when the target's own record
// (bb.applied_requests) already holds the request: it was applied once, and
// applying it again would run every statement twice. The count ApplyRequest
// returns with it is the one the target recorded, so the caller can note the
// outcome its store missed.
var ErrAlreadyApplied = errors.New("the target's record shows this change request was already applied")

// MarshalEntries is the snapshot stored with a request.
func MarshalEntries(entries []RequestEntry) (string, error) {
	b, err := json.Marshal(entries)
	return string(b), err
}

// UnmarshalEntries reads a stored snapshot.
func UnmarshalEntries(s string) ([]RequestEntry, error) {
	var out []RequestEntry
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	err := json.Unmarshal([]byte(s), &out)
	return out, err
}

// FormatRequest renders a request for a person about to decide on it.
func FormatRequest(c auth.ChangeRequest, entries []RequestEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Change request #%d: %s → %s\n", c.ID, c.Source, c.Target)
	fmt.Fprintf(&b, "  asked by %s at %s (%s)\n", c.CreatedBy, c.Created, c.Status)
	if c.DecidedBy != "" {
		fmt.Fprintf(&b, "  decided by %s at %s\n", c.DecidedBy, c.Decided)
	}
	if c.Note != "" {
		fmt.Fprintf(&b, "  note: %s\n", c.Note)
	}
	if c.ForkAfterID > 0 {
		fmt.Fprintf(&b, "  the branches share history up to entry %d\n", c.ForkAfterID)
	}
	// Whether data goes too is the first thing an approver must not miss.
	if c.IncludeData {
		fmt.Fprintf(&b, "\n  INCLUDES DATA CHANGES: the asker chose to carry %s's INSERT, UPDATE, DELETE and similar\n"+
			"  statements as well, and approving runs them against %s's rows.\n", c.Source, c.Target)
	} else {
		b.WriteString("  schema changes only\n")
	}
	if c.OmittedCount > 0 {
		fmt.Fprintf(&b, "\n%d data change(s) on %s were left out and will not be applied:\n", c.OmittedCount, c.Source)
		omitted, _ := UnmarshalOmitted(c.Omitted)
		for _, o := range omitted {
			actor := o.Actor
			if o.ActorKind == "agent" {
				actor += " (agent)"
			}
			fmt.Fprintf(&b, "  entry %d: %s %s, by %s\n", o.ID, o.CommandTag, o.Object, actor)
		}
		if more := c.OmittedCount - len(omitted); more > 0 {
			fmt.Fprintf(&b, "  … and %d more\n", more)
		}
		fmt.Fprintf(&b, "  To carry them too, ask again with data changes included (`%s branch request %s --include-data`).\n",
			brand.CLI, c.Source)
	}
	fmt.Fprintf(&b, "\n%d statement(s), in the order they ran on %s:\n\n", len(entries), c.Source)
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ENTRY\tACTOR\tCHANGE\tRISK")
	for _, e := range entries {
		actor := e.Actor
		if actor == "" {
			actor = "—"
		}
		if e.ActorKind == "agent" {
			actor += " (agent)"
		}
		fmt.Fprintf(w, "%d\t%s\t%s %s\t%s\n", e.ID, actor, e.CommandTag, e.Object, e.Risk)
	}
	_ = w.Flush()
	b.WriteString("\n")
	for _, e := range entries {
		if e.SameRun != 0 {
			fmt.Fprintf(&b, "-- entry %d, by %s: made by the same run as entry %d, above\n\n", e.ID, e.Actor, e.SameRun)
			continue
		}
		fmt.Fprintf(&b, "-- entry %d, by %s\n%s\n\n", e.ID, e.Actor, strings.TrimSpace(e.Statement))
	}
	return b.String()
}

// quoteIdent renders s as a quoted SQL identifier. A role named for an email
// address has to be quoted, and a quote inside one has to be doubled.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// riskyEntries names the entries a reviewer should look at hardest: the ones the
// gate flagged rather than blocked.
func riskyEntries(entries []RequestEntry) []string {
	var out []string
	for _, e := range entries {
		if e.Risk != "" {
			out = append(out, fmt.Sprintf("entry %d (%s %s): %s", e.ID, e.CommandTag, e.Object, e.Risk))
		}
	}
	return out
}

// RequestSummary is one line about a request, for listings.
func RequestSummary(c auth.ChangeRequest) string {
	entries, _ := UnmarshalEntries(c.Entries)
	risky := ""
	if r := riskyEntries(entries); len(r) > 0 {
		risky = fmt.Sprintf(", %d flagged", len(r))
	}
	applied := ""
	if c.Applied > 0 {
		applied = fmt.Sprintf(", %d applied", c.Applied)
	}
	data := ""
	switch {
	case c.IncludeData:
		data = ", INCLUDES DATA"
	case c.OmittedCount > 0:
		data = fmt.Sprintf(", %d data change(s) left out", c.OmittedCount)
	}
	return fmt.Sprintf("#%-4d %-9s %s → %s  %d statement(s)%s%s%s  asked by %s",
		c.ID, c.Status, c.Source, c.Target, len(entries), risky, data, applied, c.CreatedBy)
}

// RequestHistory is this source's requests to this target that were, or may
// have been, applied: the approved ones and the failed ones. It is what
// BuildRequest and ApplyRequest are given.
//
// A request whose outcome this store never learned (the changes committed and
// noting so failed, or the commit's answer was lost) reads here as applying
// nothing, and its entries would be offered again in the next request and run
// twice. The target keeps its own record, written in the same transaction as
// the changes (bb.applied_requests), so such a request is looked up there and,
// when the target has it, recorded as applied here: reconciled, not re-applied.
func RequestHistory(s *auth.Store, source, target string) ([]auth.ChangeRequest, error) {
	list, err := s.RequestsFrom(source, target, auth.RequestApproved, auth.RequestFailed)
	if err != nil {
		return nil, err
	}
	unsure := false
	for _, c := range list {
		unsure = unsure || c.Applied == 0
	}
	if !unsure {
		return list, nil
	}
	recorded, err := appliedRequestsOf(target)
	if err != nil {
		// Not knowing is not the same as "not applied": refuse rather than
		// offer statements the target may already have.
		return nil, fmt.Errorf("reading which change requests %q already has: %w", target, err)
	}
	for i := range list {
		n, ok := recorded[AppliedKeyOf(list[i])]
		if !ok || list[i].Applied != 0 {
			continue
		}
		if err := s.ReconcileChangeRequest(list[i].ID, n); err != nil {
			return nil, err
		}
		list[i].Status, list[i].Applied = auth.RequestApproved, n
	}
	return list, nil
}

// Reconcile records a request's outcome from its target's own record, when the
// target has one. It reports whether it did. A caller that could not note an
// apply's outcome, or was told the request was already applied, uses it.
func Reconcile(s *auth.Store, c auth.ChangeRequest) (bool, error) {
	recorded, err := appliedRequestsOf(c.Target)
	if err != nil {
		return false, err
	}
	n, ok := recorded[AppliedKeyOf(c)]
	if !ok {
		return false, nil
	}
	return true, s.ReconcileChangeRequest(c.ID, n)
}

// appliedRequestsOf is AppliedRequests, a variable so tests can stand in for
// the target's record without a database.
var appliedRequestsOf = AppliedRequests

// AppliedKey is how a target knows a change request: its id and its store's
// name for it (auth.ChangeRequest.UID, "" for one made before requests had
// one). The id alone repeats once a store is recreated or restored from an
// older backup, and a new request must not be taken for an old one applied.
type AppliedKey struct {
	ID  int64
	UID string
}

// AppliedKeyOf is the key the target records c under.
func AppliedKeyOf(c auth.ChangeRequest) AppliedKey { return AppliedKey{c.ID, c.UID} }

// AppliedRequests reads a branch's record of the change requests applied to it
// (bb.applied_requests): each request to the number of statements. A branch
// whose Blackbox predates the table has applied none that it recorded; one
// whose table predates the name column recorded every request without one.
func AppliedRequests(name string) (map[AppliedKey]int, error) {
	has, err := ledgerLines(name, "SELECT (to_regclass('bb.applied_requests') IS NOT NULL)::text || ' ' || "+
		"EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('bb.applied_requests') "+
		"AND attname = 'request_uid' AND NOT attisdropped)::text")
	if err != nil {
		return nil, err
	}
	out := map[AppliedKey]int{}
	if len(has) == 0 || !strings.HasPrefix(has[0], "true") {
		return out, nil
	}
	uid := "''"
	if has[0] == "true true" {
		uid = "coalesce(request_uid, '')"
	}
	lines, err := ledgerLines(name, "SELECT request_id || ' ' || statements || ' ' || "+uid+" FROM bb.applied_requests")
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if k, n, ok := parseAppliedLine(l); ok {
			out[k] = n
		}
	}
	return out, nil
}

// parseAppliedLine reads "id statements [uid]", the uid absent for a request
// recorded without a name.
func parseAppliedLine(l string) (AppliedKey, int, bool) {
	f := strings.Fields(l)
	if len(f) < 2 || len(f) > 3 {
		return AppliedKey{}, 0, false
	}
	var k AppliedKey
	var n int
	if _, err := fmt.Sscan(f[0]+" "+f[1], &k.ID, &n); err != nil {
		return AppliedKey{}, 0, false
	}
	if len(f) == 3 {
		k.UID = f[2]
	}
	return k, n, true
}

// ApplyClaimed applies a request that has just been claimed as approved, and
// records the outcome in the store. It is the one way the CLI and the API
// apply a request, so both handle the two awkward outcomes the same way:
//
//   - The target's record already holds the request (ErrAlreadyApplied): it
//     was applied before, say by a node whose store this one has not caught
//     up with. Nothing runs again, and the store is reconciled with the
//     target's count instead.
//   - The apply committed and noting so here failed (recordErr): the changes
//     are in. The next request from this source reads the target's record
//     (RequestHistory) and reconciles, so its entries are not offered again.
func ApplyClaimed(s *auth.Store, c auth.ChangeRequest, approver string) (n int, applyErr, recordErr error) {
	entries, err := UnmarshalEntries(c.Entries)
	if err != nil {
		return 0, err, s.FinishChangeRequest(c.ID, 0, err.Error())
	}
	history, err := RequestHistory(s, c.Source, c.Target)
	if err != nil {
		err = fmt.Errorf("applying the request to %q (nothing was committed): %w", c.Target, err)
		return 0, err, s.FinishChangeRequest(c.ID, 0, err.Error())
	}
	n, applyErr = applyNow(ApplyPlan{Request: c, Entries: entries, Approver: approver, History: history})
	if errors.Is(applyErr, ErrAlreadyApplied) {
		return n, applyErr, s.ReconcileChangeRequest(c.ID, n)
	}
	failure := ""
	if applyErr != nil {
		failure = applyErr.Error()
	}
	return n, applyErr, s.FinishChangeRequest(c.ID, n, failure)
}

// applyNow is ApplyRequest, a variable so tests can check ApplyClaimed's
// bookkeeping without a running target.
var applyNow = ApplyRequest

// ApplyPlan is an approved request, ready to apply.
type ApplyPlan struct {
	// Request is the record as claimed: its id, source, target and fork point.
	Request auth.ChangeRequest
	// Entries is the request's snapshot, decoded.
	Entries []RequestEntry
	// Approver is who approved it, as the target's Blackbox will name them.
	Approver string
	// History is RequestHistory(source, target): the target sessions this
	// source's earlier requests ran under are its own changes, not the
	// target's, when conflicts are checked again at apply time.
	History []auth.ChangeRequest
}

// The paid half, supplied by enterprise/promote in an Enterprise build and nil
// in a Standard one.
//
// What stays here is what a request still needs after an install changes
// edition: the entry type, its encoding, and the rendering. Listing, showing
// and rejecting a request are free — a request left open must be closeable
// rather than stranded — and all three need this code.
var (
	buildRequest func(source, target string, history []auth.ChangeRequest, opts RequestOptions) (RequestPlan, error)
	applyRequest func(p ApplyPlan) (int, error)
)

// SetPromotion installs them. Called from enterprise/promote's init, and from
// nowhere else.
func SetPromotion(
	build func(source, target string, history []auth.ChangeRequest, opts RequestOptions) (RequestPlan, error),
	apply func(p ApplyPlan) (int, error),
) {
	buildRequest, applyRequest = build, apply
}

// BuildRequest works out what source holds that target does not.
func BuildRequest(source, target string, history []auth.ChangeRequest, opts RequestOptions) (RequestPlan, error) {
	if err := requireFeature(edition.Promotion); err != nil {
		return RequestPlan{}, err
	}
	if buildRequest == nil {
		return RequestPlan{}, ErrPromotionNotLicensed
	}
	return buildRequest(source, target, history, opts)
}

// ApplyRequest applies an approved request to its target. With
// ErrAlreadyApplied it returns the count the target recorded the first time.
func ApplyRequest(p ApplyPlan) (int, error) {
	// Applying is the paid half. Reading requests stays free, so one left
	// pending when an install changed edition is still visible and can still
	// be rejected rather than stranded.
	if err := requireFeature(edition.Promotion); err != nil {
		return 0, err
	}
	if applyRequest == nil {
		return 0, ErrPromotionNotLicensed
	}
	// A source branch's audit marks (F6) are GRANTs to the audit roles, in its
	// Blackbox like any schema change, and the target may never have had
	// those roles: a mark on the source must not make its changes
	// unappliable. Made here, as marking makes them, before the replay.
	ensureAuditRolesBestEffort(p.Request.Target)
	return applyRequest(p)
}
