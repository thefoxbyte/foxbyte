// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Erasure requests (point 11.2, F4; docs/FOX_F4_Erasure_Design.md). One
// request, for one person: their rows found from the values given and the
// columns a reviewer confirmed, a plan shown table by table with counts, then
// applied on main in one transaction, vacuumed, and rewritten in the files.
// Gate 1 step 1 is main; every branch, the statement text, restores and the
// evidence are the steps after it.
//
// A request keeps no value (decision 9): each value's category and its last
// four characters, so the requester can tell their requests apart, and,
// once applied, the row keys of what was changed. Applying therefore asks for
// the values again: they are checked against what was kept, the rows are
// found again inside the transaction that changes them, and nothing is
// applied if the plan has changed since it was shown.
//
// Making, planning, applying and rewriting are Enterprise (edition.DPDP);
// enterprise/dpdp supplies them. Reading a request and what it did is free,
// so an install whose licence lapses can still show what was done.

// ErasureValue is one value the person is known by, given for a run and
// never kept. Category is "" to recognise it from its shape.
type ErasureValue struct {
	Category string `json:"category"`
	Value    string `json:"value"`
}

// ErasureRef is what a request keeps of a value: the categories it was read
// as, and its last four characters.
type ErasureRef struct {
	Categories []string `json:"categories"`
	Last4      string   `json:"last4"`
}

func (r ErasureRef) String() string {
	return strings.Join(r.Categories, "/") + " ending " + r.Last4
}

// ErasureColumn is one column a plan clears, and what it is cleared to.
type ErasureColumn struct {
	Column     string   `json:"column"`
	Path       string   `json:"path,omitempty"` // a JSON path inside it; "" for the whole column
	Categories []string `json:"categories"`
	To         string   `json:"to"` // NULL, DEFAULT, a placeholder in quotes, or "null at the path"
}

// ErasureException is a place a law requires to be kept (section 13): not
// erased, and recorded with its citation and when the period ends.
type ErasureException struct {
	Column   string     `json:"column"` // "" for the whole table
	Citation string     `json:"citation"`
	Keep     DPDPKeep   `json:"keep"`
	Ends     *time.Time `json:"ends,omitempty"` // when the event's date was given
	Text     string     `json:"text"`
	// Categories are what the place kept holds: an Aadhaar number a law keeps
	// keeps its vault record too (section 8).
	Categories []string `json:"categories,omitempty"`
}

// The things a plan may do to a table's rows.
const (
	ErasureActClear    = "clear"     // the person's personal columns cleared; the row stays
	ErasureActDelete   = "delete"    // the row deleted
	ErasureActCascade  = "cascade"   // deleted by its foreign key, with a row the plan deletes
	ErasureActSetNull  = "set-null"  // its reference cleared by its foreign key, with a row the plan deletes
	ErasureActKeep     = "keep"      // it refers to the person's rows and holds no personal data: left as it is
	ErasureActKeptLaw  = "kept"      // a law requires it kept (an exception)
	ErasureActReferral = "refers-to" // another row of the same table refers to the person's: someone else's
)

// ErasureTable is what a plan does in one table.
type ErasureTable struct {
	Schema string `json:"schema"`
	Table  string `json:"table"`
	// Why the rows are the person's: "holds the value in email" for a
	// match, or "refers to public.customers (orders_customer_id_fkey)".
	Why    string `json:"why"`
	Depth  int    `json:"depth"` // 0 for a match; 1, 2… along foreign keys
	Rows   int    `json:"rows"`
	Action string `json:"action"`
	// Columns are what a clear sets; empty for any other action.
	Columns []ErasureColumn `json:"columns"`
	// Entry is the table's inventory entry as it stood when the plan was
	// made; nil when it has none, and Default says the action is the
	// default rather than a decision.
	Entry      *DPDPEntry         `json:"entry"`
	Default    bool               `json:"default"`
	Exceptions []ErasureException `json:"exceptions"`
	// Problems stop the plan: nothing is applied while any table has one.
	Problems []string `json:"problems"`
	Notes    []string `json:"notes"`
	Keyed    bool     `json:"keyed"` // a primary key or replica identity names its rows
	Size     int64    `json:"size"`  // bytes, with its indexes and TOAST
	// Rewrite is when the table's files are rewritten (section 7): "apply",
	// with the apply, or "later", listed for an admin to run, and why.
	Rewrite    string `json:"rewrite"`
	RewriteWhy string `json:"rewriteWhy,omitempty"`
}

// Changes reports whether the plan changes the table's rows.
func (t ErasureTable) Changes() bool {
	switch t.Action {
	case ErasureActClear, ErasureActDelete, ErasureActCascade, ErasureActSetNull:
		return t.Rows > 0
	}
	return false
}

// ErasurePlan is what a request will do on a branch, shown before it does it.
type ErasurePlan struct {
	Branch  string         `json:"branch"`
	Made    time.Time      `json:"made"`
	By      string         `json:"by"`
	Refs    []ErasureRef   `json:"refs"`
	Tables  []ErasureTable `json:"tables"`
	Matched int            `json:"matched"` // rows holding a value
	Rows    int            `json:"rows"`    // rows the plan changes, cascades included
	Blocked bool           `json:"blocked"` // a table has a problem
	// Searched is how many confirmed places were searched.
	Searched int      `json:"searched"`
	Limits   []string `json:"limits"`
	Review   string   `json:"review"` // the sign-off, said every time (decision 12)
	// Blackbox is what the branch's Blackbox holds of the values (step 3);
	// nil where the branch cannot say.
	Blackbox *ErasureText `json:"blackbox,omitempty"`
	// Copies are what the install keeps of the person beside the branches
	// (step 3b): on main's plan only.
	Copies *ErasureCopies `json:"copies,omitempty"`
}

// ErasureText is what a Blackbox holds of a person's values: data changes
// whose recorded text holds one (redacted with a seal), schema changes that
// do (kept as they are, and flagged: comparison and promotion replay them),
// and original texts kept beside the chain that do (deleted).
type ErasureText struct {
	Redact    int `json:"redact"`
	Flagged   int `json:"flagged"`
	Originals int `json:"originals"`
}

// ErasureTextDone is what the redaction did.
type ErasureTextDone struct {
	Redacted  int     `json:"redacted"`
	Flagged   []int64 `json:"flagged"`         // schema changes holding a value, kept
	Entry     int64   `json:"entry,omitempty"` // the ERASURE REDACT entry; 0 when nothing was redacted
	Originals int     `json:"originals"`
	IDs       []int64 `json:"ids,omitempty"` // the entries redacted
	// OriginalIDs are the entries whose originals beside the chain were
	// deleted: a copy restored from before the erasure is cleared of them by
	// id (step 4).
	OriginalIDs []int64 `json:"originalIds,omitempty"`
}

// Summary is the plan in a line, for the security log: counts, never a value
// or a key.
func (p ErasurePlan) Summary() string {
	n := 0
	for _, t := range p.Tables {
		if t.Changes() {
			n++
		}
	}
	s := fmt.Sprintf("%s: %d value(s); %d row(s) matched, %d changed in %d table(s)", p.Branch, len(p.Refs), p.Matched, p.Rows, n)
	if p.Blocked {
		s += "; blocked"
	}
	return s
}

// ErasureDone is what an apply did in a table, and the row keys it changed:
// kept so the erasure can be checked, and applied again after a restore,
// without the values (decision 9).
type ErasureDone struct {
	Schema     string            `json:"schema"`
	Table      string            `json:"table"`
	Action     string            `json:"action"`
	Rows       int               `json:"rows"`
	KeyColumns []string          `json:"keyColumns,omitempty"`
	Keys       []json.RawMessage `json:"keys,omitempty"`
}

// ErasureRewrite is one table's rewrite in the files (section 7).
type ErasureRewrite struct {
	Schema string     `json:"schema"`
	Table  string     `json:"table"`
	Size   int64      `json:"size"`
	State  string     `json:"state"` // done, pending, failed
	At     *time.Time `json:"at,omitempty"`
	Why    string     `json:"why,omitempty"`
	Error  string     `json:"error,omitempty"`
}

// The states of a rewrite.
const (
	RewriteDone    = "done"
	RewritePending = "pending"
	RewriteFailed  = "failed"
)

// ErasureResult is what applying did.
type ErasureResult struct {
	Applied time.Time     `json:"applied"`
	By      string        `json:"by"`
	Tables  []ErasureDone `json:"tables"`
	Rows    int           `json:"rows"`
	// Verified says a search for the values afterwards, in the same
	// transaction, found none outside the places kept by law.
	Verified bool `json:"verified"`
	// Vacuumed is when the tables were vacuumed: removed from live queries.
	Vacuumed *time.Time       `json:"vacuumed,omitempty"`
	Rewrites []ErasureRewrite `json:"rewrites"`
	// Statistics is when pg_statistic was rewritten and the WAL holding the
	// old pages switched out, after the last rewrite.
	Statistics *time.Time `json:"statistics,omitempty"`
	// Blackbox is what the redaction did, in the same transaction.
	Blackbox *ErasureTextDone `json:"blackbox,omitempty"`
	// AadhaarPlaces is how many of the Aadhaar exposure report's places, in
	// the rows erased, were removed with them.
	AadhaarPlaces int `json:"aadhaarPlaces,omitempty"`
	// Copies is what was removed beside the branches (main's result only).
	Copies *ErasureCopiesDone `json:"copies,omitempty"`
	Notes  []string           `json:"notes"`
}

// RewritesPending counts the tables still to be rewritten.
func (r ErasureResult) RewritesPending() int {
	n := 0
	for _, w := range r.Rewrites {
		if w.State != RewriteDone {
			n++
		}
	}
	return n
}

// ErasureReview is said with every plan and on every page until a privacy
// lawyer and a storage engineer have reviewed F4 (decision 12).
const ErasureReview = "FoxByte's reading of erasure under the DPDP Act, 2023 has not yet been reviewed by a privacy lawyer or a storage engineer. " +
	"It is not legal advice; have it reviewed before relying on it."

// ErasureApply is what the engine is given to apply a request.
type ErasureApply struct {
	ID          int64
	UID         string
	Values      []ErasureValue
	Events      map[string]string
	Fingerprint string
	Actor       string
	// Seed is main's rows, by key, for a masked branch, whose masks are not
	// the person's values but are still the person's rows (section 6).
	Seed ErasureSeed
	// VaultRefs are the vault's reference keys for the request's Aadhaar
	// numbers: a column the vault migrated holds the key (section 4).
	VaultRefs []string
	// Only and Retention are a retention run's (point 11.3): the rows of one
	// table (schema.table), found by Seed, whose period has ended. Other
	// tables are left to their own retention.
	Only      string
	Retention bool
}

// ErasureSeed is rows found by their keys rather than by a value: for each
// table (schema.table), the keys as the engine writes them (a JSON array of
// the key's columns as text). Held for a run, never stored before an apply.
type ErasureSeed map[string][]string

// ErasureEngine is the paid half, supplied by enterprise/dpdp.
type ErasureEngine struct {
	// Refs reads the values as a request keeps them, refusing one that is
	// not recognised.
	Refs func(values []ErasureValue) ([]ErasureRef, error)
	// Plan finds the person's rows on a branch and says what it would do,
	// changing nothing; with the plan's fingerprint, and the keys of the rows
	// it would change (the seed a masked branch is planned from). seed, when
	// not nil, finds rows by key as well as by value.
	Plan func(branch string, values []ErasureValue, events map[string]string, actor string, seed ErasureSeed, vaultRefs []string) (ErasurePlan, string, ErasureSeed, error)
	// Forms are the strings a text is searched for: each value as given and
	// in its normalised forms (the Blackbox, history, the audit log).
	Forms func(values []ErasureValue) []string
	// Apply finds the rows again in one transaction and, if the plan's
	// fingerprint is the one given, applies it and commits. Otherwise it
	// changes nothing and returns the plan as it is now, with
	// ErrErasurePlanChanged.
	Apply func(branch string, a ErasureApply) (ErasurePlan, string, ErasureResult, error)
	// Settle vacuums what an apply changed and rewrites the tables the plan
	// rewrites with it, or, with only, those tables.
	Settle func(branch string, plan ErasurePlan, res ErasureResult, only []string) ErasureResult
	// AppliedOn reports whether a branch's own record holds the request: the
	// apply's transaction writes it, so it is the truth when the store's
	// record of the outcome was lost.
	AppliedOn func(branch, uid string) (bool, error)
	// Reapply applies a request again to a copy restored from before it
	// (step 4): the rows the request changed, found by the keys it kept, as
	// its plan said, in one transaction; the Blackbox entries it redacted,
	// by id; the Aadhaar report's places in those rows. target is a branch,
	// or the restore copy ("restore"). Settle rewrites the tables after.
	Reapply func(target string, a ErasureReapply) (ErasureResult, error)
	// Recheck searches a branch again by the row keys a request kept (step
	// 5): a row it deleted found again, or one it cleared holding a value
	// again, is counted.
	Recheck func(branch string, plan ErasurePlan, done []ErasureDone) ([]RecheckTable, error)
	// PlanRetention plans a retention run (point 11.3): the rows of one table
	// (schema.table), by key, whose period has ended; other tables left to
	// their own retention. Changes nothing. Apply it with Only and Retention.
	PlanRetention func(branch, only string, seed ErasureSeed, actor string) (ErasurePlan, string, ErasureSeed, error)
	// Due finds the rows of a table whose start date is before a cutoff,
	// oldest first, read-only.
	Due func(branch string, q RetentionQuery) (RetentionDue, error)
}

// ErasureReapply is what applying a request again takes: no value, only
// what the request kept.
type ErasureReapply struct {
	ID    int64
	UID   string
	Actor string // what the tracking columns name as the change's maker
	// Plan and Done are the request's plan and what it did, on the branch
	// the copy is of (or main's, for a branch it has no record of).
	Plan ErasurePlan
	Done []ErasureDone
	// Redact and Originals are the Blackbox entries to redact and the
	// originals to delete, by id; empty where the copy's entries are not
	// the ones the request redacted.
	Redact, Originals []int64
}

var erasure *ErasureEngine

// SetErasure installs the engine. Called from enterprise/dpdp's init.
func SetErasure(e ErasureEngine) { erasure = &e }

// Errors an erasure request can give.
var (
	ErrErasurePlanChanged = errors.New("the plan has changed since it was shown")
	ErrErasureValues      = errors.New("the values given are not the request's")
	ErrErasureState       = errors.New("the request is not in a state to do that")
	ErrErasureBlocked     = errors.New("the plan cannot be applied as it stands")
)

func erasureEngine() (*ErasureEngine, error) {
	if err := requireFeature(edition.DPDP); err != nil {
		return nil, err
	}
	if erasure == nil {
		return nil, ErrDPDPNotLicensed
	}
	return erasure, nil
}

// ErasureView is a request as it is read: its record, its latest plan, and
// what applying it did.
type ErasureView struct {
	auth.ErasureRequest
	Refs   []ErasureRef      `json:"refs"`
	Events map[string]string `json:"events"`
	Plan   ErasurePlan       `json:"plan"`
	Result *ErasureResult    `json:"result,omitempty"`
	// Branches is every other branch: its plan, and what applying did there.
	Branches []ErasureBranch `json:"branches"`
	// MadeBefore are the branches whose files still hold the person's old
	// blocks however they were erased (section 6): to remake or delete. Read
	// with the request (GetErasure), not stored.
	MadeBefore []ErasureStale `json:"madeBefore"`
	// Old are the branches past FOX_BRANCH_MAX_AGE (decision 6).
	Old []BranchAge `json:"old"`
	// Restores are the restores past the request an admin decided, and how
	// applying it again to each copy went (step 4). Read with the request.
	Restores []auth.ErasureRestore `json:"restores"`
}

// ViewErasure decodes a request's record. Free in every edition.
func ViewErasure(r auth.ErasureRequest) (ErasureView, error) {
	v := ErasureView{ErasureRequest: r, Refs: []ErasureRef{}, Events: map[string]string{}}
	if err := json.Unmarshal([]byte(r.Refs), &v.Refs); err != nil {
		return v, fmt.Errorf("request %d's values: %w", r.ID, err)
	}
	if r.Events != "" {
		if err := json.Unmarshal([]byte(r.Events), &v.Events); err != nil {
			return v, fmt.Errorf("request %d's event dates: %w", r.ID, err)
		}
	}
	if err := json.Unmarshal([]byte(r.Plan), &v.Plan); err != nil {
		return v, fmt.Errorf("request %d's plan: %w", r.ID, err)
	}
	if r.Result != "" && r.Result != "{}" {
		var res ErasureResult
		if err := json.Unmarshal([]byte(r.Result), &res); err != nil {
			return v, fmt.Errorf("request %d's result: %w", r.ID, err)
		}
		v.Result = &res
	}
	v.Branches, v.MadeBefore, v.Old = []ErasureBranch{}, []ErasureStale{}, []BranchAge{}
	if r.BranchesJSON != "" {
		if err := json.Unmarshal([]byte(r.BranchesJSON), &v.Branches); err != nil {
			return v, fmt.Errorf("request %d's branches: %w", r.ID, err)
		}
	}
	return v, nil
}

// SameRefs reports whether two sets of kept values are the same, in any
// order.
func SameRefs(a, b []ErasureRef) bool {
	key := func(rs []ErasureRef) []string {
		out := make([]string, len(rs))
		for i, r := range rs {
			cs := append([]string(nil), r.Categories...)
			sort.Strings(cs)
			out[i] = strings.Join(cs, "/") + "\x00" + r.Last4
		}
		sort.Strings(out)
		return out
	}
	ka, kb := key(a), key(b)
	if len(ka) != len(kb) {
		return false
	}
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

// ParseErasureValue reads one value as given on a line: "category:value", or
// the value alone to be recognised from its shape.
func ParseErasureValue(s string) ErasureValue {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i > 0 && i <= 12 {
		c := s[:i]
		if strings.Trim(c, "abcdefghijklmnopqrstuvwxyz_") == "" {
			return ErasureValue{Category: c, Value: strings.TrimSpace(s[i+1:])}
		}
	}
	return ErasureValue{Value: s}
}

// NewErasure makes a request on a branch (main, for now) and its first plan.
func NewErasure(s *auth.Store, branchName string, values []ErasureValue, events map[string]string, note, actor string) (ErasureView, error) {
	eng, err := erasureEngine()
	if err != nil {
		return ErasureView{}, err
	}
	if branchName == "" {
		branchName = "main"
	}
	if branchName != "main" {
		return ErasureView{}, fmt.Errorf("%w: a request erases main and every branch made from it; it is made on main", ErrInvalidRequest)
	}
	if len(values) == 0 {
		return ErasureView{}, fmt.Errorf("%w: give at least one value the person is known by", ErrInvalidRequest)
	}
	if n := len([]rune(note)); n > 500 {
		return ErasureView{}, fmt.Errorf("%w: the note is at most 500 characters, not %d", ErrInvalidRequest, n)
	}
	if err := checkEvents(events); err != nil {
		return ErasureView{}, err
	}
	refs, err := eng.Refs(values)
	if err != nil {
		return ErasureView{}, err
	}
	vrefs, vaultNote := erasureVaultRefs(s, eng, values, actor)
	plan, fp, seed, err := eng.Plan(branchName, values, events, actor, nil, vrefs)
	if err != nil {
		return ErasureView{}, err
	}
	plan.Copies = previewCopies(s, eng, values, vrefs, vaultNote)
	branches := planBranches(eng, nil, values, events, actor, seed, vrefs)
	rj, _ := json.Marshal(refs)
	ej, _ := json.Marshal(events)
	pj, _ := json.Marshal(plan)
	bj, _ := json.Marshal(branches)
	rec, err := s.CreateErasure(auth.NewErasureRequest{Branch: branchName, Refs: string(rj), Events: string(ej),
		Note: strings.TrimSpace(note), Plan: string(pj), Fingerprint: fp, Actor: actor, Branches: string(bj)})
	if err != nil {
		return ErasureView{}, err
	}
	return GetErasure(s, rec.ID)
}

// checkEvents refuses an event date that is not one: they are the dates an
// exception's period runs from (section 13), by the inventory's own words.
func checkEvents(events map[string]string) error {
	for k, v := range events {
		if _, ok := dpdpFind(DPDPWords.From, k); !ok {
			return fmt.Errorf("%w: an event is one of %s, not %q", ErrInvalidRequest, dpdpValues(DPDPWords.From), k)
		}
		if _, err := time.Parse("2006-01-02", v); err != nil {
			return fmt.Errorf("%w: %s's date is YYYY-MM-DD, not %q", ErrInvalidRequest, k, v)
		}
	}
	return nil
}

// openErasure reads a request and checks the values given are its own.
func openErasure(s *auth.Store, id int64, values []ErasureValue) (*ErasureEngine, ErasureView, error) {
	eng, err := erasureEngine()
	if err != nil {
		return nil, ErasureView{}, err
	}
	rec, err := settledErasure(s, id)
	if err != nil {
		return nil, ErasureView{}, err
	}
	v, err := ViewErasure(rec)
	if err != nil {
		return nil, v, err
	}
	refs, err := eng.Refs(values)
	if err != nil {
		return nil, v, err
	}
	if !SameRefs(refs, v.Refs) {
		return nil, v, fmt.Errorf("%w: it was made for %s; give the same values (the request keeps only each one's last four characters)",
			ErrErasureValues, refList(v.Refs))
	}
	return eng, v, nil
}

func refList(rs []ErasureRef) string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.String()
	}
	return strings.Join(out, ", ")
}

// ReplanErasure makes a planned request's plan again, from the values: main's
// and every branch's. For an applied request it plans again the branches not
// yet erased, and those made since, to be applied with ApplyErasureBranch.
func ReplanErasure(s *auth.Store, id int64, values []ErasureValue, actor string) (ErasureView, error) {
	eng, v, err := openErasure(s, id, values)
	if err != nil {
		return v, err
	}
	switch v.State {
	case auth.ErasurePlanned:
	case auth.ErasureApplied:
		refs, _ := erasureVaultRefs(s, eng, values, actor)
		branches := planBranches(eng, v.Branches, values, v.Events, actor, resultSeed(v.Result), refs)
		bj, _ := json.Marshal(branches)
		if _, err := s.SaveErasureBranches(id, string(bj)); err != nil {
			return v, err
		}
		return GetErasure(s, id)
	default:
		return v, fmt.Errorf("%w: request %d is %s", ErrErasureState, id, v.State)
	}
	refs, vaultNote := erasureVaultRefs(s, eng, values, actor)
	plan, fp, seed, err := eng.Plan(v.Branch, values, v.Events, actor, nil, refs)
	if err != nil {
		return v, err
	}
	plan.Copies = previewCopies(s, eng, values, refs, vaultNote)
	branches := planBranches(eng, nil, values, v.Events, actor, seed, refs)
	pj, _ := json.Marshal(plan)
	if _, err := s.SaveErasurePlan(id, string(pj), fp, actor); err != nil {
		return v, err
	}
	bj, _ := json.Marshal(branches)
	if _, err := s.SaveErasureBranches(id, string(bj)); err != nil {
		return v, err
	}
	return GetErasure(s, id)
}

// ApplyErasure applies a planned request on its branch: in one transaction,
// only if the plan is the one last shown, then vacuumed and, for the tables
// under the size limit, rewritten. When the plan has changed, nothing is
// applied: the new plan is kept, to be reviewed and applied again, and the
// error is ErrErasurePlanChanged.
func ApplyErasure(s *auth.Store, id int64, values []ErasureValue, actor string) (ErasureView, error) {
	eng, v, err := openErasure(s, id, values)
	if err != nil {
		return v, err
	}
	if v.State != auth.ErasurePlanned {
		return v, fmt.Errorf("%w: request %d is %s", ErrErasureState, id, v.State)
	}
	if v.Plan.Blocked {
		return v, fmt.Errorf("%w: %s", ErrErasureBlocked, firstProblem(v.Plan))
	}
	if err := s.ClaimErasure(id, v.Fingerprint, actor); err != nil {
		return v, err
	}
	refs, _ := erasureVaultRefs(s, eng, values, actor)
	var (
		plan ErasurePlan
		fp   string
		res  ErasureResult
	)
	// Under main's erasing lock: no branch is copied from main while its
	// rows are changed and its files rewritten (section 6).
	err = withErasingLock(v.Branch, func() error {
		var aerr error
		plan, fp, res, aerr = eng.Apply(v.Branch, ErasureApply{ID: id, UID: v.UID, Values: values, Events: v.Events,
			Fingerprint: v.Fingerprint, Actor: actor, VaultRefs: refs})
		if aerr != nil {
			return aerr
		}
		rj, _ := json.Marshal(res)
		if _, ferr := s.FinishErasure(id, string(rj), actor); ferr != nil {
			return &recordErr{fmt.Errorf("the erasure was applied on %s, but recording it failed: %w", v.Branch, ferr)}
		}
		res = eng.Settle(v.Branch, plan, res, nil)
		return nil
	})
	var rerr *recordErr
	if errors.As(err, &rerr) {
		return v, rerr.err
	}
	if errors.Is(err, ErrErasurePlanChanged) {
		pj, _ := json.Marshal(plan)
		rec, serr := s.SaveErasurePlan(id, string(pj), fp, actor)
		if serr != nil {
			return v, serr
		}
		nv, _ := ViewErasure(rec)
		return nv, err
	}
	if err != nil {
		if rerr := s.ReleaseErasure(id); rerr != nil {
			return v, fmt.Errorf("%w (and the request could not be released: %v)", err, rerr)
		}
		return v, err
	}
	rj, _ := json.Marshal(res)
	if _, err := s.SaveErasureResult(id, string(rj)); err != nil {
		return v, fmt.Errorf("the erasure was applied on %s, but recording its vacuum and rewrite failed: %w", v.Branch, err)
	}
	// Then every branch, each in its own transaction (decided 26 Nov): one
	// whose plan changed, or that cannot be erased, is skipped and said so,
	// for ApplyErasureBranch.
	v.Result = &res
	_ = applyBranches(s, eng, v, values, actor, "", refs)
	// Then what the install keeps beside the branches (step 3b), last: the
	// vault's record goes once no branch is left to hold its key unerased.
	nv, err := GetErasure(s, id)
	if err != nil {
		return nv, err
	}
	res.Copies = applyCopies(s, eng, nv, values, actor, refs)
	rj, _ = json.Marshal(res)
	if _, err := s.SaveErasureResult(id, string(rj)); err != nil {
		return nv, fmt.Errorf("the erasure was applied, but recording what it removed beside the branches failed: %w", err)
	}
	return GetErasure(s, id)
}

// recordErr is a failure after the apply committed: the erasure is in, and
// the request must not be released as if it were not.
type recordErr struct{ err error }

func (e *recordErr) Error() string { return e.err.Error() }

func firstProblem(p ErasurePlan) string {
	for _, t := range p.Tables {
		if len(t.Problems) > 0 {
			return t.Schema + "." + t.Table + ": " + t.Problems[0]
		}
	}
	return "a table has a problem"
}

// RewriteErasure rewrites the tables an applied request left for later on
// main, or the ones named (schema.table).
func RewriteErasure(s *auth.Store, id int64, tables []string, actor string) (ErasureView, error) {
	return RewriteErasureOn(s, id, "main", tables, actor)
}

// RewriteErasureOn is RewriteErasure on one branch: main, or a branch the
// request was applied to.
func RewriteErasureOn(s *auth.Store, id int64, branchName string, tables []string, actor string) (ErasureView, error) {
	if branchName != "" && branchName != "main" {
		return rewriteBranch(s, id, branchName, tables, actor)
	}
	eng, err := erasureEngine()
	if err != nil {
		return ErasureView{}, err
	}
	rec, err := settledErasure(s, id)
	if err != nil {
		return ErasureView{}, err
	}
	v, err := ViewErasure(rec)
	if err != nil {
		return v, err
	}
	if v.State != auth.ErasureApplied || v.Result == nil {
		return v, fmt.Errorf("%w: request %d is %s; a request is rewritten once it is applied", ErrErasureState, id, v.State)
	}
	only := tables
	if len(only) == 0 {
		for _, w := range v.Result.Rewrites {
			if w.State != RewriteDone {
				only = append(only, w.Schema+"."+w.Table)
			}
		}
	}
	for _, t := range only {
		if !hasRewrite(*v.Result, t) {
			return v, fmt.Errorf("%w: %s is not a table request %d changed", ErrInvalidRequest, t, id)
		}
	}
	if len(only) == 0 {
		return v, nil
	}
	res := eng.Settle(v.Branch, v.Plan, *v.Result, only)
	rj, _ := json.Marshal(res)
	if _, err = s.SaveErasureResult(id, string(rj)); err != nil {
		return v, err
	}
	return GetErasure(s, id)
}

func hasRewrite(r ErasureResult, t string) bool {
	for _, w := range r.Rewrites {
		if w.Schema+"."+w.Table == t {
			return true
		}
	}
	return false
}

// WithdrawErasure closes a planned request without applying it.
func WithdrawErasure(s *auth.Store, id int64, actor string) (ErasureView, error) {
	if _, err := erasureEngine(); err != nil {
		return ErasureView{}, err
	}
	rec, err := s.WithdrawErasure(id, actor)
	if err != nil {
		return ErasureView{}, err
	}
	return ViewErasure(rec)
}

// GetErasure reads one request, settling one left applying. Free.
func GetErasure(s *auth.Store, id int64) (ErasureView, error) {
	rec, err := settledErasure(s, id)
	if err != nil {
		return ErasureView{}, err
	}
	v, err := ViewErasure(rec)
	if err != nil {
		return v, err
	}
	// What the branches are now: read, not stored, so a branch remade or
	// deleted by any door is seen as it is.
	v.MadeBefore = madeBefore(s, v)
	v.Old = OldBranches()
	if v.Restores, err = s.ErasureRestores(v.ID); err != nil {
		return v, err
	}
	return v, nil
}

// ListErasures reads every request, newest first. Free.
func ListErasures(s *auth.Store) ([]ErasureView, error) {
	recs, err := s.Erasures()
	if err != nil {
		return nil, err
	}
	out := make([]ErasureView, 0, len(recs))
	for _, r := range recs {
		v, err := ViewErasure(r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// erasureStuck is how long a request may read as applying before it is
// looked up on its branch: an apply holds it that long at most. A variable
// so a test need not wait.
var erasureStuck = 15 * time.Minute

// settledErasure reads a request. One left applying by an engine that
// stopped is settled from the branch's own record: applied if the
// transaction committed, planned again if it did not.
func settledErasure(s *auth.Store, id int64) (auth.ErasureRequest, error) {
	rec, err := s.Erasure(id)
	if err != nil || rec.State != auth.ErasureApplying || time.Since(rec.Claimed) < erasureStuck || erasure == nil {
		return rec, err
	}
	on, err := erasure.AppliedOn(rec.Branch, rec.UID)
	if err != nil {
		return rec, nil // not knowing is not settling: read as it stands
	}
	if on {
		res := ErasureResult{Applied: rec.Claimed, Notes: []string{"The engine stopped before recording what it changed; " +
			rec.Branch + "'s own record shows the erasure was applied."}, Rewrites: []ErasureRewrite{}}
		rj, _ := json.Marshal(res)
		return s.FinishErasure(id, string(rj), "")
	}
	if err := s.ReleaseErasure(id); err != nil {
		return rec, err
	}
	return s.Erasure(id)
}
