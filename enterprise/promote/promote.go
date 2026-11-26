//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package promote is change requests: working out what a branch holds that its
// target does not, and applying it once someone who can manage the target has
// agreed. It is the paid half of `fox request`; the entry type, the encoding
// and the rendering stay in internal/branch, because listing and rejecting a
// request are free and need all three.
package promote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// init registers both halves with internal/branch, which is how the free side
// reaches them without importing this package.
func init() { branch.SetPromotion(build, apply) }

// build reads what source has that target does not, and returns the
// statements that would be applied. It refuses a request that cannot be applied
// cleanly, so the refusal comes when someone asks rather than when a reviewer
// approves.
//
// history is this source's already-applied requests for this target
// (branch.RequestHistory). Without it a second round of changes from the same
// branch looks like a conflict: the statements the target was given are on both
// sides now, touching the same objects. Changes that came from this source are
// therefore not counted as the target's own, and entries already carried are
// not offered again.
//
// Data changes are left out unless opts.IncludeData, and listed in the plan, so
// the request says what it is not carrying.
func build(source, target string, history []auth.ChangeRequest, opts branch.RequestOptions) (plan branch.RequestPlan, err error) {
	if source, err = branch.ResolveBranch(source); err != nil {
		return plan, err
	}
	if target, err = branch.ResolveBranch(target); err != nil {
		return plan, err
	}
	if source == target {
		return plan, fmt.Errorf("%w: %q is the source and the target", branch.ErrInvalidRequest, source)
	}
	if !branch.Exists(source) {
		return plan, fmt.Errorf("no branch %q", source)
	}
	if !branch.Exists(target) {
		return plan, fmt.Errorf("no branch %q", target)
	}
	if _, err := branch.EnsureRunning(source); err != nil {
		return plan, err
	}
	if _, err := branch.EnsureRunning(target); err != nil {
		return plan, err
	}
	// Only the requests this target holds count as applied to it. A request is
	// stored under its branches' names, and a branch deleted and made again
	// under the same name is not the one the request was applied to.
	recorded, err := branch.AppliedRequests(target)
	if err != nil {
		return plan, fmt.Errorf("reading which change requests %q already has: %w", target, err)
	}
	promoted, fromUs := alreadyPromoted(source, target, heldBy(history, recorded))
	p := newForkPlan(promoted, fromUs)
	p.maskedFork, p.masked = branch.MaskedBranchFork(source)
	// Both ledgers are read side by side as they stream (branch.WalkLedgerFork):
	// the shared history is compared and dropped, and of what follows the fork
	// only the source entries a replay would carry are kept.
	if err := branch.WalkLedgerFork(source, target, p.visitor()); err != nil {
		return plan, err
	}
	plan = p.plan(opts)
	// A data change is recorded with placeholders (F4); the text it ran with
	// is kept beside the chain, and is what a replay runs.
	if err := withOriginals(source, plan.Entries); err != nil {
		if errors.Is(err, branch.ErrNotReplayable) {
			return branch.RequestPlan{}, err
		}
		return branch.RequestPlan{}, fmt.Errorf("reading %q's original statements: %w", source, err)
	}
	if err := p.conflicts(plan.Entries); err != nil {
		return branch.RequestPlan{}, fmt.Errorf("%w. Look at both with `%s blackbox diff %s %s`, then either "+
			"re-branch from %s and redo the change, or apply it by hand", err, brand.CLI, source, target, target)
	}
	if len(plan.Entries) == 0 {
		if plan.OmittedCount > 0 {
			return branch.RequestPlan{}, fmt.Errorf("%w: %q has no schema change that %q does not already have; "+
				"its %d data change(s) were left out, which a request carries only when asked to (--include-data)",
				branch.ErrNothingToPromote, source, target, plan.OmittedCount)
		}
		return branch.RequestPlan{}, fmt.Errorf("%w: %q has no schema change that %q does not already have",
			branch.ErrNothingToPromote, source, target)
	}
	if err := checkReplayable(plan.Entries); err != nil {
		return branch.RequestPlan{}, err
	}
	if !plan.IncludeData {
		if err := checkSchemaOnly(plan.Entries); err != nil {
			return branch.RequestPlan{}, err
		}
	}
	xids, err := runXids(source, plan.ForkAfterID)
	if err != nil {
		return branch.RequestPlan{}, fmt.Errorf("reading %q's Blackbox: %w", source, err)
	}
	branch.ReplayOnce(plan.Entries, xids)
	if err := checkPolicyFor(target, plan.Entries); err != nil {
		return branch.RequestPlan{}, err
	}
	return plan, nil
}

// withOriginals puts back, in each entry recorded with placeholders, the text
// it ran with, kept beside the chain in bb.ledger_text. An entry whose original
// an erasure deleted keeps its placeholders, and checkReplayable refuses it:
// it cannot be replayed without the values it no longer has.
func withOriginals(source string, entries []branch.RequestEntry) error {
	if len(entries) == 0 {
		return nil
	}
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = strconv.FormatInt(e.ID, 10)
	}
	lines, err := branch.LedgerQuery(source, "SELECT CASE WHEN to_regclass('bb.ledger_text') IS NULL THEN '{}'::json "+
		"ELSE (SELECT coalesce(json_object_agg(id, statement), '{}'::json) FROM bb.ledger_text WHERE id IN ("+strings.Join(ids, ",")+")) END")
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return nil
	}
	var orig map[string]string
	if err := json.Unmarshal([]byte(lines[0]), &orig); err != nil {
		return err
	}
	var bad []string
	for i := range entries {
		if t, ok := orig[strconv.FormatInt(entries[i].ID, 10)]; ok {
			entries[i].Statement = t
			continue
		}
		// A data change still holding its placeholders: its values are gone.
		if isDataChange(entries[i].CommandTag, entries[i].Risk) && placeholder.MatchString(entries[i].Statement) {
			bad = append(bad, fmt.Sprintf("entry %d (%s %s): recorded without its values, which an erasure request removed",
				entries[i].ID, entries[i].CommandTag, entries[i].Object))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w:\n  %s\nLeave data changes out of the request, or make them again on the source", branch.ErrNotReplayable, strings.Join(bad, "\n  "))
	}
	return nil
}

// placeholder is a $1-style parameter, as bbid_placeholders writes them: not
// part of a dollar quote ($$1$$) or a name.
var placeholder = regexp.MustCompile(`(^|[^$\w])\$[0-9]+\b`)

// plan turns the walk's candidates into a request's entries, leaving out the
// data changes unless they were asked for.
func (p *forkPlan) plan(opts branch.RequestOptions) branch.RequestPlan {
	out := branch.RequestPlan{ForkAfterID: p.forkAfterID, IncludeData: opts.IncludeData}
	for _, r := range p.candidates {
		// An entry holds its author's whole message. A command tag of CREATE
		// TABLE does not mean the message is only that: `CREATE TABLE t;
		// INSERT INTO t` is recorded as one entry, and replaying it would
		// change rows. Leaving it in, then refusing the whole request, also
		// blocks every later schema change on that branch. It is left out,
		// like any other data change, and listed so the asker can see it.
		reason := ""
		if !opts.IncludeData && isDataChange(r.CommandTag, r.Risk) {
			reason = "a data change; the request is schema only"
		} else if !opts.IncludeData {
			if r := dataRefusal(r.Statement); r != "" {
				reason = r + "; a schema-only request would run it"
			}
		}
		if reason != "" {
			out.OmittedCount++
			if len(out.Omitted) < branch.OmittedListed {
				out.Omitted = append(out.Omitted, branch.OmittedEntry{ID: r.ID, Actor: r.Actor, ActorKind: r.ActorKind,
					CommandTag: r.CommandTag, Object: r.ObjectIdentity, Reason: reason})
			}
			continue
		}
		out.Entries = append(out.Entries, branch.RequestEntry{
			ID: r.ID, At: r.At.UTC().Format("2006-01-02T15:04:05Z"), Actor: r.Actor, ActorKind: r.ActorKind,
			CommandTag: r.CommandTag, Object: r.ObjectIdentity, Statement: r.Statement, Risk: r.Risk,
		})
	}
	return out
}

// conflicts names the objects both the request's entries and the target's own
// changes since the fork touch. Only the entries the request carries count: an
// object only a left-out data change touched is not walked into.
func (p *forkPlan) conflicts(entries []branch.RequestEntry) error {
	var both []string
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Object != "" && p.tgtTouched[e.Object] && !seen[e.Object] {
			seen[e.Object] = true
			both = append(both, e.Object)
		}
	}
	if len(both) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", branch.ErrConflict, strings.Join(both, ", "))
}

// dataTags are the command tags the Blackbox records a change to rows under:
// the TG_OP of datachanges.sql's statement triggers (INSERT, UPDATE, DELETE,
// TRUNCATE), and the other row-changing commands, should they ever be
// recorded.
var dataTags = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "TRUNCATE": true, "COPY": true,
}

// dataRisks are the risks only a data change is recorded with: the row limit,
// the row budget, an agent's unqualified UPDATE or DELETE, and TRUNCATE. A
// FLAGGED entry with one of these is a data change whatever its tag says.
// Other FLAGGED entries (a column dropped, a type changed) are schema changes,
// and stay in the request with their risk shown.
var dataRisks = map[string]bool{"impact": true, "budget": true, "unqualified": true, "truncate": true}

// isDataChange reports whether a Blackbox entry records a change to rows
// rather than to the schema.
func isDataChange(commandTag, risk string) bool {
	tag := strings.ToUpper(strings.TrimSpace(commandTag))
	if i := strings.IndexByte(tag, ' '); i > 0 {
		tag = tag[:i]
	}
	return dataTags[tag] || dataRisks[strings.ToLower(strings.TrimSpace(risk))]
}

// forkPlan collects what a request needs from a walk of the source's and the
// target's Blackboxes: where they part, the source entries after that which
// could be replayed, and the objects the target changed on its own since.
type forkPlan struct {
	promoted map[int64]branch.RequestEntry // source entries the target already has, as they were carried
	fromUs   map[string]bool               // target sessions this source's requests ran under

	maskedFork int64
	masked     bool

	maskedMode  bool
	forkAfterID int64
	candidates  []ledger.Row
	tgtTouched  map[string]bool
}

func newForkPlan(promoted map[int64]branch.RequestEntry, fromUs map[string]bool) *forkPlan {
	return &forkPlan{promoted: promoted, fromUs: fromUs, tgtTouched: map[string]bool{}}
}

func (p *forkPlan) visitor() branch.LedgerFork {
	return branch.LedgerFork{
		Fork: func(n int, last *ledger.Row) {
			if last != nil {
				p.forkAfterID = last.ID
			}
			// A masked branch's Blackbox starts at its making (masking step 5):
			// it shares no entry with the source, so the fork is the source's
			// last entry when it was copied, which its record keeps. Every entry
			// of its own is after it, and the target's own changes are those
			// after it too.
			if p.masked && n == 0 {
				p.maskedMode, p.forkAfterID = true, p.maskedFork
			}
		},
		OnlyA: func(r ledger.Row) {
			if replayable(r, p.promoted) {
				p.candidates = append(p.candidates, r)
			}
		},
		// What the target has changed on its own since the fork: the objects a
		// replay could walk into. Entries this source gave it are not the
		// target's own doing.
		OnlyB: func(r ledger.Row) {
			if p.maskedMode && r.ID <= p.maskedFork {
				return
			}
			if r.ObjectIdentity == "" || r.Status == "BLOCKED" || p.fromUs[r.Session] {
				return
			}
			p.tgtTouched[r.ObjectIdentity] = true
		},
	}
}

// replayable reports whether a source entry after the fork is one a request
// carries.
func replayable(r ledger.Row, promoted map[int64]branch.RequestEntry) bool {
	switch {
	case r.Status == "BLOCKED":
		return false // it never happened, so there is nothing to carry over
	case ledger.IsScanStatus(r.Status):
		return false // found by the catalog scan: no statement anyone ran, so nothing to replay
	case carried(r, promoted):
		return false // the target already has this one, from an earlier request
	case strings.TrimSpace(r.Statement) == "":
		return false // an entry with no statement recorded cannot be replayed
	}
	return true
}

// runXids reads the transaction each Blackbox entry after the fork was recorded
// in (bb.ledger_ext), so that the entries one run made share its statement
// once. A branch without the capture table has none, and replays as before.
func runXids(source string, after int64) (map[int64]int64, error) {
	ext, _, err := branch.LedgerV2Tables(source)
	if err != nil || !ext {
		return nil, err
	}
	lines, err := branch.LedgerQuery(source, fmt.Sprintf(
		"SELECT ledger_id || ' ' || xid FROM bb.ledger_ext WHERE ledger_id > %d AND xid IS NOT NULL", after))
	if err != nil {
		return nil, err
	}
	xids := make(map[int64]int64, len(lines))
	for _, l := range lines {
		var id, x int64
		if _, err := fmt.Sscan(l, &id, &x); err == nil {
			xids[id] = x
		}
	}
	return xids, nil
}

// carried reports whether an earlier request already gave the target this
// source entry. An id is not enough: a branch deleted and made again under the
// same name numbers its entries from where its parent was, so its entry 140 is
// not the one an earlier request carried as 140. The entry must also have been
// recorded at the same second, as the same command. A snapshot without a time
// is known by its id alone, as it always was.
func carried(r ledger.Row, promoted map[int64]branch.RequestEntry) bool {
	e, ok := promoted[r.ID]
	if !ok {
		return false
	}
	at, err := time.Parse(time.RFC3339, e.At)
	if e.At == "" || err != nil {
		return true
	}
	if !r.At.UTC().Truncate(time.Second).Equal(at) {
		return false
	}
	tag, was := strings.TrimSpace(r.CommandTag), strings.TrimSpace(e.CommandTag)
	return tag == "" || was == "" || strings.EqualFold(tag, was)
}

// heldBy is the history without the requests the target's own record says it
// does not hold (bb.applied_requests, written in the same transaction as the
// changes). The store keeps a request under its branches' names, so a target
// deleted and made again under the same name inherits the old one's requests;
// a target restored to before a request was applied no longer has it either.
// Either way the request's entries are not on this target, and must be offered
// again rather than taken as carried.
//
// Only a request with a name (auth.ChangeRequest.UID) is checked: every engine
// that names requests records each one it applies, by its name, before it runs
// a statement (recordApplied). One from before has no such record to look for,
// and counts as it always did.
func heldBy(history []auth.ChangeRequest, recorded map[branch.AppliedKey]int) []auth.ChangeRequest {
	out := make([]auth.ChangeRequest, 0, len(history))
	for _, c := range history {
		if c.UID != "" && c.Status == auth.RequestApproved && c.Applied > 0 {
			if _, ok := recorded[branch.AppliedKeyOf(c)]; !ok {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// alreadyPromoted reads the approved requests from this source to this target: the
// source entries the target already holds, as each request carried them, and the
// Blackbox sessions those statements were applied under.
func alreadyPromoted(source, target string, history []auth.ChangeRequest) (ids map[int64]branch.RequestEntry, sessions map[string]bool) {
	ids, sessions = map[int64]branch.RequestEntry{}, map[string]bool{}
	for _, c := range history {
		if c.Source != source || c.Target != target || c.Status != auth.RequestApproved || c.Applied == 0 {
			continue
		}
		sessions[fmt.Sprintf("request-%d", c.ID)] = true
		entries, err := branch.UnmarshalEntries(c.Entries)
		if err != nil {
			continue
		}
		for _, e := range entries {
			ids[e.ID] = e
		}
	}
	return ids, sessions
}

// checkPolicyFor asks the target's own policy gate about every statement, before
// anything is applied. The gate is the target's, not the source's: a rule an admin
// turned on for main is exactly what a merge must not walk around.
func checkPolicyFor(target string, entries []branch.RequestEntry) error {
	var blocked []string
	for _, e := range entries {
		// The tag the Blackbox recorded when the statement ran, not one derived from
		// the text: a recorded `SET …; DROP TABLE x` reads as a SET otherwise.
		_, matches, err := branch.PolicyCheckTag(target, e.CommandTag, e.Statement)
		if err != nil {
			// A gate that cannot be consulted is not a reason to apply anyway.
			return fmt.Errorf("checking entry %d against %q's policy: %w", e.ID, target, err)
		}
		for _, m := range matches {
			if m.Action == "block" {
				blocked = append(blocked, fmt.Sprintf("entry %d (%s %s) by rule %s: %s",
					e.ID, e.CommandTag, e.Object, m.RuleID, m.Reason))
			}
		}
	}
	if len(blocked) > 0 {
		return fmt.Errorf("%w:\n  %s\nAn admin can allow the rule on %s (`%s policy warn <rule>`) and ask again, "+
			"or the change can be made by hand", branch.ErrBlockedByPolicy, strings.Join(blocked, "\n  "), target, brand.CLI)
	}
	return nil
}

// ApplyRequest applies an approved request's statements to the target, in one
// transaction, and returns how many went in.
//
// Each statement is attributed to the person or agent who wrote it on the source,
// and the approver is recorded beside it: the Blackbox entry's session says which
// request applied it, and the request says who approved it. One transaction means
// the target is never left half-merged — either every statement is in, or none is.
//
// The transaction also writes the request's id into the target's own record
// (bb.applied_requests), first, so the record and the changes commit together:
// an id already there is refused before any statement runs, and a request
// whose outcome the engine's store failed to note can still be found applied
// (branch.RequestHistory). And it checks again, inside the transaction, that
// the target has not changed the same objects since the fork: the request was
// checked when it was asked for, and the target may have moved on since.
//
// It logs in as the shared client role, over pgx. Ownership is why that role:
// applied as the superuser, a promoted table belongs to the admin role, and the
// next `ALTER TABLE` through the gateway fails with "must be owner of table", so
// running as what the gateway runs every client as (proxy.realUser) gives the
// object exactly the owner it has on the source. Logging in as it, rather than
// SET ROLE from a superuser's session, is why nothing in a statement can get back
// out. The Blackbox's attribution is unaffected: for a session logged in as this
// role it reads bb.actor, as it did for the superuser.
func apply(p branch.ApplyPlan) (int, error) {
	c, entries := p.Request, p.Entries
	if len(entries) == 0 {
		return 0, branch.ErrNothingToPromote
	}
	if err := checkSnapshot(c, entries); err != nil {
		return 0, err
	}
	target, err := branch.ResolveBranch(c.Target)
	if err != nil {
		return 0, err
	}
	c.Target = target
	if _, err := branch.EnsureRunning(target); err != nil {
		return 0, err
	}
	if err := ensureAppliedRecord(target); err != nil {
		return 0, err
	}
	_, fromUs := alreadyPromoted(c.Source, target, p.History)
	ctx := context.Background()
	openCtx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	conn, err := branch.OpenClient(openCtx, target)
	if err != nil {
		return 0, fmt.Errorf("applying the request to %q (nothing was committed): %w", target, err)
	}
	defer conn.Close(ctx)

	replayed := false
	recorded := 0
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		inTx := func() bool { return conn.PgConn().TxStatus() != 'I' }
		n, err := applyIn(ctx, tx, inTx, c, p.Approver, entries, fromUs)
		recorded = n
		if err != nil {
			return err
		}
		replayed = true
		return nil
	})
	if errors.Is(err, branch.ErrAlreadyApplied) {
		return recorded, fmt.Errorf("applying the request to %q (nothing was run again): %w", target, err)
	}
	if err != nil {
		return 0, applyFailure(target, replayed, err)
	}
	return len(entries), nil
}

// checkSnapshot checks what is about to be applied, again: it is a stored
// snapshot, and may predate the checks made when it was asked for, or have
// been written by an engine that made fewer of them.
func checkSnapshot(c auth.ChangeRequest, entries []branch.RequestEntry) error {
	if err := checkReplayable(entries); err != nil {
		return err
	}
	if c.IncludeData {
		return nil
	}
	// A schema-only request applies no data change, whatever its snapshot
	// says: one made before data changes were left out may hold some.
	var data []string
	for _, e := range entries {
		if isDataChange(e.CommandTag, e.Risk) {
			data = append(data, fmt.Sprintf("entry %d (%s %s)", e.ID, e.CommandTag, e.Object))
		}
	}
	if len(data) > 0 {
		return fmt.Errorf("%w: it is schema only and holds data changes: %s. Nothing was applied. "+
			"Ask again (`%s branch request %s`), which leaves them out, or with --include-data to carry them",
			branch.ErrNotReplayable, strings.Join(data, ", "), brand.CLI, c.Source)
	}
	return checkSchemaOnly(entries)
}

// ensureAppliedRecord makes sure the target has bb.applied_requests, with the
// column for a request's name, before the transaction that writes to it. A
// target whose Blackbox predates either is upgraded, the way `fox ledger
// upgrade` does it; if that fails nothing is applied, since a request applied
// without the record could be applied again.
func ensureAppliedRecord(target string) error {
	if has, err := branch.LedgerQuery(target, "SELECT EXISTS (SELECT 1 FROM pg_attribute "+
		"WHERE attrelid = to_regclass('bb.applied_requests') AND attname = 'request_uid' AND NOT attisdropped)::text"); err == nil &&
		len(has) == 1 && has[0] == "true" {
		return nil
	}
	if err := branch.EnsureLedgerV2(target); err != nil {
		return fmt.Errorf("adding the record of applied requests to %q (nothing was applied; `%s ledger upgrade %s` retries it): %w",
			target, brand.CLI, target, err)
	}
	return nil
}

// applyTx is what applyIn needs of a transaction.
type applyTx interface {
	execer
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// applyIn is the whole of an apply inside its transaction: record the request
// on the target, check for conflicts, then replay. On ErrAlreadyApplied it
// returns the number of statements the target recorded the first time.
func applyIn(ctx context.Context, tx applyTx, inTx func() bool, c auth.ChangeRequest, approver string,
	entries []branch.RequestEntry, fromUs map[string]bool) (int, error) {
	if n, err := recordApplied(ctx, tx, c, approver, len(entries)); err != nil {
		return n, err
	}
	if err := conflictsSince(ctx, tx, c, entries, fromUs); err != nil {
		return 0, err
	}
	return 0, replay(ctx, tx, inTx, c.ID, approver, entries)
}

// recordApplied writes the request into the target's record, first, so that a
// second apply of the same request finds it and stops. A request is its id and
// its store's name for it (auth.ChangeRequest.UID): another request with the
// same id, from a store recreated or restored since, is not it. Two applies at
// once meet on the key: the second waits for the first to commit or roll back,
// and then either finds the row or writes its own.
func recordApplied(ctx context.Context, tx applyTx, c auth.ChangeRequest, approver string, statements int) (int, error) {
	tag, err := tx.Exec(ctx, "INSERT INTO bb.applied_requests (request_id, request_uid, source, approver, statements) "+
		"VALUES ($1, $2, $3, $4, $5) ON CONFLICT ON CONSTRAINT applied_requests_request_key DO NOTHING",
		c.ID, requestUID(c), c.Source, approver, statements)
	if err != nil {
		return 0, fmt.Errorf("recording request #%d in %q's Blackbox: %w", c.ID, c.Target, err)
	}
	if tag.RowsAffected() == 1 {
		return 0, nil
	}
	had := 0
	if err := tx.QueryRow(ctx, "SELECT statements FROM bb.applied_requests "+
		"WHERE request_id = $1 AND request_uid IS NOT DISTINCT FROM $2", c.ID, requestUID(c)).Scan(&had); err != nil {
		return 0, fmt.Errorf("%w: request #%d (reading its record: %v)", branch.ErrAlreadyApplied, c.ID, err)
	}
	return had, fmt.Errorf("%w: request #%d is in %q's record of applied requests", branch.ErrAlreadyApplied, c.ID, c.Target)
}

// requestUID is the name a request is recorded under: NULL for one made
// before requests had one, so it is one request with its earlier record.
func requestUID(c auth.ChangeRequest) any {
	if c.UID == "" {
		return nil
	}
	return c.UID
}

// conflictsSince asks the target, inside the apply's transaction, whether it
// has changed any object the request touches since the branches parted: the
// same question build asked, over the target's Blackbox as it stands now.
// Changes this source's earlier requests made are the source's own, as there.
//
// Only the columns that say what changed and under which session are read, not
// the statements.
func conflictsSince(ctx context.Context, tx applyTx, c auth.ChangeRequest, entries []branch.RequestEntry, fromUs map[string]bool) error {
	objects := []string{}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Object != "" && !seen[e.Object] {
			seen[e.Object] = true
			objects = append(objects, e.Object)
		}
	}
	if len(objects) == 0 {
		return nil
	}
	sessions := []string{}
	for s := range fromUs {
		sessions = append(sessions, s)
	}
	var touched string
	err := tx.QueryRow(ctx, "SELECT coalesce(string_agg(DISTINCT object_identity, ', ' ORDER BY object_identity), '') "+
		"FROM bb.schema_ledger WHERE id > $1 AND object_identity = ANY($2) AND status <> 'BLOCKED' "+
		"AND NOT (coalesce(session, '') = ANY($3))", c.ForkAfterID, objects, sessions).Scan(&touched)
	if err != nil {
		return fmt.Errorf("checking %q for changes since the fork: %w", c.Target, err)
	}
	if touched != "" {
		return fmt.Errorf("%w: %s changed on %s since the branches parted. Nothing was applied; "+
			"look at both with `%s blackbox diff %s %s` and ask again", branch.ErrConflict, touched, c.Target,
			brand.CLI, c.Source, c.Target)
	}
	return nil
}

// openTimeout bounds the login. The statements themselves have no limit: an ALTER
// on a large table has always been allowed to take what it takes.
const openTimeout = 30 * time.Second

// errTransactionEnded is a statement having ended the transaction it was given,
// which checkReplayable exists to prevent. If one ever gets past that, the apply
// stops there and says so, rather than report a rollback that did not happen.
var errTransactionEnded = errors.New("the statement ended the transaction it was applied in")

// applyFailure says what a failed apply left behind. Every statement's error
// comes before the commit and rolls the transaction back, and a commit the server
// refused did too. Only a commit whose answer never arrived leaves it open.
func applyFailure(target string, replayed bool, err error) error {
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, errTransactionEnded):
		return fmt.Errorf("applying the request to %q: part of it may be committed; compare the target with its Blackbox: %w", target, err)
	case replayed && !errors.As(err, &pgErr) && !errors.Is(err, pgx.ErrTxCommitRollback):
		return fmt.Errorf("applying the request to %q: every statement ran but the commit was not confirmed, so it may or may not be in; "+
			"look for this request's session in the target's Blackbox: %w", target, err)
	}
	return fmt.Errorf("applying the request to %q (nothing was committed): %w", target, err)
}

// execer is the one call replay needs of a transaction.
type execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// replay runs a request's statements in tx, each under its own author. inTx says
// whether the connection is still in that transaction.
//
// A statement goes to the server as its own message, exactly as recorded and with
// no arguments, which pgx sends by the simple protocol: one message may hold
// several statements, and nothing but the server reads it, so a :name or a
// backslash in it is only text. The settings are bound values for the same
// reason; set_config(…, true) is SET LOCAL.
func replay(ctx context.Context, tx execer, inTx func() bool, requestID int64, approver string, entries []branch.RequestEntry) error {
	// Set once for the whole transaction: which request this was, and that the
	// engine applied it rather than a client. standard_conforming_strings because
	// the check read the statements with it on, whatever the role's default is.
	if _, err := tx.Exec(ctx, "SELECT set_config('standard_conforming_strings', 'on', true), "+
		"set_config('bb.session', $1, true), set_config('application_name', $2, true)",
		fmt.Sprintf("request-%d", requestID), brand.CLI+" request approve (by "+approver+")"); err != nil {
		return fmt.Errorf("setting up the transaction: %w", err)
	}
	for _, e := range entries {
		if e.SameRun != 0 {
			continue // its statement ran with the entry it shares it with
		}
		// Per statement: the actor is whoever ran it on the source, so the target's
		// record names them and not the approver.
		if _, err := tx.Exec(ctx, "SELECT set_config('bb.actor', $1, true)", e.Actor); err != nil {
			return fmt.Errorf("entry %d: %w", e.ID, err)
		}
		if e.ActorKind != "" {
			if _, err := tx.Exec(ctx, "SELECT set_config('bb.actor_kind', $1, true)", e.ActorKind); err != nil {
				return fmt.Errorf("entry %d: %w", e.ID, err)
			}
		}
		if _, err := tx.Exec(ctx, strings.TrimSpace(e.Statement)); err != nil {
			return fmt.Errorf("entry %d: %w", e.ID, err)
		}
		if !inTx() {
			return fmt.Errorf("entry %d: %w", e.ID, errTransactionEnded)
		}
	}
	return nil
}
