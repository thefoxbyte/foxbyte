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
	"errors"
	"fmt"
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

// BuildRequest reads what source has that target does not, and returns the
// statements that would be applied. It refuses a request that cannot be applied
// cleanly, so the refusal comes when someone asks rather than when a reviewer
// approves.
//
// history is this source's already-approved requests for this target. Without it a
// second round of changes from the same branch looks like a conflict: the
// statements the target was given are on both sides now, touching the same
// objects. Changes that came from this source are therefore not counted as the
// target's own, and entries already carried are not offered again.
func build(source, target string, history []auth.ChangeRequest) (entries []branch.RequestEntry, forkAfterID int64, err error) {
	if source, err = branch.ResolveBranch(source); err != nil {
		return nil, 0, err
	}
	if target, err = branch.ResolveBranch(target); err != nil {
		return nil, 0, err
	}
	if source == target {
		return nil, 0, fmt.Errorf("%w: %q is the source and the target", branch.ErrInvalidRequest, source)
	}
	if !branch.Exists(source) {
		return nil, 0, fmt.Errorf("no branch %q", source)
	}
	if !branch.Exists(target) {
		return nil, 0, fmt.Errorf("no branch %q", target)
	}
	if _, err := branch.EnsureRunning(source); err != nil {
		return nil, 0, err
	}
	if _, err := branch.EnsureRunning(target); err != nil {
		return nil, 0, err
	}
	srcRows, err := branch.LedgerRows(source, false, "")
	if err != nil {
		return nil, 0, fmt.Errorf("reading %q's Blackbox: %w", source, err)
	}
	tgtRows, err := branch.LedgerRows(target, false, "")
	if err != nil {
		return nil, 0, fmt.Errorf("reading %q's Blackbox: %w", target, err)
	}
	n := branch.CommonPrefix(srcRows, tgtRows)
	if n > 0 {
		forkAfterID = srcRows[n-1].ID
	}
	// A masked branch's Blackbox starts at its making (masking step 5): it
	// shares no entry with the source, so the fork is the source's last entry
	// when it was copied, which its record keeps. Every entry of its own is
	// after it, and the target's own changes are those after it too.
	ns, nt := n, n
	if fork, ok := branch.MaskedBranchFork(source); ok && n == 0 {
		ns, nt, forkAfterID = 0, len(tgtRows), fork
		for i, r := range tgtRows {
			if r.ID > fork {
				nt = i
				break
			}
		}
	}
	promoted, fromUs := alreadyPromoted(source, target, history)

	// What the target has changed on its own since the fork: the objects a replay
	// could walk into. Entries this source gave it are not the target's own doing.
	tgtTouched := map[string]bool{}
	for _, r := range tgtRows[nt:] {
		if r.ObjectIdentity == "" || r.Status == "BLOCKED" || fromUs[r.Session] {
			continue
		}
		tgtTouched[r.ObjectIdentity] = true
	}

	var conflicts []string
	seen := map[string]bool{}
	for _, r := range srcRows[ns:] {
		if r.Status == "BLOCKED" {
			continue // it never happened, so there is nothing to carry over
		}
		if ledger.IsScanStatus(r.Status) {
			continue // found by the catalog scan: no statement anyone ran, so nothing to replay
		}
		if promoted[r.ID] {
			continue // the target already has this one, from an earlier request
		}
		if strings.TrimSpace(r.Statement) == "" {
			continue // an entry with no statement recorded cannot be replayed
		}
		if r.ObjectIdentity != "" && tgtTouched[r.ObjectIdentity] && !seen[r.ObjectIdentity] {
			seen[r.ObjectIdentity] = true
			conflicts = append(conflicts, r.ObjectIdentity)
		}
		entries = append(entries, branch.RequestEntry{
			ID: r.ID, At: r.At.UTC().Format("2006-01-02T15:04:05Z"), Actor: r.Actor, ActorKind: r.ActorKind,
			CommandTag: r.CommandTag, Object: r.ObjectIdentity, Statement: r.Statement, Risk: r.Risk,
		})
	}
	if len(conflicts) > 0 {
		return nil, 0, fmt.Errorf("%w: %s. Look at both with `%s blackbox diff %s %s`, then either "+
			"re-branch from %s and redo the change, or apply it by hand",
			branch.ErrConflict, strings.Join(conflicts, ", "), brand.CLI, source, target, target)
	}
	if len(entries) == 0 {
		return nil, 0, fmt.Errorf("%w: %q has no schema change that %q does not already have",
			branch.ErrNothingToPromote, source, target)
	}
	if err := checkReplayable(entries); err != nil {
		return nil, 0, err
	}
	xids, err := runXids(source, forkAfterID)
	if err != nil {
		return nil, 0, fmt.Errorf("reading %q's Blackbox: %w", source, err)
	}
	branch.ReplayOnce(entries, xids)
	if err := checkPolicyFor(target, entries); err != nil {
		return nil, 0, err
	}
	return entries, forkAfterID, nil
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

// alreadyPromoted reads the approved requests from this source to this target: the
// source entry ids the target already holds, and the Blackbox sessions those
// statements were applied under.
func alreadyPromoted(source, target string, history []auth.ChangeRequest) (ids map[int64]bool, sessions map[string]bool) {
	ids, sessions = map[int64]bool{}, map[string]bool{}
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
			ids[e.ID] = true
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
// It logs in as the shared client role, over pgx. Ownership is why that role:
// applied as the superuser, a promoted table belongs to the admin role, and the
// next `ALTER TABLE` through the gateway fails with "must be owner of table", so
// running as what the gateway runs every client as (proxy.realUser) gives the
// object exactly the owner it has on the source. Logging in as it, rather than
// SET ROLE from a superuser's session, is why nothing in a statement can get back
// out. The Blackbox's attribution is unaffected: for a session logged in as this
// role it reads bb.actor, as it did for the superuser.
func apply(requestID int64, target, approver string, entries []branch.RequestEntry) (int, error) {
	if len(entries) == 0 {
		return 0, branch.ErrNothingToPromote
	}
	// Again here: what is applied is a stored snapshot, and may predate this check.
	if err := checkReplayable(entries); err != nil {
		return 0, err
	}
	target, err := branch.ResolveBranch(target)
	if err != nil {
		return 0, err
	}
	if _, err := branch.EnsureRunning(target); err != nil {
		return 0, err
	}
	ctx := context.Background()
	openCtx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	conn, err := branch.OpenClient(openCtx, target)
	if err != nil {
		return 0, fmt.Errorf("applying the request to %q (nothing was committed): %w", target, err)
	}
	defer conn.Close(ctx)

	replayed := false
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		inTx := func() bool { return conn.PgConn().TxStatus() != 'I' }
		if err := replay(ctx, tx, inTx, requestID, approver, entries); err != nil {
			return err
		}
		replayed = true
		return nil
	})
	if err != nil {
		return 0, applyFailure(target, replayed, err)
	}
	return len(entries), nil
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
