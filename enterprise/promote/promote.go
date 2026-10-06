//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package promote is change requests: working out what a branch holds that its
// target does not, and applying it once someone who can manage the target has
// agreed. It is the paid half of `fox request`; the entry type, the encoding
// and the rendering stay in internal/branch, because listing and rejecting a
// request are free and need all three.
package promote

import (
	"fmt"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
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
	promoted, fromUs := alreadyPromoted(source, target, history)

	// What the target has changed on its own since the fork: the objects a replay
	// could walk into. Entries this source gave it are not the target's own doing.
	tgtTouched := map[string]bool{}
	for _, r := range tgtRows[n:] {
		if r.ObjectIdentity == "" || r.Status == "BLOCKED" || fromUs[r.Session] {
			continue
		}
		tgtTouched[r.ObjectIdentity] = true
	}

	var conflicts []string
	seen := map[string]bool{}
	for _, r := range srcRows[n:] {
		if r.Status == "BLOCKED" {
			continue // it never happened, so there is nothing to carry over
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
	if err := checkPolicyFor(target, entries); err != nil {
		return nil, 0, err
	}
	return entries, forkAfterID, nil
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
func apply(requestID int64, target, approver string, entries []branch.RequestEntry) (int, error) {
	if len(entries) == 0 {
		return 0, branch.ErrNothingToPromote
	}
	target, err := branch.ResolveBranch(target)
	if err != nil {
		return 0, err
	}
	if _, err := branch.EnsureRunning(target); err != nil {
		return 0, err
	}
	var b strings.Builder
	b.WriteString("BEGIN;\n")
	// Set once for the whole transaction: which request this was, and that the
	// engine applied it rather than a client.
	fmt.Fprintf(&b, "SET LOCAL bb.session = %s;\n", branch.QuoteLiteral(fmt.Sprintf("request-%d", requestID)))
	fmt.Fprintf(&b, "SET LOCAL application_name = %s;\n", branch.QuoteLiteral(brand.CLI+" request approve (by "+approver+")"))
	// As the shared client role, which is what the gateway runs every client as
	// (proxy.realUser). Ownership is the reason: applied as the superuser, a
	// promoted table belongs to the admin role, and the next `ALTER TABLE` through
	// the gateway fails with "must be owner of table" — the change arrives and then
	// cannot be worked on. Running as the same role the gateway uses gives the
	// object exactly the owner it has on the source.
	//
	// session_user stays the superuser, so the Blackbox's attribution — which reads
	// session_user and falls back to bb.actor — is unaffected.
	fmt.Fprintf(&b, "SET LOCAL ROLE %s;\n", branch.QuoteIdent(branch.ClientRole))
	for _, e := range entries {
		// Per statement: the actor is whoever ran it on the source, so the target's
		// record names them and not the approver.
		fmt.Fprintf(&b, "SET LOCAL bb.actor = %s;\n", branch.QuoteLiteral(e.Actor))
		if e.ActorKind != "" {
			fmt.Fprintf(&b, "SET LOCAL bb.actor_kind = %s;\n", branch.QuoteLiteral(e.ActorKind))
		}
		b.WriteString(strings.TrimRight(strings.TrimSpace(e.Statement), ";") + ";\n")
	}
	b.WriteString("RESET ROLE;\nCOMMIT;\n")
	if err := branch.ExecScript(target, b.String()); err != nil {
		return 0, fmt.Errorf("applying the request to %q (nothing was committed): %w", target, err)
	}
	return len(entries), nil
}
