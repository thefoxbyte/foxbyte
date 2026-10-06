// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/thefoxbyte/foxbyte/internal/edition"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
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
// Schema only. Data is not moved, and saying so plainly is better than a merge
// that silently means something narrower than it sounds.

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
func BuildRequest(source, target string, history []auth.ChangeRequest) (entries []RequestEntry, forkAfterID int64, err error) {
	if source, err = ledgerBranchName(source); err != nil {
		return nil, 0, err
	}
	if target, err = ledgerBranchName(target); err != nil {
		return nil, 0, err
	}
	if source == target {
		return nil, 0, fmt.Errorf("%w: %q is the source and the target", ErrInvalidRequest, source)
	}
	if !Exists(source) {
		return nil, 0, fmt.Errorf("no branch %q", source)
	}
	if !Exists(target) {
		return nil, 0, fmt.Errorf("no branch %q", target)
	}
	if _, err := EnsureRunning(source); err != nil {
		return nil, 0, err
	}
	if _, err := EnsureRunning(target); err != nil {
		return nil, 0, err
	}
	srcRows, err := loadLedgerRows(source, false, "")
	if err != nil {
		return nil, 0, fmt.Errorf("reading %q's Blackbox: %w", source, err)
	}
	tgtRows, err := loadLedgerRows(target, false, "")
	if err != nil {
		return nil, 0, fmt.Errorf("reading %q's Blackbox: %w", target, err)
	}
	n := commonPrefix(srcRows, tgtRows)
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
		entries = append(entries, RequestEntry{
			ID: r.ID, At: r.At.UTC().Format("2006-01-02T15:04:05Z"), Actor: r.Actor, ActorKind: r.ActorKind,
			CommandTag: r.CommandTag, Object: r.ObjectIdentity, Statement: r.Statement, Risk: r.Risk,
		})
	}
	if len(conflicts) > 0 {
		return nil, 0, fmt.Errorf("%w: %s. Look at both with `%s blackbox diff %s %s`, then either "+
			"re-branch from %s and redo the change, or apply it by hand",
			ErrConflict, strings.Join(conflicts, ", "), brand.CLI, source, target, target)
	}
	if len(entries) == 0 {
		return nil, 0, fmt.Errorf("%w: %q has no schema change that %q does not already have",
			ErrNothingToPromote, source, target)
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
		entries, err := UnmarshalEntries(c.Entries)
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
func checkPolicyFor(target string, entries []RequestEntry) error {
	var blocked []string
	for _, e := range entries {
		// The tag the Blackbox recorded when the statement ran, not one derived from
		// the text: a recorded `SET …; DROP TABLE x` reads as a SET otherwise.
		_, matches, err := PolicyCheckTag(target, e.CommandTag, e.Statement)
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
			"or the change can be made by hand", ErrBlockedByPolicy, strings.Join(blocked, "\n  "), target, brand.CLI)
	}
	return nil
}

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

// ApplyRequest applies an approved request's statements to the target, in one
// transaction, and returns how many went in.
//
// Each statement is attributed to the person or agent who wrote it on the source,
// and the approver is recorded beside it: the Blackbox entry's session says which
// request applied it, and the request says who approved it. One transaction means
// the target is never left half-merged — either every statement is in, or none is.
func ApplyRequest(requestID int64, target, approver string, entries []RequestEntry) (int, error) {
	// Applying is the paid half. Reading requests stays free, so one left
	// pending when an install changed edition is still visible and can still
	// be rejected rather than stranded.
	if err := requireFeature(edition.Promotion); err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, ErrNothingToPromote
	}
	target, err := ledgerBranchName(target)
	if err != nil {
		return 0, err
	}
	if _, err := EnsureRunning(target); err != nil {
		return 0, err
	}
	var b strings.Builder
	b.WriteString("BEGIN;\n")
	// Set once for the whole transaction: which request this was, and that the
	// engine applied it rather than a client.
	fmt.Fprintf(&b, "SET LOCAL bb.session = %s;\n", quoteLiteral(fmt.Sprintf("request-%d", requestID)))
	fmt.Fprintf(&b, "SET LOCAL application_name = %s;\n", quoteLiteral(brand.CLI+" request approve (by "+approver+")"))
	// As the shared client role, which is what the gateway runs every client as
	// (proxy.realUser). Ownership is the reason: applied as the superuser, a
	// promoted table belongs to the admin role, and the next `ALTER TABLE` through
	// the gateway fails with "must be owner of table" — the change arrives and then
	// cannot be worked on. Running as the same role the gateway uses gives the
	// object exactly the owner it has on the source.
	//
	// session_user stays the superuser, so the Blackbox's attribution — which reads
	// session_user and falls back to bb.actor — is unaffected.
	fmt.Fprintf(&b, "SET LOCAL ROLE %s;\n", quoteIdent(ClientRole))
	for _, e := range entries {
		// Per statement: the actor is whoever ran it on the source, so the target's
		// record names them and not the approver.
		fmt.Fprintf(&b, "SET LOCAL bb.actor = %s;\n", quoteLiteral(e.Actor))
		if e.ActorKind != "" {
			fmt.Fprintf(&b, "SET LOCAL bb.actor_kind = %s;\n", quoteLiteral(e.ActorKind))
		}
		b.WriteString(strings.TrimRight(strings.TrimSpace(e.Statement), ";") + ";\n")
	}
	b.WriteString("RESET ROLE;\nCOMMIT;\n")
	if err := psqlStdin(target, b.String()); err != nil {
		return 0, fmt.Errorf("applying the request to %q (nothing was committed): %w", target, err)
	}
	return len(entries), nil
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
	return fmt.Sprintf("#%-4d %-9s %s → %s  %d statement(s)%s%s  asked by %s",
		c.ID, c.Status, c.Source, c.Target, len(entries), risky, applied, c.CreatedBy)
}
