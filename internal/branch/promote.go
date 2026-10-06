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

// The paid half, supplied by enterprise/promote in an Enterprise build and nil
// in a Standard one.
//
// What stays here is what a request still needs after an install changes
// edition: the entry type, its encoding, and the rendering. Listing, showing
// and rejecting a request are free — a request left open must be closeable
// rather than stranded — and all three need this code.
var (
	buildRequest func(source, target string, history []auth.ChangeRequest) ([]RequestEntry, int64, error)
	applyRequest func(requestID int64, target, approver string, entries []RequestEntry) (int, error)
)

// SetPromotion installs them. Called from enterprise/promote's init, and from
// nowhere else.
func SetPromotion(
	build func(source, target string, history []auth.ChangeRequest) ([]RequestEntry, int64, error),
	apply func(requestID int64, target, approver string, entries []RequestEntry) (int, error),
) {
	buildRequest, applyRequest = build, apply
}

// BuildRequest works out what source holds that target does not.
func BuildRequest(source, target string, history []auth.ChangeRequest) ([]RequestEntry, int64, error) {
	if err := requireFeature(edition.Promotion); err != nil {
		return nil, 0, err
	}
	if buildRequest == nil {
		return nil, 0, ErrPromotionNotLicensed
	}
	return buildRequest(source, target, history)
}

// ApplyRequest applies an approved request to its target.
func ApplyRequest(requestID int64, target, approver string, entries []RequestEntry) (int, error) {
	// Applying is the paid half. Reading requests stays free, so one left
	// pending when an install changed edition is still visible and can still
	// be rejected rather than stranded.
	if err := requireFeature(edition.Promotion); err != nil {
		return 0, err
	}
	if applyRequest == nil {
		return 0, ErrPromotionNotLicensed
	}
	return applyRequest(requestID, target, approver, entries)
}
