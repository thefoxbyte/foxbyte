// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Change requests over the API: a branch's schema changes, offered for review,
// then applied to another branch.
//
// Who may do what follows the same rule as every other branch-scoped operation
// (internal/access): asking needs access to both branches, and approving needs the
// right to manage the target — an admin for main, the owner for anything else. An
// agent's branch-scoped key cannot manage anything, so an agent can propose a
// change and cannot approve its own, which is the point of having a review step.

// requestView is a change request as the API returns it: the record, plus the
// statements it holds and what it left out, decoded.
type requestView struct {
	auth.ChangeRequest
	Entries []branch.RequestEntry `json:"entries"`
	Omitted []branch.OmittedEntry `json:"omitted"`
	// Existing is set when asking found an open request for exactly the same
	// changes and returned it rather than making a second one.
	Existing bool `json:"existing,omitempty"`
}

func viewOf(c auth.ChangeRequest) requestView {
	entries, _ := branch.UnmarshalEntries(c.Entries)
	omitted, _ := branch.UnmarshalOmitted(c.Omitted)
	if omitted == nil {
		omitted = []branch.OmittedEntry{}
	}
	c.Entries, c.Omitted = "", "" // they are below, decoded; sending both is noise
	return requestView{ChangeRequest: c, Entries: entries, Omitted: omitted}
}

// Seams for tests: the paid half's build and apply, which need running
// branches.
var (
	buildChangeRequest = branch.BuildRequest
	applyClaimed       = branch.ApplyClaimed
	requestHistory     = branch.RequestHistory
)

func registerRequests(mux *http.ServeMux, store *auth.Store) {
	// Ask for a branch's changes to be applied elsewhere. The path's branch is the
	// source (authorize has already checked the caller may use it).
	mux.HandleFunc("POST /api/branches/{name}/request", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.Promotion) {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		source := r.PathValue("name")
		var body struct {
			Target string `json:"target"`
			// IncludeData carries the source's data changes too. Off unless
			// asked for, and shown on the request when it is on.
			IncludeData bool `json:"include_data"`
		}
		if err := decode(r, &body); err != nil {
			writeErr(w, 400, err)
			return
		}
		target := body.Target
		if target == "" {
			target = "main"
		}
		// Reading the target's schema is part of asking, so the caller needs at
		// least access to it. Approving needs more, and is checked there.
		if !allowed(w, r, u, target, access.Use) {
			return
		}
		history, err := requestHistory(store, source, target)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		plan, err := buildChangeRequest(source, target, history, branch.RequestOptions{IncludeData: body.IncludeData})
		if err != nil {
			writeErr(w, statusForRequestErr(err), err)
			return
		}
		rec, err := branch.NewRequest(source, target, plan)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		c, existing, err := store.OpenChangeRequest(u.ID, rec)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if existing {
			// The same changes are already waiting for a decision: a second
			// request would be a second chance to apply them.
			v := viewOf(c)
			v.Existing = true
			writeJSON(w, 200, v)
			return
		}
		store.Audit(auth.EvChangeRequested, u.Email, fmt.Sprintf("request #%d: %s → %s", c.ID, source, target),
			remoteIP(r), branch.RequestedDetail(plan))
		writeJSON(w, 201, viewOf(c))
	})

	// The requests this caller can see: those touching a branch they may reach.
	mux.HandleFunc("GET /api/requests", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		list, err := store.ChangeRequests(r.URL.Query().Get("status"), r.URL.Query().Get("target"))
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		out := []requestView{}
		for _, c := range list {
			if acl.Level(u, c.Target) == access.None && acl.Level(u, c.Source) == access.None {
				continue
			}
			out = append(out, viewOf(c))
		}
		writeJSON(w, 200, out)
	})

	mux.HandleFunc("GET /api/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		c, ok := requestFor(w, r, store, access.Use)
		if !ok {
			return
		}
		writeJSON(w, 200, viewOf(c))
	})

	// Approving applies the statements. Rejecting leaves the target alone, and
	// is therefore not gated: a request left pending when an install changed
	// edition can still be closed rather than stranded open forever.
	mux.HandleFunc("POST /api/requests/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.Promotion) {
			return
		}
		decideRequest(w, r, store, auth.RequestApproved)
	})
	mux.HandleFunc("POST /api/requests/{id}/reject", func(w http.ResponseWriter, r *http.Request) {
		decideRequest(w, r, store, auth.RequestRejected)
	})
}

// requestFor loads the request named in the path and checks the caller's level on
// its target. A request the caller cannot reach is a 404, like a branch they
// cannot reach — it says nothing about what exists.
func requestFor(w http.ResponseWriter, r *http.Request, store *auth.Store, need access.Level) (auth.ChangeRequest, bool) {
	u, _ := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, fmt.Errorf("a change request id is a positive number"))
		return auth.ChangeRequest{}, false
	}
	c, err := store.ChangeRequest(id)
	if err != nil {
		writeErr(w, 404, err)
		return auth.ChangeRequest{}, false
	}
	lvl := acl.Level(u, c.Target)
	if lvl == access.None {
		writeErr(w, 404, fmt.Errorf("no change request %d", id))
		return auth.ChangeRequest{}, false
	}
	if lvl < need {
		secLog.Audit(auth.EvDenied, u.Email, fmt.Sprintf("request #%d on %s", id, c.Target), remoteIP(r),
			r.Method+" "+r.URL.Path)
		writeErr(w, 403, fmt.Errorf("only the owner of %q or an admin may decide what is applied to it", c.Target))
		return auth.ChangeRequest{}, false
	}
	return c, true
}

// decideRequest approves or rejects a request, and applies an approved one.
//
// Both are privileged, and each writes its intent to the security log before
// it happens and its outcome after (auth.BeginPrivileged). The intents come
// before the claim, because once a request is claimed the decision is made: an
// intent that cannot be written must stop the decision, not follow it.
func decideRequest(w http.ResponseWriter, r *http.Request, store *auth.Store, decision string) {
	c, ok := requestFor(w, r, store, access.Manage)
	if !ok {
		return
	}
	u, _ := auth.UserFrom(r.Context())
	var body struct {
		Note string `json:"note"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, err)
		return
	}
	entries, err := branch.UnmarshalEntries(c.Entries)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	ip := remoteIP(r)
	decided, err := store.BeginPrivileged(auth.EvChangeDecideStarted, auth.EvChangeDecided, auth.EvChangeDecideFailed,
		u.Email, fmt.Sprintf("request #%d %s", c.ID, decision), ip, body.Note)
	if err != nil {
		writeErr(w, 503, err)
		return
	}
	var applying *auth.Privileged
	if decision == auth.RequestApproved {
		applying, err = store.BeginPrivileged(auth.EvChangeApplyStarted, auth.EvChangeApplied, auth.EvChangeApplyFailed,
			u.Email, fmt.Sprintf("request #%d: %s → %s", c.ID, c.Source, c.Target), ip, applyDetail(c, len(entries)))
		if err != nil {
			decided.Done(err, "not decided")
			writeErr(w, 503, err)
			return
		}
	}
	// One writer wins: a second approval of the same request must not apply its
	// statements twice.
	claimed, err := store.ClaimChangeRequest(c.ID, u.ID, decision, body.Note)
	if err != nil {
		decided.Done(err, "not decided")
		applying.Done(err, "not applied")
		if errors.Is(err, auth.ErrRequestDecided) {
			writeErr(w, 409, err)
			return
		}
		writeErr(w, 500, err)
		return
	}
	if decision == auth.RequestRejected {
		decided.Done(nil, body.Note)
		writeJSON(w, 200, viewOf(claimed))
		return
	}
	n, applyErr, recordErr := applyClaimed(store, claimed, u.Email)
	outcome := fmt.Sprintf("%d statement(s) applied to %s", n, c.Target)
	switch {
	case errors.Is(applyErr, branch.ErrAlreadyApplied):
		applying.Done(applyErr, "nothing run again; the target already had it")
	default:
		applying.Done(applyErr, outcome)
	}
	decided.Done(nil, outcome)
	final, err := store.ChangeRequest(c.ID)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	switch {
	case errors.Is(applyErr, branch.ErrAlreadyApplied):
		writeJSON(w, 409, map[string]any{"error": applyErr.Error(), "request": viewOf(final)})
	case applyErr != nil:
		// The decision stands and the record says it failed, so this is reported as
		// a failure to apply rather than a refusal to decide.
		writeJSON(w, 500, map[string]any{"error": applyErr.Error(), "request": viewOf(final)})
	case recordErr != nil:
		// Applied, and the store could not say so. The target's own record has
		// it, and the next request from this source reconciles from there.
		writeJSON(w, 500, map[string]any{"error": fmt.Sprintf("the request was applied to %s, but recording that here failed "+
			"(it will be reconciled from %s's own record): %v", c.Target, c.Target, recordErr), "request": viewOf(final)})
	default:
		writeJSON(w, 200, viewOf(final))
	}
}

// applyDetail is the apply intent's detail: how much, and whether rows change.
func applyDetail(c auth.ChangeRequest, n int) string {
	if c.IncludeData {
		return fmt.Sprintf("%d statement(s), including data changes", n)
	}
	return fmt.Sprintf("%d statement(s), schema only", n)
}

// statusForRequestErr maps a refusal to ask for a promotion onto a status code.
func statusForRequestErr(err error) int {
	switch {
	case errors.Is(err, branch.ErrConflict):
		return 409
	case errors.Is(err, branch.ErrBlockedByPolicy), errors.Is(err, branch.ErrNotReplayable):
		return 422
	case errors.Is(err, branch.ErrNothingToPromote):
		return 400
	case errors.Is(err, branch.ErrInvalidRequest):
		return 400
	}
	return 400
}
