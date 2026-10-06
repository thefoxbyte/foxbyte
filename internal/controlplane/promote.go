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
// statements it holds, decoded.
type requestView struct {
	auth.ChangeRequest
	Entries []branch.RequestEntry `json:"entries"`
}

func viewOf(c auth.ChangeRequest) requestView {
	entries, _ := branch.UnmarshalEntries(c.Entries)
	c.Entries = "" // it is in Entries below, decoded; sending both is noise
	return requestView{ChangeRequest: c, Entries: entries}
}

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
		history, err := store.ApprovedRequestsFrom(source, target)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		entries, forkAfter, err := branch.BuildRequest(source, target, history)
		if err != nil {
			writeErr(w, statusForRequestErr(err), err)
			return
		}
		snapshot, err := branch.MarshalEntries(entries)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		c, err := store.CreateChangeRequest(u.ID, source, target, forkAfter, snapshot)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		store.Audit(auth.EvChangeRequested, u.Email, fmt.Sprintf("request #%d: %s → %s", c.ID, source, target),
			remoteIP(r), fmt.Sprintf("%d statement(s)", len(entries)))
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
	// One writer wins: a second approval of the same request must not apply its
	// statements twice.
	claimed, err := store.ClaimChangeRequest(c.ID, u.ID, decision, body.Note)
	if err != nil {
		if errors.Is(err, auth.ErrRequestDecided) {
			writeErr(w, 409, err)
			return
		}
		writeErr(w, 500, err)
		return
	}
	if decision == auth.RequestRejected {
		store.Audit(auth.EvChangeDecided, u.Email, fmt.Sprintf("request #%d rejected", c.ID), remoteIP(r), body.Note)
		writeJSON(w, 200, viewOf(claimed))
		return
	}
	n, applyErr := branch.ApplyRequest(c.ID, c.Target, u.Email, entries)
	failure := ""
	if applyErr != nil {
		failure = applyErr.Error()
	}
	if err := store.FinishChangeRequest(c.ID, n, failure); err != nil {
		writeErr(w, 500, err)
		return
	}
	store.Audit(auth.EvChangeDecided, u.Email, fmt.Sprintf("request #%d approved", c.ID), remoteIP(r),
		fmt.Sprintf("%d statement(s) applied to %s", n, c.Target))
	final, err := store.ChangeRequest(c.ID)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if applyErr != nil {
		// The decision stands and the record says it failed, so this is reported as
		// a failure to apply rather than a refusal to decide.
		writeJSON(w, 500, map[string]any{"error": applyErr.Error(), "request": viewOf(final)})
		return
	}
	writeJSON(w, 200, viewOf(final))
}

// statusForRequestErr maps a refusal to ask for a promotion onto a status code.
func statusForRequestErr(err error) int {
	switch {
	case errors.Is(err, branch.ErrConflict):
		return 409
	case errors.Is(err, branch.ErrBlockedByPolicy):
		return 422
	case errors.Is(err, branch.ErrNothingToPromote):
		return 400
	case errors.Is(err, branch.ErrInvalidRequest):
		return 400
	}
	return 400
}
