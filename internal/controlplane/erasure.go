// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Erasure requests over HTTP (point 11.2, F4, Gate 1 step 1).
//
//	GET  /api/dpdp/erasures                 every request, newest first
//	GET  /api/dpdp/erasures/{id}            one, with its plan and what applying it did
//	POST /api/dpdp/erasures                 make one (Enterprise): {"values": [{"category"?, "value"}], "note"?, "events"?: {"account_closed": "YYYY-MM-DD"}}
//	POST /api/dpdp/erasures/{id}/plan       plan it again (Enterprise): {"values": [...]}
//	POST /api/dpdp/erasures/{id}/apply      apply it to main (Enterprise): {"values": [...]}; 409 with the new plan when it has changed
//	POST /api/dpdp/erasures/{id}/rewrite    rewrite the tables left for later, or {"tables": ["schema.table"]} (Enterprise)
//	POST /api/dpdp/erasures/{id}/withdraw   close a planned request (Enterprise)
//
// Admins only, reading included: a plan says where a person's data is
// (decision 10). An agent key is refused by the control plane itself, and no
// MCP tool or Agent API route reaches these: erasure is a person's decision.
// Each step is in the security log with counts, never a value.
func registerErasure(mux *http.ServeMux, store *auth.Store) {
	admin := func(w http.ResponseWriter, r *http.Request) bool {
		if !isAdmin(r) {
			writeErr(w, 403, fmt.Errorf("erasure requests are for admins"))
			return false
		}
		return true
	}
	id := func(w http.ResponseWriter, r *http.Request) (int64, bool) {
		n, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || n <= 0 {
			writeErr(w, 400, fmt.Errorf("%q is not a request's number", r.PathValue("id")))
			return 0, false
		}
		return n, true
	}
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, auth.ErrNoErasure):
			writeErr(w, 404, err)
		case errors.Is(err, branch.ErrInvalidRequest), errors.Is(err, branch.ErrErasureValues):
			writeErr(w, 400, err)
		case errors.Is(err, branch.ErrNotLicensed):
			writeErr(w, 403, err)
		case errors.Is(err, branch.ErrErasureState), errors.Is(err, branch.ErrErasureBlocked), errors.Is(err, auth.ErrErasureMoved):
			writeErr(w, 409, err)
		default:
			writeErr(w, 500, err)
		}
	}
	type valuesBody struct {
		Values []branch.ErasureValue `json:"values"`
		Note   string                `json:"note"`
		Events map[string]string     `json:"events"`
		Tables []string              `json:"tables"`
	}
	body := func(w http.ResponseWriter, r *http.Request) (valuesBody, bool) {
		var b valuesBody
		if err := decode(r, &b); err != nil {
			writeErr(w, 400, err)
			return b, false
		}
		if len(b.Values) > 50 {
			writeErr(w, 400, fmt.Errorf("at most 50 values a request"))
			return b, false
		}
		return b, true
	}
	audit := func(r *http.Request, kind, branchName, summary string) {
		if secLog != nil {
			u, _ := auth.UserFrom(r.Context())
			secLog.Audit(kind, u.Email, branchName, remoteIP(r), summary)
		}
	}

	mux.HandleFunc("GET /api/dpdp/erasures", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		vs, err := branch.ListErasures(store)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, vs)
	})
	mux.HandleFunc("GET /api/dpdp/erasures/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		n, ok := id(w, r)
		if !ok {
			return
		}
		v, err := branch.GetErasure(store, n)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("POST /api/dpdp/erasures", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) || !requireFeature(w, edition.DPDP) {
			return
		}
		b, ok := body(w, r)
		if !ok {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		v, err := branch.NewErasure(store, "main", b.Values, b.Events, b.Note, u.Email)
		if err != nil {
			fail(w, err)
			return
		}
		audit(r, auth.EvErasurePlanned, v.Branch, fmt.Sprintf("request #%d: %s", v.ID, v.Plan.Summary()))
		writeJSON(w, 201, v)
	})
	mux.HandleFunc("POST /api/dpdp/erasures/{id}/plan", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) || !requireFeature(w, edition.DPDP) {
			return
		}
		n, ok := id(w, r)
		if !ok {
			return
		}
		b, ok := body(w, r)
		if !ok {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		v, err := branch.ReplanErasure(store, n, b.Values, u.Email)
		if err != nil {
			fail(w, err)
			return
		}
		audit(r, auth.EvErasurePlanned, v.Branch, fmt.Sprintf("request #%d planned again: %s", v.ID, v.Plan.Summary()))
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("POST /api/dpdp/erasures/{id}/apply", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) || !requireFeature(w, edition.DPDP) {
			return
		}
		n, ok := id(w, r)
		if !ok {
			return
		}
		b, ok := body(w, r)
		if !ok {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		v, err := branch.ApplyErasure(store, n, b.Values, u.Email)
		if errors.Is(err, branch.ErrErasurePlanChanged) {
			audit(r, auth.EvErasurePlanned, v.Branch, fmt.Sprintf("request #%d planned again at apply: %s", v.ID, v.Plan.Summary()))
			writeJSON(w, 409, map[string]any{"error": "nothing was applied: " + err.Error() + "; review the new plan, then apply again", "request": v})
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		rows, tables := 0, 0
		if v.Result != nil {
			rows, tables = v.Result.Rows, len(v.Result.Tables)
		}
		audit(r, auth.EvErasureApplied, v.Branch, fmt.Sprintf("request #%d applied: %d row(s) changed in %d table(s)", v.ID, rows, tables))
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("POST /api/dpdp/erasures/{id}/rewrite", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) || !requireFeature(w, edition.DPDP) {
			return
		}
		n, ok := id(w, r)
		if !ok {
			return
		}
		b, ok := body(w, r)
		if !ok {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		v, err := branch.RewriteErasure(store, n, b.Tables, u.Email)
		if err != nil {
			fail(w, err)
			return
		}
		audit(r, auth.EvErasureRewritten, v.Branch, fmt.Sprintf("request #%d: %s", v.ID, strings.Join(b.Tables, ", ")))
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("POST /api/dpdp/erasures/{id}/withdraw", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) || !requireFeature(w, edition.DPDP) {
			return
		}
		n, ok := id(w, r)
		if !ok {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		v, err := branch.WithdrawErasure(store, n, u.Email)
		if err != nil {
			fail(w, err)
			return
		}
		audit(r, auth.EvErasureWithdrawn, v.Branch, fmt.Sprintf("request #%d withdrawn", v.ID))
		writeJSON(w, 200, v)
	})
}
