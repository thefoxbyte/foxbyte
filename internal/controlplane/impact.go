// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// registerImpact mounts Blackbox impact analysis and diff (behind auth):
//
//	POST /api/branches/{name}/impact   what a change would affect ({sql} or {object, column})
//	GET  /api/ledger/diff?a=&b=        schema changes on each branch since they split
//	GET  /api/blackbox/diff?a=&b=      the same, under the Blackbox name
func registerImpact(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/branches/{name}/impact", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		var body struct {
			SQL    string `json:"sql"`
			Object string `json:"object"`
			Column string `json:"column"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		rep, err := branch.Impact(name, body.SQL, body.Object, body.Column)
		switch {
		case err == nil:
			writeJSON(w, 200, rep)
		case errors.Is(err, branch.ErrInvalidRequest):
			writeErr(w, 400, err)
		default:
			writeErr(w, 500, err)
		}
	})

	diff := func(w http.ResponseWriter, r *http.Request) {
		a, b := r.URL.Query().Get("a"), r.URL.Query().Get("b")
		if a == "" || b == "" {
			writeErr(w, 400, fmt.Errorf("query parameters a and b (branch names) are required"))
			return
		}
		for _, n := range []string{a, b} {
			if _, err := branch.EnsureRunning(n); err != nil {
				writeErr(w, 404, err)
				return
			}
		}
		d, err := branch.DiffLedgers(a, b)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, d)
	}
	mux.HandleFunc("GET /api/ledger/diff", diff)
	mux.HandleFunc("GET /api/blackbox/diff", diff)
}
