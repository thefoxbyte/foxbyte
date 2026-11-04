// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// The hardening report over HTTP (point 3.2).
//
//	GET /api/hardening?branch=main   the report, as JSON
//
// Admins only: it lists a database's roles, its pg_hba.conf rules and the
// install's weak points. In every edition. Each report produced is in the
// security log.
func registerHardening(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/hardening", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may produce the hardening report"))
			return
		}
		name := r.URL.Query().Get("branch")
		if name == "" {
			name = "main"
		}
		rep, err := branch.ProduceHardening(name)
		switch {
		case err == nil:
		case errors.Is(err, branch.ErrInvalidRequest), errors.Is(err, branch.ErrBadName):
			writeErr(w, 400, err)
			return
		default:
			writeErr(w, 500, err)
			return
		}
		if secLog != nil {
			u, _ := auth.UserFrom(r.Context())
			secLog.Audit(auth.EvHardeningReported, u.Email, name, remoteIP(r), rep.LogLine())
		}
		writeJSON(w, 200, rep)
	})
}
