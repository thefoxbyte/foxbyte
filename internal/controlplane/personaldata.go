// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Personal-data discovery over HTTP (point 4.1).
//
//	GET  /api/branches/{name}/personal-data        the latest scan and every finding (Manage)
//	POST /api/branches/{name}/personal-data/scan   scan now, {"sample": rows per table} (Manage, Enterprise)
//
// Both need Manage (needFor): a list of where personal data sits is itself
// sensitive. Reading is free in every edition, scanning is not. A scan is in the
// security log, with how much it covered and never a value.
func registerPersonalData(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/branches/{name}/personal-data", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		rep, err := branch.PersonalDataFindings(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, rep)
	})
	mux.HandleFunc("POST /api/branches/{name}/personal-data/scan", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.PersonalData) {
			return
		}
		name := r.PathValue("name")
		var body struct {
			Sample int `json:"sample"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, 400, fmt.Errorf("the body must be JSON: {\"sample\": rows per table}"))
				return
			}
		}
		o, err := branch.CheckPIIScanOptions(branch.PIIScanOptions{Sample: body.Sample})
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		u, _ := auth.UserFrom(r.Context())
		o.Actor = u.Email
		rep, err := branch.ScanPersonalData(name, o)
		switch {
		case err == nil:
		case errors.Is(err, branch.ErrInvalidRequest):
			writeErr(w, 400, err)
			return
		default:
			writeErr(w, 500, err)
			return
		}
		if secLog != nil {
			secLog.Audit(auth.EvPersonalDataScanned, u.Email, name, remoteIP(r), rep.Summary())
		}
		writeJSON(w, 200, rep)
	})
}
