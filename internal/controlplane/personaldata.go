// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Personal-data discovery over HTTP (point 4.1).
//
//	GET  /api/branches/{name}/personal-data                         the latest scan and every finding
//	POST /api/branches/{name}/personal-data/scan                    scan now, {"sample": rows per table} (Enterprise)
//	GET  /api/branches/{name}/personal-data/findings/{id}           one finding and every decision on it
//	POST /api/branches/{name}/personal-data/findings/{id}/mark      decide, {"state": confirmed|rejected|suggested, "note"} (Enterprise)
//	GET  /api/branches/{name}/personal-data/findings/{id}/samples   masked samples, ?n=5, read as the caller's own role (Enterprise)
//	GET  /api/branches/{name}/personal-data/unclassified            what appeared since the first scan, not yet reviewed
//	POST /api/branches/{name}/personal-data/columns/{id}/accept     a new column or path holds nothing to classify, {"note"} (Enterprise)
//
// All need Manage (needFor): a list of where personal data sits is itself
// sensitive. Reading is free in every edition; scanning, deciding and reading
// samples are not. Each scan, decision and view of samples is in the security
// log, with a location and never a value.
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
			Sample  int  `json:"sample"`
			NewOnly bool `json:"newOnly"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, 400, fmt.Errorf("the body must be JSON: {\"sample\": rows per table, \"newOnly\": true|false}"))
				return
			}
		}
		o, err := branch.CheckPIIScanOptions(branch.PIIScanOptions{Sample: body.Sample, NewOnly: body.NewOnly})
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

// registerPersonalDataReview mounts review (point 4.6).
func registerPersonalDataReview(mux *http.ServeMux) {
	finding := func(w http.ResponseWriter, r *http.Request) (string, int64, bool) {
		name := r.PathValue("name")
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id < 1 {
			writeErr(w, 400, fmt.Errorf("a finding is named by its number, not %q", r.PathValue("id")))
			return "", 0, false
		}
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return "", 0, false
		}
		return name, id, true
	}
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, branch.ErrNoFinding):
			writeErr(w, 404, err)
		case errors.Is(err, branch.ErrInvalidRequest):
			writeErr(w, 400, err)
		case errors.Is(err, branch.ErrCannotReadLocation):
			writeErr(w, 403, err)
		default:
			writeErr(w, 500, err)
		}
	}
	mux.HandleFunc("GET /api/branches/{name}/personal-data/findings/{id}", func(w http.ResponseWriter, r *http.Request) {
		name, id, ok := finding(w, r)
		if !ok {
			return
		}
		d, err := branch.PersonalDataFinding(name, id)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, d)
	})
	mux.HandleFunc("POST /api/branches/{name}/personal-data/findings/{id}/mark", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.PersonalData) {
			return
		}
		name, id, ok := finding(w, r)
		if !ok {
			return
		}
		var body struct {
			State string `json:"state"`
			Note  string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, fmt.Errorf("the body must be JSON: {\"state\": \"confirmed\"|\"rejected\"|\"suggested\", \"note\": \"…\"}"))
			return
		}
		u, _ := auth.UserFrom(r.Context())
		d, err := branch.MarkPersonalData(name, id, body.State, body.Note, u.Email)
		if err != nil {
			fail(w, err)
			return
		}
		if secLog != nil {
			secLog.Audit(auth.EvPersonalDataMarked, u.Email, name, remoteIP(r), d.Finding.MarkSummary())
		}
		writeJSON(w, 200, d)
	})
	mux.HandleFunc("GET /api/branches/{name}/personal-data/findings/{id}/samples", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.PersonalData) {
			return
		}
		name, id, ok := finding(w, r)
		if !ok {
			return
		}
		n := 0
		if v := r.URL.Query().Get("n"); v != "" {
			var err error
			if n, err = strconv.Atoi(v); err != nil {
				writeErr(w, 400, fmt.Errorf("n is a number of samples, not %q", v))
				return
			}
		}
		u, _ := auth.UserFrom(r.Context())
		ss, err := branch.PersonalDataSamples(name, id, n, u.Email)
		if err != nil {
			fail(w, err)
			return
		}
		if secLog != nil {
			secLog.Audit(auth.EvPersonalDataSampled, u.Email, name, remoteIP(r), ss.Summary())
		}
		writeJSON(w, 200, ss)
	})
}

// registerPersonalDataInventory mounts keeping it current (point 4.7).
func registerPersonalDataInventory(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/branches/{name}/personal-data/unclassified", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		cs, err := branch.PersonalDataUnclassified(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"branch": name, "columns": cs})
	})
	mux.HandleFunc("POST /api/branches/{name}/personal-data/columns/{id}/accept", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.PersonalData) {
			return
		}
		name := r.PathValue("name")
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id < 1 {
			writeErr(w, 400, fmt.Errorf("a column is named by its number, not %q", r.PathValue("id")))
			return
		}
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		var body struct {
			Note string `json:"note"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, 400, fmt.Errorf("the body must be JSON: {\"note\": \"…\"}"))
				return
			}
		}
		u, _ := auth.UserFrom(r.Context())
		c, err := branch.AcceptPersonalData(name, id, body.Note, u.Email)
		switch {
		case err == nil:
		case errors.Is(err, branch.ErrNoColumn):
			writeErr(w, 404, err)
			return
		case errors.Is(err, branch.ErrUndecided):
			writeErr(w, 409, err)
			return
		case errors.Is(err, branch.ErrInvalidRequest):
			writeErr(w, 400, err)
			return
		default:
			writeErr(w, 500, err)
			return
		}
		if secLog != nil {
			secLog.Audit(auth.EvPersonalDataAccepted, u.Email, name, remoteIP(r), c.AcceptSummary())
		}
		writeJSON(w, 200, c)
	})
}
