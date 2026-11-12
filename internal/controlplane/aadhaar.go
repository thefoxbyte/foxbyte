// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The Aadhaar exposure report over HTTP (point 4.5).
//
//	GET  /api/branches/{name}/personal-data/aadhaar          the latest run: by column, and by person
//	POST /api/branches/{name}/personal-data/aadhaar/run      read every row now, {"tableTimeout": seconds} (Enterprise)
//	GET  /api/branches/{name}/personal-data/aadhaar/places   ?person=n&column=s.t.c&gone=1&limit=200
//	GET  /api/branches/{name}/personal-data/aadhaar/log-places  ?person=n&source=history&gone=1&limit=200 (admins)
//
// Under personal-data, so Manage, as the scan is (needFor): where a person's
// Aadhaar sits is as sensitive as anything FoxByte reports. A place is a row's
// key and the number's last four digits, never the number. Each run is in the
// security log with its counts.
//
// The logs part (4.5b, {"logs": true}) is for admins only, on top of that: it
// reads everyone's query history on the branch and says who typed whose
// number. An admin's report includes it; an owner's does not.
func registerAadhaarExposure(mux *http.ServeMux) {
	// logStore is the store the logs part is kept in, for an admin; nil for
	// anyone else, whose report has no logs part.
	logStore := func(r *http.Request) *auth.Store {
		if isAdmin(r) {
			return secLog
		}
		return nil
	}
	const adminsOnly = "the Aadhaar report's logs part is for admins only: it says who typed whose number"
	running := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return "", false
		}
		return name, true
	}
	fail := func(w http.ResponseWriter, err error) {
		if errors.Is(err, branch.ErrInvalidRequest) {
			writeErr(w, 400, err)
			return
		}
		writeErr(w, 500, err)
	}
	mux.HandleFunc("GET /api/branches/{name}/personal-data/aadhaar", func(w http.ResponseWriter, r *http.Request) {
		name, ok := running(w, r)
		if !ok {
			return
		}
		rep, err := branch.AadhaarExposureFor(name, logStore(r))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, rep)
	})
	mux.HandleFunc("POST /api/branches/{name}/personal-data/aadhaar/run", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.PersonalData) {
			return
		}
		var body struct {
			TableTimeout int  `json:"tableTimeout"` // seconds
			Logs         bool `json:"logs"`
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, 400, fmt.Errorf("the body must be JSON: {\"tableTimeout\": seconds a table's read may take, \"logs\": true to read the logs too}"))
				return
			}
		}
		o, err := branch.CheckAadhaarRunOptions(branch.AadhaarRunOptions{TableTimeout: time.Duration(body.TableTimeout) * time.Second, Logs: body.Logs})
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		if o.Logs && !isAdmin(r) {
			writeErr(w, 403, errors.New(adminsOnly))
			return
		}
		o.Store = logStore(r)
		name, ok := running(w, r)
		if !ok {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		o.Actor = u.Email
		rep, err := branch.RunAadhaarExposure(name, o)
		if err != nil {
			fail(w, err)
			return
		}
		if secLog != nil {
			secLog.Audit(auth.EvAadhaarExposure, u.Email, name, remoteIP(r), rep.Summary())
		}
		writeJSON(w, 200, rep)
	})
	mux.HandleFunc("GET /api/branches/{name}/personal-data/aadhaar/places", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var f branch.AadhaarPlaceFilter
		for _, x := range []struct {
			key string
			to  *int
		}{{"person", &f.Person}, {"limit", &f.Limit}} {
			if v := q.Get(x.key); v != "" {
				n, err := strconv.Atoi(v)
				if err != nil || n < 0 {
					writeErr(w, 400, fmt.Errorf("%s is a number, not %q", x.key, v))
					return
				}
				*x.to = n
			}
		}
		if c := q.Get("column"); c != "" {
			where, err := branch.ParseAadhaarWhere(c)
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			f.Where = where
		}
		f.Gone = q.Get("gone") == "1" || q.Get("gone") == "true"
		name, ok := running(w, r)
		if !ok {
			return
		}
		ps, err := branch.AadhaarPlaces(name, f)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"branch": name, "places": ps})
	})
	mux.HandleFunc("GET /api/branches/{name}/personal-data/aadhaar/log-places", func(w http.ResponseWriter, r *http.Request) {
		st := logStore(r)
		if st == nil {
			writeErr(w, 403, errors.New(adminsOnly))
			return
		}
		q := r.URL.Query()
		f := auth.AadhaarLogFilter{Source: q.Get("source"), Gone: q.Get("gone") == "1" || q.Get("gone") == "true"}
		for _, x := range []struct {
			key string
			to  *int
		}{{"person", &f.Person}, {"limit", &f.Limit}} {
			if v := q.Get(x.key); v != "" {
				n, err := strconv.Atoi(v)
				if err != nil || n < 0 {
					writeErr(w, 400, fmt.Errorf("%s is a number, not %q", x.key, v))
					return
				}
				*x.to = n
			}
		}
		name, ok := running(w, r)
		if !ok {
			return
		}
		ps, err := branch.AadhaarLogPlaces(name, st, f)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"branch": name, "places": ps})
	})
}
