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

// Fixes and profiles (points 3.3, 3.4), Enterprise, admins only:
//
//	POST /api/hardening/fix      {"branch", "check", "apply"}    the preview, or with apply the fix and the check again
//	POST /api/hardening/profile  {"branch", "profile", "apply"}  every fix a profile makes, and what it leaves to a person
//
// Each fix and profile applied is in the security log.
func registerHardeningFixes(mux *http.ServeMux) {
	type body struct {
		Branch  string `json:"branch"`
		Check   string `json:"check"`
		Profile string `json:"profile"`
		Apply   bool   `json:"apply"`
	}
	read := func(w http.ResponseWriter, r *http.Request) (body, bool) {
		var b body
		if !requireFeature(w, edition.Hardening) {
			return b, false
		}
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may change a database's hardening"))
			return b, false
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&b); err != nil {
			writeErr(w, 400, errors.New(`the body must be JSON: {"branch": "main", "check"|"profile": "…", "apply": true|false}`))
			return b, false
		}
		if b.Branch == "" {
			b.Branch = "main"
		}
		return b, true
	}
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, branch.ErrInvalidRequest), errors.Is(err, branch.ErrBadName), errors.Is(err, branch.ErrNoHardeningFix):
			writeErr(w, 400, err)
		default:
			writeErr(w, 500, err)
		}
	}
	record := func(r *http.Request, kind, b, detail string) {
		if secLog != nil {
			u, _ := auth.UserFrom(r.Context())
			secLog.Audit(kind, u.Email, b, remoteIP(r), detail)
		}
	}
	mux.HandleFunc("POST /api/hardening/fix", func(w http.ResponseWriter, r *http.Request) {
		b, ok := read(w, r)
		if !ok {
			return
		}
		if !b.Apply {
			f, err := branch.PlanHardeningFix(b.Branch, b.Check)
			if err != nil {
				fail(w, err)
				return
			}
			writeJSON(w, 200, map[string]any{"fix": f})
			return
		}
		u, _ := auth.UserFrom(r.Context())
		res, err := branch.ApplyHardeningFix(b.Branch, b.Check, u.Email)
		if err != nil {
			fail(w, err)
			return
		}
		record(r, auth.EvHardeningFixed, b.Branch, res.FixLogLine())
		writeJSON(w, 200, map[string]any{"result": res})
	})
	mux.HandleFunc("POST /api/hardening/profile", func(w http.ResponseWriter, r *http.Request) {
		b, ok := read(w, r)
		if !ok {
			return
		}
		if !b.Apply {
			fixes, manual, err := branch.PlanHardeningProfile(b.Branch, b.Profile)
			if err != nil {
				fail(w, err)
				return
			}
			if fixes == nil {
				fixes = []branch.HardeningFix{}
			}
			if manual == nil {
				manual = []branch.HardeningCheck{}
			}
			writeJSON(w, 200, map[string]any{"fixes": fixes, "manual": manual})
			return
		}
		u, _ := auth.UserFrom(r.Context())
		results, err := branch.ApplyHardeningProfile(b.Branch, b.Profile, u.Email)
		failed := 0
		for _, res := range results {
			record(r, auth.EvHardeningFixed, b.Branch, res.FixLogLine())
			if res.Error != "" {
				failed++
			}
		}
		if err != nil {
			fail(w, err)
			return
		}
		record(r, auth.EvHardeningProfile, b.Branch, fmt.Sprintf("profile %s on %s: %d fix(es) made, %d did not hold", b.Profile, b.Branch, len(results)-failed, failed))
		if results == nil {
			results = []branch.HardeningFixResult{}
		}
		writeJSON(w, 200, map[string]any{"results": results})
	})
}
