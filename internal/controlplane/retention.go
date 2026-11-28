// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// registerRetention serves retention acted on (point 11.3), admins only:
// reading it is free; turning it on, naming a date column, arming and
// running are Enterprise (the dpdp feature). Disarming and turning off are
// free: stopping is never paid.
func registerRetention(mux *http.ServeMux, store *auth.Store) {
	admin := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if !isAdmin(r) {
			writeErr(w, 403, fmt.Errorf("retention is for admins"))
			return "", false
		}
		u, _ := auth.UserFrom(r.Context())
		return u.Email, true
	}
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, branch.ErrInvalidRequest):
			writeErr(w, 400, err)
		case errors.Is(err, branch.ErrNotLicensed):
			writeErr(w, 403, err)
		case errors.Is(err, branch.ErrRetentionOff), errors.Is(err, branch.ErrErasureBlocked):
			writeErr(w, 409, err)
		default:
			writeErr(w, 500, err)
		}
	}
	mux.HandleFunc("GET /api/dpdp/retention", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := admin(w, r); !ok {
			return
		}
		st, err := branch.GetRetentionStatus(store)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, st)
	})
	// {on: true, notify} turns it on, and answers with the signing secret,
	// shown this once; {on: false} turns it off.
	mux.HandleFunc("POST /api/dpdp/retention", func(w http.ResponseWriter, r *http.Request) {
		by, ok := admin(w, r)
		if !ok {
			return
		}
		var b struct {
			On     bool   `json:"on"`
			Notify string `json:"notify"`
		}
		if err := decode(r, &b); err != nil {
			writeErr(w, 400, err)
			return
		}
		if !b.On {
			if err := branch.SetRetentionOff(store, by); err != nil {
				fail(w, err)
				return
			}
			writeJSON(w, 200, map[string]any{"on": false})
			return
		}
		secret, err := branch.SetRetentionOn(store, b.Notify, by)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"on": true, "secret": secret, "header": branch.NoticeSignature})
	})
	mux.HandleFunc("POST /api/dpdp/retention/tables/{table}/column", func(w http.ResponseWriter, r *http.Request) {
		by, ok := admin(w, r)
		if !ok {
			return
		}
		var b struct {
			Column string `json:"column"`
		}
		if err := decode(r, &b); err != nil {
			writeErr(w, 400, err)
			return
		}
		d, err := branch.SetRetentionColumn(store, r.PathValue("table"), b.Column, by)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, d)
	})
	mux.HandleFunc("GET /api/dpdp/retention/tables/{table}/preview", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := admin(w, r); !ok {
			return
		}
		d, err := branch.RetentionPreview(store, r.PathValue("table"))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, d)
	})
	mux.HandleFunc("POST /api/dpdp/retention/tables/{table}/arm", func(w http.ResponseWriter, r *http.Request) {
		by, ok := admin(w, r)
		if !ok {
			return
		}
		var b struct {
			Reason string `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			writeErr(w, 400, err)
			return
		}
		d, err := branch.ArmRetention(store, r.PathValue("table"), by, b.Reason)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, d)
	})
	mux.HandleFunc("POST /api/dpdp/retention/tables/{table}/disarm", func(w http.ResponseWriter, r *http.Request) {
		by, ok := admin(w, r)
		if !ok {
			return
		}
		if err := branch.DisarmRetention(store, r.PathValue("table"), by); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"armed": false})
	})
	mux.HandleFunc("POST /api/dpdp/retention/run", func(w http.ResponseWriter, r *http.Request) {
		by, ok := admin(w, r)
		if !ok {
			return
		}
		run, err := branch.RunRetention(store, by)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, run)
	})
	mux.HandleFunc("GET /api/dpdp/retention/notices", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := admin(w, r); !ok {
			return
		}
		schema, table := "", ""
		if t := r.URL.Query().Get("table"); t != "" {
			s, tb, _, err := branch.SplitDPDPPlace(t)
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			schema, table = s, tb
		}
		ns, err := store.RetentionNotices(schema, table, r.URL.Query().Get("open") == "1", 500)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, ns)
	})
}
