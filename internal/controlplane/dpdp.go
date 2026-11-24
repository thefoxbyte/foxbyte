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

// The DPDP personal-data inventory over HTTP (point 11.1).
//
//	GET    /api/branches/{name}/dpdp/inventory[?format=csv]          every table with confirmed personal data, what covers it, the gaps
//	PUT    /api/branches/{name}/dpdp/entries                         set an entry (Enterprise): {"schema", "table", "column"?, "basis",
//	                                                                 "purpose", "principals": [...], "keep": {"count", "unit", "from",
//	                                                                 "reason", "citation"}, "note"}
//	DELETE /api/branches/{name}/dpdp/entries?schema=&table=&column=  remove one (Enterprise); its history keeps it
//	GET    /api/branches/{name}/dpdp/history?schema=&table=[&column=] every change to a table's entries, or one column's
//
// All need Manage (needFor), as the findings do. Reading is free in every
// edition; setting and removing are not, and each is in the security log with
// the place, the basis and the retention, never the purpose or the note.
func registerDPDP(mux *http.ServeMux) {
	running := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return "", false
		}
		return name, true
	}
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, branch.ErrNoDPDPEntry):
			writeErr(w, 404, err)
		case errors.Is(err, branch.ErrInvalidRequest):
			writeErr(w, 400, err)
		case errors.Is(err, branch.ErrNotLicensed):
			writeErr(w, 403, err)
		default:
			writeErr(w, 500, err)
		}
	}
	mux.HandleFunc("GET /api/branches/{name}/dpdp/inventory", func(w http.ResponseWriter, r *http.Request) {
		name, ok := running(w, r)
		if !ok {
			return
		}
		inv, err := branch.DPDPInventoryOf(name)
		if err != nil {
			fail(w, err)
			return
		}
		switch f := r.URL.Query().Get("format"); f {
		case "", "json":
			writeJSON(w, 200, inv)
		case "csv":
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dpdp-inventory-%s.csv"`, name))
			_ = branch.WriteDPDPCSV(w, inv)
		default:
			writeErr(w, 400, fmt.Errorf("format is json or csv, not %q", f))
		}
	})
	mux.HandleFunc("PUT /api/branches/{name}/dpdp/entries", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.DPDP) {
			return
		}
		name, ok := running(w, r)
		if !ok {
			return
		}
		var e branch.DPDPEntry
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			writeErr(w, 400, fmt.Errorf(`the body must be JSON: {"schema", "table", "column", "basis", "purpose", "principals": [...], "keep": {"count", "unit", "from", "reason", "citation"}, "note"}`))
			return
		}
		u, _ := auth.UserFrom(r.Context())
		got, err := branch.SetDPDPEntry(name, e, u.Email)
		if err != nil {
			fail(w, err)
			return
		}
		if secLog != nil {
			secLog.Audit(auth.EvDPDPSet, u.Email, name, remoteIP(r), got.Summary())
		}
		writeJSON(w, 200, got)
	})
	mux.HandleFunc("DELETE /api/branches/{name}/dpdp/entries", func(w http.ResponseWriter, r *http.Request) {
		if !requireFeature(w, edition.DPDP) {
			return
		}
		name, ok := running(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		e := branch.DPDPEntry{Schema: q.Get("schema"), Table: q.Get("table"), Column: q.Get("column")}
		if e.Schema == "" || e.Table == "" {
			writeErr(w, 400, fmt.Errorf("say which entry: ?schema=…&table=…, and &column=… for a column's"))
			return
		}
		u, _ := auth.UserFrom(r.Context())
		if err := branch.RemoveDPDPEntry(name, e.Schema, e.Table, e.Column, u.Email); err != nil {
			fail(w, err)
			return
		}
		if secLog != nil {
			secLog.Audit(auth.EvDPDPRemoved, u.Email, name, remoteIP(r), e.Where())
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /api/branches/{name}/dpdp/history", func(w http.ResponseWriter, r *http.Request) {
		name, ok := running(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		if q.Get("schema") == "" || q.Get("table") == "" {
			writeErr(w, 400, fmt.Errorf("say which table: ?schema=…&table=…, and &column=… for one column"))
			return
		}
		hs, err := branch.DPDPHistory(name, q.Get("schema"), q.Get("table"), q.Get("column"))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, hs)
	})
}
