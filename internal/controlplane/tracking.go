// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Row tracking over HTTP (points 5.1, 5.2 and 6.1): who changed each row,
// whom for, and when. The rules are in internal/ledger/tracking.sql and
// internal/branch/tracking.go.
//
//	GET    /api/branches/{name}/tracking                          what is tracked (Use)
//	PUT    /api/branches/{name}/tracking/tables/{schema}/{table}  start tracking a table (Manage)
//	DELETE /api/branches/{name}/tracking/tables/{schema}/{table}  stop; the columns stay (Manage)
//	PUT    /api/branches/{name}/tracking/new                      track tables made from now on, or not (Manage)
//
// Changing a table's columns is the branch owner's decision, as realtime's
// preparation is: needFor gives every route under tracking/ Manage. Each
// change is in the security log, and the table's change in the Blackbox,
// under the person who asked.
func registerTracking(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/branches/{name}/tracking", func(w http.ResponseWriter, r *http.Request) {
		t, err := branch.TrackingOf(r.PathValue("name"))
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, t)
	})
	mux.HandleFunc("PUT /api/branches/{name}/tracking/tables/{schema}/{table}", func(w http.ResponseWriter, r *http.Request) {
		o := branch.DefaultTrackOptions
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
				writeErr(w, 400, fmt.Errorf("the body must be JSON: {\"created\", \"updated\", \"by\", \"for\", \"label_existing\"}"))
				return
			}
		}
		trackingChange(w, r, "started tracking "+r.PathValue("schema")+"."+r.PathValue("table"), func(actor string) error {
			return branch.TrackTable(r.PathValue("name"), r.PathValue("schema"), r.PathValue("table"), o, actor, "console")
		})
	})
	mux.HandleFunc("DELETE /api/branches/{name}/tracking/tables/{schema}/{table}", func(w http.ResponseWriter, r *http.Request) {
		trackingChange(w, r, "stopped tracking "+r.PathValue("schema")+"."+r.PathValue("table"), func(actor string) error {
			return branch.UntrackTable(r.PathValue("name"), r.PathValue("schema"), r.PathValue("table"), actor, "console")
		})
	})
	mux.HandleFunc("PUT /api/branches/{name}/tracking/new", func(w http.ResponseWriter, r *http.Request) {
		body := struct {
			On bool `json:"on"`
			branch.TrackOptions
		}{TrackOptions: branch.DefaultTrackOptions}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, fmt.Errorf("the body must be JSON: {\"on\": true|false, \"created\", \"updated\", \"by\", \"for\"}"))
			return
		}
		what := "new tables off"
		if body.On {
			what = "new tables on"
		}
		trackingChange(w, r, what, func(actor string) error {
			return branch.SetTrackNew(r.PathValue("name"), body.On, body.TrackOptions, actor, "console")
		})
	})
}

// trackingChange runs a change as the signed-in user, records it, and answers
// with the branch's tracking as it now is.
func trackingChange(w http.ResponseWriter, r *http.Request, what string, change func(actor string) error) {
	u, _ := auth.UserFrom(r.Context())
	name := r.PathValue("name")
	if _, err := branch.EnsureRunning(name); err != nil {
		writeErr(w, 404, err)
		return
	}
	if err := change(u.Email); err != nil {
		writeErr(w, 400, err)
		return
	}
	if secLog != nil {
		secLog.Audit(auth.EvTrackingChanged, u.Email, name, remoteIP(r), what)
	}
	t, err := branch.TrackingOf(name)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, t)
}
