// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Sessions and maintenance (point 12.5). The branch's owner and an admin see
// and signal every client session on it; anyone else who may use it, their
// own and their agent keys': another account's statements can hold values
// that are not theirs to read. Vacuum and analyse are the owner's, as other
// changes to how a branch runs are (authz.go); a table's upkeep is anyone's.
func registerSessions(mux *http.ServeMux) {
	mine := func(r *http.Request, name string) (auth.User, string) {
		u, _ := auth.UserFrom(r.Context())
		if acl.Level(u, name) >= access.Manage {
			return u, ""
		}
		return u, u.Email
	}
	mux.HandleFunc("GET /api/branches/{name}/sessions", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		_, only := mine(r, name)
		ss, err := branch.Sessions(name)
		if err != nil {
			sessionFail(w, err)
			return
		}
		out := []branch.Session{}
		for _, s := range ss {
			if only == "" || branch.SessionOf(s.User, only) {
				out = append(out, s)
			}
		}
		writeJSON(w, 200, map[string]any{"branch": name, "all": only == "", "sessions": out})
	})
	signal := func(end bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			pid, err := branch.ParsePID(r.PathValue("pid"))
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			u, only := mine(r, name)
			s, err := branch.SignalSession(name, pid, end, only)
			if err != nil {
				sessionFail(w, err)
				return
			}
			kind, what := auth.EvSessionCancel, "cancelled the query of"
			if end {
				kind, what = auth.EvSessionEnd, "ended"
			}
			secLog.Audit(kind, u.Email, name, remoteIP(r), fmt.Sprintf("%s session %d (%s)", what, pid, s.User))
			writeJSON(w, 200, map[string]any{"branch": name, "pid": pid, "user": s.User, "ended": end})
		}
	}
	mux.HandleFunc("POST /api/branches/{name}/sessions/{pid}/cancel", signal(false))
	mux.HandleFunc("POST /api/branches/{name}/sessions/{pid}/end", signal(true))

	mux.HandleFunc("GET /api/branches/{name}/maintenance", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ts, err := branch.TablesStats(r.PathValue("name"), q.Get("schema"), q.Get("table"))
		if err != nil {
			sessionFail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"branch": r.PathValue("name"), "tables": ts})
	})
	mux.HandleFunc("POST /api/branches/{name}/maintenance", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Schema string `json:"schema"`
			Table  string `json:"table"`
			Op     string `json:"op"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&b); err != nil || b.Table == "" {
			writeErr(w, 400, errors.New(`the body is {"schema", "table", "op": "vacuum" | "analyze" | "vacuum-analyze"}`))
			return
		}
		name := r.PathValue("name")
		u, _ := auth.UserFrom(r.Context())
		t, took, err := branch.Maintain(name, b.Schema, b.Table, b.Op)
		if err != nil {
			sessionFail(w, err)
			return
		}
		secLog.Audit(auth.EvMaintenance, u.Email, name, remoteIP(r), fmt.Sprintf("%s of %s.%s", b.Op, t.Schema, t.Table))
		writeJSON(w, 200, map[string]any{"branch": name, "op": b.Op, "ms": took.Milliseconds(), "table": t})
	})
}

func sessionFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, branch.ErrNotFound):
		writeErr(w, 404, err)
	case errors.Is(err, branch.ErrInvalidRequest), errors.Is(err, branch.ErrBadName):
		writeErr(w, 400, err)
	case errors.Is(err, branch.ErrBranchClosed):
		writeErr(w, 423, err)
	default:
		writeErr(w, 500, err)
	}
}
