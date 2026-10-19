// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// Query history over HTTP (points 8.1, 8.3). The rules are internal/auth's
// (history.go); this file records what the console and the API run, and serves
// each caller their own history and the switches.
//
// Recording never fails a query: history is a convenience for the person who
// ran it, and a store that is briefly busy must not turn a good query into an
// error. It is logged instead.

// recordQuery keeps one statement in its runner's history.
func recordQuery(e auth.HistoryEntry) {
	if secLog == nil {
		return
	}
	if _, err := secLog.RecordQuery(e); err != nil {
		log.Printf("query history for %s on %s: %v", e.Actor, e.Branch, err)
	}
}

// queryOutcome reads runQuery's answer for history: the rows returned across
// every statement, and the error if there was one. Rows only as a count.
func queryOutcome(m map[string]any) (rows int64, errText string) {
	if rs, ok := m["results"].([]map[string]any); ok && len(rs) > 0 {
		for _, r := range rs {
			if v, ok := r["rows"].([][]any); ok {
				rows += int64(len(v))
			}
			if e, _ := r["error"].(string); e != "" && errText == "" {
				errText = e
			}
		}
	} else if v, ok := m["rows"].([][]any); ok {
		rows = int64(len(v))
	}
	if e, _ := m["error"].(string); e != "" {
		errText = e
	}
	return rows, errText
}

// RecordCLIQuery keeps a statement run at the command line (`fox sql`,
// `fox export`) in the history of whoever is at the machine.
func RecordCLIQuery(store *auth.Store, actor, branchName, sql, kind string, start time.Time, rows int64, err error) {
	if store == nil {
		return
	}
	e := auth.HistoryEntry{Actor: actor, Branch: branchName, Source: "cli", Kind: kind, SQL: sql,
		At: start.UnixMilli(), DurationMS: time.Since(start).Milliseconds(), Rows: rows, OK: err == nil}
	if err != nil {
		e.Error = err.Error()
	}
	if _, rerr := store.RecordQuery(e); rerr != nil {
		log.Printf("query history: %v", rerr)
	}
}

// registerHistory mounts the caller's own history and the switches:
//
//	GET    /api/history               your entries, newest first (?branch, ?limit, ?before)
//	DELETE /api/history               delete all of yours
//	DELETE /api/history/{id}          delete one of yours
//	GET    /api/history/settings      the install's settings, yours, and how many you have
//	PUT    /api/history/settings      {"mine": bool} for you; {"enabled", "retention_days"} for admins
//
// There is no route to read or delete somebody else's history, admins
// included: that is `fox history --user` at the machine, recorded in the
// security log.
func registerHistory(mux *http.ServeMux, store *auth.Store) {
	mux.HandleFunc("GET /api/history", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		q := auth.HistoryQuery{Branch: r.URL.Query().Get("branch")}
		q.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
		q.Before, _ = strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
		h, err := store.History(u.Email, q)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"entries": h})
	})
	mux.HandleFunc("DELETE /api/history", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		n, err := store.PurgeHistory(u.Email)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		store.Audit(auth.EvHistoryPurged, u.Email, u.Email, remoteIP(r), fmt.Sprintf("%d entries, their own", n))
		writeJSON(w, 200, map[string]any{"deleted": n})
	})
	mux.HandleFunc("DELETE /api/history/{id}", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeErr(w, 400, fmt.Errorf("id must be a number"))
			return
		}
		ok, err := store.DeleteHistoryEntry(u.Email, id)
		switch {
		case err != nil:
			writeErr(w, 500, err)
		case !ok:
			writeErr(w, 404, fmt.Errorf("no such entry in your history"))
		default:
			w.WriteHeader(204)
		}
	})
	mux.HandleFunc("GET /api/history/settings", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		writeHistorySettings(w, r, store, u)
	})
	mux.HandleFunc("PUT /api/history/settings", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		var body struct {
			Mine          *bool `json:"mine"`
			Enabled       *bool `json:"enabled"`
			RetentionDays *int  `json:"retention_days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, fmt.Errorf("the body must be JSON"))
			return
		}
		if (body.Enabled != nil || body.RetentionDays != nil) && !isAdmin(r) {
			writeErr(w, 403, fmt.Errorf("only an admin can change the install's history settings"))
			return
		}
		if body.Mine != nil {
			if err := store.SetHistoryOptOut(u.Email, !*body.Mine); err != nil {
				writeErr(w, 500, err)
				return
			}
		}
		if body.Enabled != nil {
			if err := store.SetHistoryEnabled(*body.Enabled); err != nil {
				writeErr(w, 500, err)
				return
			}
			store.Audit(auth.EvHistorySettings, u.Email, "", remoteIP(r), "history "+onOff(*body.Enabled))
		}
		if body.RetentionDays != nil {
			if err := store.SetHistoryRetention(*body.RetentionDays); err != nil {
				writeErr(w, 400, err)
				return
			}
			store.Audit(auth.EvHistorySettings, u.Email, "", remoteIP(r), fmt.Sprintf("retention %d days", *body.RetentionDays))
		}
		writeHistorySettings(w, r, store, u)
	})
}

func writeHistorySettings(w http.ResponseWriter, r *http.Request, store *auth.Store, u auth.User) {
	set, err := store.HistorySettings()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	n, _ := store.HistoryCount(u.Email)
	writeJSON(w, 200, map[string]any{
		"enabled": set.Enabled, "retention_days": set.RetentionDays,
		"mine": !store.HistoryOptedOut(u.Email), "count": n, "admin": isAdmin(r),
	})
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
