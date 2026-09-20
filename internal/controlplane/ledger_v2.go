// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/foxbyte/foxbyte/internal/branch"
)

// registerLedgerV2 mounts the Blackbox 2.0 endpoints (behind auth):
//
//	GET  /api/branches/{name}/ledger/integrity   check the ledger against its anchors
//	POST /api/branches/{name}/ledger/checkpoint  anchor new entries now
//	GET  /api/branches/{name}/ledger/export      every entry as JSON lines
//	GET  /api/branches/{name}/ledger/entries     newest entries with their ids
//	GET  /api/branches/{name}/ledger/sessions    agent sessions (provenance)
//	POST /api/branches/{name}/ledger/{id}/branch a new branch as of just before entry {id}
func registerLedgerV2(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/branches/{name}/ledger/integrity", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		rep, err := branch.Integrity(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, rep)
	})

	mux.HandleFunc("POST /api/branches/{name}/ledger/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		a, path, err := branch.Checkpoint(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if a == nil {
			writeJSON(w, 200, map[string]any{"checkpoint": nil, "status": "nothing new"})
			return
		}
		writeJSON(w, 201, map[string]any{"checkpoint": a, "anchor_path": path, "status": "created"})
	})

	// Newest ledger entries with their ids (the existing /ledger view has none).
	mux.HandleFunc("GET /api/branches/{name}/ledger/entries", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		entries, err := branch.LedgerEntries(name, limit)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, entries)
	})

	// Agent sessions (Blackbox provenance): agent, task, parent session, entries.
	mux.HandleFunc("GET /api/branches/{name}/ledger/sessions", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		ss, err := branch.AgentSessions(name, limit)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, ss)
	})

	// Branch from just before a ledger entry. Synchronous: it returns once the
	// restore has finished and the branch is serving (typically a few minutes).
	mux.HandleFunc("POST /api/branches/{name}/ledger/{id}/branch", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			writeErr(w, 400, fmt.Errorf("entry id must be a positive ledger id"))
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		res, err := branch.BranchBeforeEntry(r.PathValue("name"), id, body.Name, nil)
		switch {
		case err == nil:
			writeJSON(w, 201, res)
		case errors.Is(err, branch.ErrInvalidRequest):
			writeErr(w, 400, err)
		case errors.Is(err, branch.ErrEntryNotFound):
			writeErr(w, 404, err)
		case errors.Is(err, branch.ErrBranchExists):
			writeErr(w, 409, err)
		case errors.Is(err, branch.ErrNoBaseBackup):
			writeErr(w, 422, err)
		default:
			writeErr(w, 500, err)
		}
	})

	mux.HandleFunc("GET /api/branches/{name}/ledger/export", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`-ledger.jsonl"`)
		if err := branch.ExportLedger(name, w); err != nil {
			// Headers may be out already; the truncated body plus the log is all we can do.
			http.Error(w, err.Error(), 500)
		}
	})
}
