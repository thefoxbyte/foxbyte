// SPDX-License-Identifier: AGPL-3.0-or-later

// Package agentapi exposes the Agent Branch API: a small HTTP service that
// gives each AI agent its own instant, isolated database branch. All /agents
// routes require authentication (an API key).
//
//	POST   /agents/{id}/branch   -> create a branch for the agent, return a DSN
//	                                (optional body {task_id, parent_session_id, session_id}
//	                                records Blackbox provenance for the agent's changes)
//	DELETE /agents/{id}/branch   -> tear the agent's branch down
//	GET    /agents               -> list active agent branches
//	GET    /healthz              -> liveness (public)
package agentapi

import (
	"encoding/json"
	"errors"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/tlsutil"
)

// agentTTL is how long an agent branch may live before the reaper removes it
// (FOX_AGENT_TTL, e.g. "30m"; unset/0 disables reaping).
func agentTTL() time.Duration {
	if v := brand.Getenv("AGENT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 0
}

// reapLoop periodically deletes agent branches past their TTL, so abandoned
// sandboxes don't accumulate and hold pool space.
func reapLoop(ttl time.Duration) {
	interval := ttl / 4
	if interval < time.Minute {
		interval = time.Minute
	}
	if interval > 15*time.Minute {
		interval = 15 * time.Minute
	}
	for {
		time.Sleep(interval)
		if n, err := branch.ReapAgentBranches(ttl); err == nil && n > 0 {
			log.Printf("reaped %d expired agent branch(es)", n)
		}
	}
}

// Serve starts the Agent Branch API on addr (e.g. ":8088").
func Serve(addr string) error {
	store, err := auth.OpenFromEnv()
	if err != nil {
		return err
	}

	if ttl := agentTTL(); ttl > 0 {
		go reapLoop(ttl)
		log.Printf("agent branch TTL enabled: reaping branches older than %s", ttl)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	agents := http.NewServeMux()
	agents.HandleFunc("GET /agents", func(w http.ResponseWriter, r *http.Request) {
		infos, err := branch.ListAgentBranches()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if infos == nil {
			infos = []branch.Info{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"agents": infos})
	})
	agents.HandleFunc("POST /agents/{id}/branch", func(w http.ResponseWriter, r *http.Request) {
		// The body is optional. Without provenance the request takes exactly the
		// original path and returns the original response.
		var p branch.Provenance
		_ = json.NewDecoder(r.Body).Decode(&p)
		if !p.Requested() {
			info, err := branch.CreateAgentBranch(r.PathValue("id"))
			if err != nil {
				writeErr(w, http.StatusConflict, err)
				return
			}
			writeJSON(w, http.StatusCreated, info)
			return
		}
		info, s, err := branch.CreateAgentBranchWithProvenance(r.PathValue("id"), p)
		if err != nil {
			code := http.StatusConflict
			if errors.Is(err, branch.ErrInvalidRequest) {
				code = http.StatusBadRequest
			}
			writeErr(w, code, err)
			return
		}
		writeJSON(w, http.StatusCreated, struct {
			branch.Info
			SessionID       string `json:"session_id"`
			TaskID          string `json:"task_id,omitempty"`
			ParentSessionID string `json:"parent_session_id,omitempty"`
		}{info, s.SessionID, p.TaskID, p.ParentSessionID})
	})
	agents.HandleFunc("DELETE /agents/{id}/branch", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := branch.DeleteAgentBranch(id); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"agent": id, "status": "deleted"})
	})

	protected := store.Authn(agents)
	mux.Handle("/agents", protected)
	mux.Handle("/agents/", protected)

	handler := cors(store.WebOrigin())(logging(mux))
	cert, key, tlsErr := tlsutil.EnsureCert()
	if tlsErr != nil {
		log.Printf("agent branch API on %s (auth on; TLS disabled: %v)", addr, tlsErr)
		return http.ListenAndServe(addr, handler)
	}
	log.Printf("agent branch API on %s (auth on; TLS)", addr)
	return http.ListenAndServeTLS(addr, cert, key, handler)
}

func cors(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin(origin, r.Header.Get("Origin")))
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// allowOrigin echoes the request Origin when it is the configured UI origin or a
// localhost origin; otherwise falls back to the configured one.
func allowOrigin(configured, reqOrigin string) string {
	if reqOrigin != "" && (reqOrigin == configured || isLocalhostOrigin(reqOrigin)) {
		return reqOrigin
	}
	return configured
}

func isLocalhostOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
