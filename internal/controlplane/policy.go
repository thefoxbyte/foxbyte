// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// registerPolicy mounts the Blackbox policy gate endpoints (behind auth). Reading
// and previewing are open to any signed-in user; changing rules needs db_admin
// on the branch.
//
//	GET    /api/branches/{name}/policies               rules
//	POST   /api/branches/{name}/policies               add a rule (admin)
//	PUT    /api/branches/{name}/policies/{rule}        change action / enabled (admin)
//	DELETE /api/branches/{name}/policies/{rule}        remove a custom rule (admin)
//	POST   /api/branches/{name}/policies/check         preview matches for a statement
//	GET    /api/branches/{name}/policies/evaluations   recent warnings, blocks, overrides
//	GET    /api/branches/{name}/admins                 who may override blocking rules
//	POST   /api/branches/{name}/admins                 grant that permission (admin)
//	DELETE /api/branches/{name}/admins/{email}         revoke it (admin)
func registerPolicy(mux *http.ServeMux, store *auth.Store) {
	running := func(w http.ResponseWriter, name string) bool {
		if _, err := branch.EnsureRunning(name); err != nil {
			writeErr(w, 404, err)
			return false
		}
		return true
	}
	admin := func(w http.ResponseWriter, r *http.Request, name, what string) (string, bool) {
		u, _ := auth.UserFrom(r.Context())
		ok, err := branch.IsAdmin(name, u.Email)
		if err != nil {
			writeErr(w, 500, err)
			return "", false
		}
		if !ok {
			store.Audit(auth.EvDenied, u.Email, name, remoteIP(r), what)
			writeErr(w, 403, fmt.Errorf("%s needs db_admin on %q — ask an admin to grant it on the Policies page, or run: fox admin grant %s --branch %s", what, name, u.Email, name))
			return "", false
		}
		return u.Email, true
	}
	fail := func(w http.ResponseWriter, err error) {
		switch {
		case errors.Is(err, branch.ErrInvalidRequest):
			writeErr(w, 400, err)
		case errors.Is(err, branch.ErrRuleNotFound):
			writeErr(w, 404, err)
		case errors.Is(err, branch.ErrRuleExists), errors.Is(err, branch.ErrBuiltinRule):
			writeErr(w, 409, err)
		default:
			writeErr(w, 500, err)
		}
	}

	mux.HandleFunc("GET /api/branches/{name}/policies", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !running(w, name) {
			return
		}
		rules, err := branch.PolicyRules(name)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, rules)
	})

	mux.HandleFunc("POST /api/branches/{name}/policies", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !running(w, name) {
			return
		}
		email, ok := admin(w, r, name, "changing Blackbox policy rules")
		if !ok {
			return
		}
		var rule branch.PolicyRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeErr(w, 400, fmt.Errorf("invalid JSON: %w", err))
			return
		}
		if rule.Action == "" {
			rule.Action = "warn"
		}
		if err := branch.AddPolicyRule(name, rule, email); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 201, map[string]string{"rule_id": rule.RuleID, "status": "added"})
	})

	mux.HandleFunc("PUT /api/branches/{name}/policies/{rule}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !running(w, name) {
			return
		}
		email, ok := admin(w, r, name, "changing Blackbox policy rules")
		if !ok {
			return
		}
		var body struct {
			Action  *string `json:"action"`
			Enabled *bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, fmt.Errorf("invalid JSON: %w", err))
			return
		}
		if err := branch.UpdatePolicyRule(name, r.PathValue("rule"), body.Action, body.Enabled, email); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"rule_id": r.PathValue("rule"), "status": "updated"})
	})

	mux.HandleFunc("DELETE /api/branches/{name}/policies/{rule}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !running(w, name) {
			return
		}
		email, ok := admin(w, r, name, "changing Blackbox policy rules")
		if !ok {
			return
		}
		if err := branch.RemovePolicyRule(name, r.PathValue("rule"), email); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, map[string]string{"rule_id": r.PathValue("rule"), "status": "removed"})
	})

	mux.HandleFunc("POST /api/branches/{name}/policies/check", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !running(w, name) {
			return
		}
		var body struct {
			SQL string `json:"sql"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		tag, matches, err := branch.PolicyCheck(name, body.SQL)
		if err != nil {
			fail(w, err)
			return
		}
		if matches == nil {
			matches = []ledger.PolicyDetail{}
		}
		writeJSON(w, 200, map[string]any{"command": tag, "matches": matches})
	})

	mux.HandleFunc("GET /api/branches/{name}/policies/evaluations", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !running(w, name) {
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		evs, err := branch.PolicyEvaluations(name, limit)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, 200, evs)
	})

	// Who may override a blocking rule: members of db_admin (and superusers).
	// Anyone signed in may look, so the console can tell a user whether an
	// override will work before they try; granting and revoking need db_admin
	// on the branch, like changing rules — otherwise anyone could grant
	// themselves.
	mux.HandleFunc("GET /api/branches/{name}/admins", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !running(w, name) {
			return
		}
		u, _ := auth.UserFrom(r.Context())
		names, err := branch.ListAdmins(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		you, err := branch.IsAdmin(name, u.Email)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if names == nil {
			names = []string{}
		}
		writeJSON(w, 200, map[string]any{"admins": names, "you": u.Email, "you_are_admin": you})
	})

	mux.HandleFunc("POST /api/branches/{name}/admins", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !running(w, name) {
			return
		}
		if _, ok := admin(w, r, name, "granting override permission"); !ok {
			return
		}
		var body struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, fmt.Errorf("invalid JSON: %w", err))
			return
		}
		email := strings.ToLower(strings.TrimSpace(body.Email))
		if email == "" {
			writeErr(w, 400, fmt.Errorf("email is required"))
			return
		}
		u, ok := store.UserByEmail(email)
		if !ok {
			writeErr(w, 404, fmt.Errorf("no account for %s — they need to sign up first", email))
			return
		}
		if err := branch.GrantAdmin(name, u.Email); err != nil {
			writeErr(w, 500, err)
			return
		}
		by, _ := auth.UserFrom(r.Context())
		store.Audit(auth.EvAdminGranted, by.Email, u.Email, remoteIP(r), "branch "+name)
		writeJSON(w, 200, map[string]string{"email": u.Email, "branch": name, "status": "granted"})
	})

	mux.HandleFunc("DELETE /api/branches/{name}/admins/{email}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !running(w, name) {
			return
		}
		if _, ok := admin(w, r, name, "revoking override permission"); !ok {
			return
		}
		email := strings.ToLower(strings.TrimSpace(r.PathValue("email")))
		names, err := branch.ListAdmins(name)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		found := false
		for _, n := range names {
			found = found || n == email
		}
		if !found {
			writeErr(w, 404, fmt.Errorf("%s is not an admin on %q", email, name))
			return
		}
		// Removing the last admin would leave nobody who can grant it back from
		// the web console.
		if len(names) == 1 {
			writeErr(w, 409, fmt.Errorf("%s is the only admin on %q — grant someone else first (or run: fox admin revoke %s --branch %s)", email, name, email, name))
			return
		}
		if err := branch.RevokeAdmin(name, email); err != nil {
			writeErr(w, 500, err)
			return
		}
		by, _ := auth.UserFrom(r.Context())
		store.Audit(auth.EvAdminRevoked, by.Email, email, remoteIP(r), "branch "+name)
		writeJSON(w, 200, map[string]string{"email": email, "branch": name, "status": "revoked"})
	})
}
