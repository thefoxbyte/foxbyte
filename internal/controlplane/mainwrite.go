// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Who may change main, over HTTP (audit LIVE-1; auth/mainwrite.go and
// branch/mainwrite.go).
//
//	GET    /api/access/main-write                   the mode, and every account under it
//	PUT    /api/access/main-write {"mode": "..."}   "all" or "granted"
//	POST   /api/access/main-write/writers {"email"} grant an account write on main
//	DELETE /api/access/main-write/writers/{email}   take it back
//
// Admins only. Each change is in the security log, its intent before it is
// made and its outcome after (auth.BeginPrivileged).

// Variables so the routes are tested without an engine.
var (
	listMainAdmins    = func() ([]string, error) { return branch.ListAdmins("main") }
	applyMainWrite    = branch.ApplyMainWrite
	applyMainWriteFor = branch.ApplyMainWriteFor
)

func mainWriteView(store *auth.Store) (access.MainWriteView, error) {
	admins, err := listMainAdmins()
	if err != nil {
		return access.MainWriteView{}, fmt.Errorf("asking main who is an admin: %w", err)
	}
	return access.ViewMainWrite(store, admins)
}

func registerMainWrite(mux *http.ServeMux, store *auth.Store) {
	mux.HandleFunc("GET /api/access/main-write", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may see who may change main"))
			return
		}
		v, err := mainWriteView(store)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, v)
	})

	mux.HandleFunc("PUT /api/access/main-write", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may change who may change main"))
			return
		}
		var body struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, fmt.Errorf("invalid JSON: %w", err))
			return
		}
		mode := strings.ToLower(strings.TrimSpace(body.Mode))
		if mode != auth.MainWriteAll && mode != auth.MainWriteGranted {
			writeErr(w, 400, fmt.Errorf(`mode is "all" or "granted", not %q`, body.Mode))
			return
		}
		before, err := mainWriteView(store)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		by, _ := auth.UserFrom(r.Context())
		act, err := store.BeginPrivileged(auth.EvMainWriteModeStarted, auth.EvMainWriteModeSet, auth.EvMainWriteModeFailed,
			by.Email, "main", remoteIP(r), "mode "+mode)
		if err != nil {
			writeErr(w, 503, err)
			return
		}
		err = store.SetMainWriteMode(mode)
		if err == nil {
			err = applyMainWrite()
		}
		act.Done(err, "mode "+mode)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		lost := []string{}
		if mode == auth.MainWriteGranted && before.Mode == auth.MainWriteAll {
			lost = before.LoseInGranted
		}
		writeJSON(w, 200, map[string]any{"mode": mode, "lost_write": lost})
	})

	grant := func(w http.ResponseWriter, r *http.Request, email string, on bool) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may grant or revoke write on main"))
			return
		}
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" {
			writeErr(w, 400, errors.New("email is required"))
			return
		}
		u, ok := store.UserByEmail(email)
		if !ok {
			writeErr(w, 404, fmt.Errorf("no account for %s", email))
			return
		}
		by, _ := auth.UserFrom(r.Context())
		started, done, failed := auth.EvMainWriteGrantStarted, auth.EvMainWriteGranted, auth.EvMainWriteGrantFailed
		if !on {
			started, done, failed = auth.EvMainWriteRevokeStarted, auth.EvMainWriteRevoked, auth.EvMainWriteRevokeFailed
		}
		act, err := store.BeginPrivileged(started, done, failed, by.Email, u.Email, remoteIP(r), "branch main")
		if err != nil {
			writeErr(w, 503, err)
			return
		}
		if on {
			err = store.GrantMainWrite(u.ID, by.Email)
		} else {
			_, err = store.RevokeMainWrite(u.ID)
		}
		if err == nil {
			err = applyMainWriteFor(u.Email)
		}
		act.Done(err, "branch main")
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		status := "granted"
		if !on {
			status = "revoked"
		}
		mode, _ := store.MainWriteMode()
		writeJSON(w, 200, map[string]string{"email": u.Email, "status": status, "mode": mode})
	}
	mux.HandleFunc("POST /api/access/main-write/writers", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, fmt.Errorf("invalid JSON: %w", err))
			return
		}
		grant(w, r, body.Email, true)
	})
	mux.HandleFunc("DELETE /api/access/main-write/writers/{email}", func(w http.ResponseWriter, r *http.Request) {
		grant(w, r, r.PathValue("email"), false)
	})
}

// withMainWriteHint says why a console statement on main was refused, when
// the reason is that main is read-only for the signed-in account. Postgres
// refuses; this only names the cause and the command that lifts it.
func withMainWriteHint(as queryAs, out map[string]any) map[string]any {
	if as.Actor == "" || as.Branch != "main" || acl == nil || secLog == nil {
		return out
	}
	msg, _ := out["error"].(string)
	if msg == "" || (!strings.Contains(msg, "permission denied") && !strings.Contains(msg, "must be owner")) {
		return out
	}
	u, ok := secLog.UserByEmail(as.Actor)
	if !ok || acl.MayWriteMain(u) {
		return out
	}
	hint := branch.MainReadOnlyError(u.Email).Error()
	if h, _ := out["hint"].(string); h != "" {
		hint += ". " + h
	}
	out["hint"] = hint
	out["main_read_only"] = true
	return out
}
