// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Application identity (F1) over HTTP: the applications that may say which of
// their users a transaction acts for, and their keys. The console's
// Applications page.
//
//	GET    /api/apps                              every application, the install id, branch readiness
//	POST   /api/apps                              register one (and its first key)
//	DELETE /api/apps/{name}                       remove one
//	POST   /api/apps/{name}/keys                  add a key
//	POST   /api/apps/{name}/keys/{kid}/revoke     revoke one, optionally reported compromised
//
// Admins only, all of it: the list names accounts and keys, and a
// registration decides who may put a name on a record. Each change is in the
// security log and reaches every running branch before the reply.

// appsReply is GET /api/apps.
type appsReply struct {
	InstallID string            `json:"install_id"`
	Apps      []auth.App        `json:"apps"`
	Readiness map[string]string `json:"readiness"` // branch -> checked | unavailable | not installed
}

// appChange is what a change replies: the application as it now is, and the
// running branches the change could not reach (it reaches them on wake).
type appChange struct {
	App      *auth.App         `json:"app,omitempty"`
	Key      *auth.AppKey      `json:"key,omitempty"`
	Unsynced map[string]string `json:"unsynced,omitempty"`
}

func registerApps(mux *http.ServeMux, store *auth.Store) {
	admin := func(w http.ResponseWriter, r *http.Request) bool {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may manage the applications that assert their users"))
			return false
		}
		return true
	}
	audit := func(r *http.Request, kind, app, detail string) {
		if secLog != nil {
			u, _ := auth.UserFrom(r.Context())
			secLog.Audit(kind, u.Email, app, remoteIP(r), detail)
		}
	}

	mux.HandleFunc("GET /api/apps", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		apps, err := store.Apps()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		id, err := store.InstallID()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		ready, err := identityReadiness()
		if err != nil {
			ready = map[string]string{}
		}
		writeJSON(w, 200, appsReply{InstallID: id, Apps: apps, Readiness: ready})
	})

	mux.HandleFunc("POST /api/apps", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		var req struct {
			Name      string `json:"name"`
			Account   string `json:"account"`
			MaxLife   int64  `json:"max_life_seconds"`
			OnInvalid string `json:"on_invalid"`
			PublicKey string `json:"public_key"`
			Kid       string `json:"kid"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeErr(w, 400, fmt.Errorf("reading the request: %w", err))
			return
		}
		// The key is read before anything is written, so a registration is
		// never left half made by a key that was not one.
		var pub []byte
		if strings.TrimSpace(req.PublicKey) != "" {
			k, err := auth.ParsePublicKey([]byte(req.PublicKey))
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			pub = k
		}
		a, err := store.RegisterApp(req.Name, req.Account, time.Duration(req.MaxLife)*time.Second, req.OnInvalid)
		if err != nil {
			writeErr(w, appStatus(err, 400), err)
			return
		}
		audit(r, auth.EvAppRegistered, a.Name, fmt.Sprintf("account %s, tokens live at most %ds, an invalid one: %s", a.Account, a.MaxLife, a.OnInvalid))
		if pub != nil {
			k, err := store.AddAppKey(a.Name, req.Kid, pub)
			if err != nil {
				// Registered, without the key: said so, rather than undone,
				// since the registration itself is in the security log.
				writeErr(w, appStatus(err, 400), fmt.Errorf("%s is registered, but its key was not added: %w", a.Name, err))
				return
			}
			audit(r, auth.EvAppKeyAdded, a.Name, "key "+k.Kid)
		}
		replyChange(w, store, a.Name, nil)
	})

	mux.HandleFunc("DELETE /api/apps/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		name := r.PathValue("name")
		if err := store.RemoveApp(name); err != nil {
			writeErr(w, appStatus(err, 500), err)
			return
		}
		audit(r, auth.EvAppRemoved, name, "")
		writeJSON(w, 200, appChange{Unsynced: syncAll()})
	})

	mux.HandleFunc("POST /api/apps/{name}/keys", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		var req struct {
			PublicKey string `json:"public_key"`
			Kid       string `json:"kid"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeErr(w, 400, fmt.Errorf("reading the request: %w", err))
			return
		}
		pub, err := auth.ParsePublicKey([]byte(req.PublicKey))
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		name := r.PathValue("name")
		k, err := store.AddAppKey(name, req.Kid, pub)
		if err != nil {
			writeErr(w, appStatus(err, 400), err)
			return
		}
		audit(r, auth.EvAppKeyAdded, name, "key "+k.Kid)
		replyChange(w, store, name, &k)
	})

	mux.HandleFunc("POST /api/apps/{name}/keys/{kid}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !admin(w, r) {
			return
		}
		var req struct {
			CompromisedSince string `json:"compromised_since"` // "", "now" or RFC 3339
		}
		if r.ContentLength != 0 {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
				writeErr(w, 400, fmt.Errorf("reading the request: %w", err))
				return
			}
		}
		var since *time.Time
		switch v := strings.TrimSpace(req.CompromisedSince); v {
		case "":
		case "now":
			t := time.Now()
			since = &t
		default:
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeErr(w, 400, fmt.Errorf("compromised_since is now or an RFC 3339 time, not %q", v))
				return
			}
			since = &t
		}
		name, kid := r.PathValue("name"), r.PathValue("kid")
		if err := store.RevokeAppKey(name, kid, since); err != nil {
			writeErr(w, appStatus(err, 500), err)
			return
		}
		detail := "key " + kid + " revoked"
		if since != nil {
			detail += ", reported compromised since " + since.UTC().Format(time.RFC3339)
		}
		audit(r, auth.EvAppKeyRevoked, name, detail)
		replyChange(w, store, name, nil)
	})
}

// replyChange copies the change into the running branches, then replies with
// the application as it now is.
func replyChange(w http.ResponseWriter, store *auth.Store, name string, k *auth.AppKey) {
	unsynced := syncAll()
	a, err := store.App(name)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, appChange{App: &a, Key: k, Unsynced: unsynced})
}

// syncAll is branch.SyncIdentityAll, as strings for the reply. A variable so
// the handlers are tested without an engine.
var syncAll = func() map[string]string {
	failed := branch.SyncIdentityAll()
	if len(failed) == 0 {
		return nil
	}
	out := map[string]string{}
	names := make([]string, 0, len(failed))
	for n := range failed {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out[n] = failed[n].Error()
	}
	return out
}

// identityReadiness is branch.IdentityReadiness, a variable for the same reason.
var identityReadiness = branch.IdentityReadiness

// appStatus maps a store error to a status: not found is 404, a duplicate is
// 409, and anything else is def.
func appStatus(err error, def int) int {
	switch {
	case errors.Is(err, auth.ErrAppNotFound), errors.Is(err, auth.ErrAppNoKey):
		return 404
	case errors.Is(err, auth.ErrAppExists), errors.Is(err, auth.ErrAppKeyFound):
		return 409
	}
	return def
}
