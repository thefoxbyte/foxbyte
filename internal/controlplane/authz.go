// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// decode reads a JSON body; an empty one decodes to the zero value.
func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

// acl is the access rule (internal/access) the control plane applies. Serve
// sets it; every branch route, and every handler that makes a branch, uses it.
var acl *access.Checker

// Every handler under /api/branches/{name} used to check only that the caller
// was signed in, so any account could read, query, suspend or delete any other
// account's branch by name (audit v2 G02). authorize applies the access rule
// before any of them runs:
//
//   - a branch the caller may not reach answers 404, as if it did not exist,
//     so names are not confirmed to someone who cannot use them;
//   - deleting a branch, cutting an import over and writing a Blackbox
//     checkpoint need Manage (owner or admin); everything else needs Use.
//
// Policies and admins on a branch keep their own, stricter check (db_admin).
func authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		if rest, ok := strings.CutPrefix(r.URL.EscapedPath(), "/api/branches/"); ok {
			seg, tail, _ := strings.Cut(rest, "/")
			name, _ := url.PathUnescape(seg)
			if name != "" && !allowed(w, u, name, needFor(r.Method, tail)) {
				return
			}
		}
		switch r.URL.Path {
		case "/api/ledger/diff", "/api/blackbox/diff":
			for _, k := range []string{"a", "b"} {
				if n := r.URL.Query().Get(k); n != "" && !allowed(w, u, n, access.Use) {
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// allowed answers the request and returns false when u may not do need to name.
func allowed(w http.ResponseWriter, u auth.User, name string, need access.Level) bool {
	switch lvl := acl.Level(u, name); {
	case lvl == access.None:
		writeErr(w, 404, fmt.Errorf("no branch %q", name))
		return false
	case lvl < need:
		writeErr(w, 403, fmt.Errorf("only the owner of %q or an admin may do that", name))
		return false
	}
	return true
}

// needFor is the level a branch route needs; tail is the path after the name.
func needFor(method, tail string) access.Level {
	switch {
	case method == http.MethodDelete && tail == "":
		return access.Manage
	case tail == "replication/cutover", tail == "ledger/checkpoint", tail == "blackbox/checkpoint":
		return access.Manage
	}
	return access.Use
}

// own records the caller as the owner of a branch they just made. A failure
// is reported, not ignored: the branch would be reachable only by admins.
func own(r *http.Request, name string) error {
	if name == "" {
		return nil
	}
	u, _ := auth.UserFrom(r.Context())
	if err := acl.Own(u, name); err != nil {
		return fmt.Errorf("the branch %q was made, but recording you as its owner failed: %w", name, err)
	}
	return nil
}

// isAdmin reports whether the caller is an admin.
func isAdmin(r *http.Request) bool {
	u, _ := auth.UserFrom(r.Context())
	return acl.Admin(u)
}

// registerAccounts mounts the account endpoints (audit v2 G16): your own
// password, and — for admins — the list of accounts and deleting one.
func registerAccounts(mux *http.ServeMux, store *auth.Store) {
	mux.HandleFunc("GET /api/account", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		writeJSON(w, 200, map[string]any{"user": u, "admin": acl.Admin(u)})
	})
	mux.HandleFunc("POST /api/account/password", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		var body struct {
			Current string `json:"current"`
			New     string `json:"new"`
		}
		if err := decode(r, &body); err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := store.ChangePassword(u.ID, body.Current, body.New, auth.SessionToken(r)); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "changed", "note": "every other session of this account was signed out"})
	})
	mux.HandleFunc("GET /api/users", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may list accounts"))
			return
		}
		list, err := store.ListAccounts()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"users": list})
	})
	mux.HandleFunc("DELETE /api/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeErr(w, 403, errors.New("only an admin may delete an account"))
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeErr(w, 400, errors.New("id must be an account id"))
			return
		}
		if u, _ := auth.UserFrom(r.Context()); u.ID == id {
			writeErr(w, 400, errors.New("you cannot delete your own account"))
			return
		}
		email := ""
		if list, err := store.ListAccounts(); err == nil {
			for _, a := range list {
				if a.ID == id {
					email = a.Email
				}
			}
		}
		if err := store.DeleteAccount(id); err != nil {
			writeErr(w, 404, err)
			return
		}
		// An admin grant lives on the account's Postgres role, not in the
		// store: without this, re-creating the same email would bring it back.
		if email != "" {
			if err := branch.RevokeAdmin("main", email); err != nil {
				log.Printf("deleted account %s: revoking its admin grant on main: %v", email, err)
			}
		}
		writeJSON(w, 200, map[string]string{"status": "deleted",
			"note": "its sessions, keys and pipelines are gone; the branches it owned are now reachable by admins only"})
	})
}
