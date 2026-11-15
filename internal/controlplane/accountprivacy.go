// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// An account holder's own rights over their data (finding PRIV-7): a copy of
// it, and deleting the account, without asking an admin.

// recentSignIn is how fresh a browser session must be to delete its account
// without typing the password again. A session lasts a month; one left open
// on a shared machine should not be enough to delete somebody.
const recentSignIn = 10 * time.Minute

// isACopy reports whether this node's accounts are a copy of a primary's (HA),
// where an account change would be undone by the next copy. A variable so
// tests need not stand up a standby.
var isACopy = branch.SharedStateIsACopy

// revokeMainAdmin takes away an account's admin grant on main. A variable so
// tests need not run Postgres.
var revokeMainAdmin = func(email string) error { return branch.RevokeAdmin("main", email) }

func registerAccountPrivacy(mux *http.ServeMux, store *auth.Store) {
	// Only the caller's own data: the account is taken from the session or
	// key, never from the request, so there is nothing to point at someone
	// else's.
	mux.HandleFunc("GET /api/account/export", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		exp, err := store.ExportAccount(u.ID)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="account-export.json"`)
		writeJSON(w, 200, exp)
	})

	mux.HandleFunc("DELETE /api/account", func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		var body struct {
			Password string `json:"password"`
		}
		if err := decode(r, &body); err != nil {
			writeErr(w, 400, err)
			return
		}
		if isACopy() {
			writeErr(w, 409, errors.New("this machine's accounts are a copy of the primary's; delete the account there"))
			return
		}
		// Either the password, or a sign-in moments ago. An API key alone is
		// never enough: a leaked key should not be able to delete its owner.
		age, fresh := store.SessionAge(auth.SessionToken(r))
		switch {
		case body.Password != "":
			if !store.CheckPassword(u.ID, body.Password) {
				store.Audit(auth.EvDenied, u.Email, u.Email, remoteIP(r), "account deletion: wrong password")
				writeErr(w, 403, errors.New("the password is wrong"))
				return
			}
		case fresh && age <= recentSignIn:
		default:
			writeErr(w, 403, fmt.Errorf("confirm with your current password, or sign in again and delete within %d minutes", int(recentSignIn/time.Minute)))
			return
		}
		admin := acl.Admin(u)
		if admin && !anotherAdmin(store, u) {
			writeErr(w, 409, errors.New("you are the only admin; make someone else an admin first, or nobody could manage this install"))
			return
		}
		res, err := eraseAccount(store, u.ID, u.Email, u.Email, remoteIP(r), "deleted by its holder", admin)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		out := map[string]any{"status": "deleted",
			"note": "your sessions, keys and pipelines are gone; branches you owned are now reachable by admins only"}
		if res != "" {
			out["securityLog"] = res
		}
		writeJSON(w, 200, out)
	})
}

// anotherAdmin reports whether an account other than u is an admin.
func anotherAdmin(store *auth.Store, u auth.User) bool {
	list, err := store.ListAccounts()
	if err != nil {
		return false // unknown is refused: losing the last admin is not undoable here
	}
	for _, a := range list {
		if a.ID != u.ID && acl.Admin(auth.User{ID: a.ID, Email: a.Email}) {
			return true
		}
	}
	return false
}

// eraseAccount is deleting an account, however it is asked for: the account
// and everything that signs it in, the record of the deletion, its admin grant,
// and then its email and addresses in the security log replaced by its
// pseudonym. The branches it owned stay, reachable by admins only, as they
// always have.
//
// The account is gone once DeleteAccount returns, so a failure after it is
// reported rather than undone: the returned text says what still needs doing.
func eraseAccount(store *auth.Store, id int64, email, by, ip, why string, admin bool) (string, error) {
	if err := store.DeleteAccount(id); err != nil {
		return "", err
	}
	store.Audit(auth.EvAccountDeleted, by, email, ip, why)
	// An admin grant lives on the account's Postgres role, not in the
	// store: without this, re-creating the same email would bring it back.
	if admin && email != "" {
		if err := revokeMainAdmin(email); err != nil {
			log.Printf("deleted account %s: revoking its admin grant on main: %v", email, err)
		}
	}
	if email == "" {
		return "", nil
	}
	res, err := store.PseudonymiseSecurityLog(email, by)
	if err != nil {
		log.Printf("deleted account %d: pseudonymising the security log: %v", id, err)
		return "the account is deleted, but its security-log events still name it: " + err.Error(), nil
	}
	return fmt.Sprintf("%d security-log events now name %s instead", res.Events, res.Pseudonym), nil
}
