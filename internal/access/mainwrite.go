// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"sort"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// MainWriteAccount is one account, and whether it may change main.
type MainWriteAccount struct {
	Email   string `json:"email"`
	Admin   bool   `json:"admin"`   // an admin, who always may
	Granted bool   `json:"granted"` // granted write by an admin
	Writes  bool   `json:"writes"`  // may change main in the current mode
}

// MainWriteView is the install's mode and every account under it: what
// `fox access list` prints and GET /api/access/main-write returns.
type MainWriteView struct {
	Mode     string             `json:"mode"`
	Accounts []MainWriteAccount `json:"accounts"`
	// LoseInGranted are the accounts that may change main in "all" and would
	// not in "granted": what switching takes away, listed before it is done.
	LoseInGranted []string `json:"lose_in_granted"`
}

// ViewMainWrite reads the mode and the grants from store. admins are the
// admins' emails, as main says (branch.ListAdmins): the store does not know
// them, and asking main once is cheaper than once per account.
func ViewMainWrite(store *auth.Store, admins []string) (MainWriteView, error) {
	mode, err := store.MainWriteMode()
	if err != nil {
		return MainWriteView{}, err
	}
	writers, err := store.MainWriters()
	if err != nil {
		return MainWriteView{}, err
	}
	accounts, err := store.ListAccounts()
	if err != nil {
		return MainWriteView{}, err
	}
	isAdmin := map[string]bool{}
	for _, a := range admins {
		isAdmin[strings.ToLower(a)] = true
	}
	granted := map[int64]bool{}
	for _, w := range writers {
		granted[w.UserID] = true
	}
	v := MainWriteView{Mode: mode, Accounts: []MainWriteAccount{}, LoseInGranted: []string{}}
	for _, a := range accounts {
		m := MainWriteAccount{Email: a.Email, Admin: isAdmin[strings.ToLower(a.Email)], Granted: granted[a.ID]}
		m.Writes = mode == auth.MainWriteAll || m.Admin || m.Granted
		if !m.Admin && !m.Granted {
			v.LoseInGranted = append(v.LoseInGranted, a.Email)
		}
		v.Accounts = append(v.Accounts, m)
	}
	sort.Slice(v.Accounts, func(i, j int) bool { return v.Accounts[i].Email < v.Accounts[j].Email })
	sort.Strings(v.LoseInGranted)
	return v, nil
}
