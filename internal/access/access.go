// SPDX-License-Identifier: AGPL-3.0-or-later

// Package access decides what an account may do to a branch. It is the one
// rule every surface applies — the control plane, the Agent API, the Gateway
// and MCP — so a branch cannot be closed on one and open on another.
//
//   - An admin (a superuser or a member of db_admin on main) may do anything.
//   - The account that made a branch owns it, and may use and manage it.
//   - main is shared: every account may use it. What it may do there is what
//     Postgres lets its role do. Who may change it is the install's main write
//     mode (auth/mainwrite.go): in "all" every account, in "granted" an admin
//     and the accounts granted write; MayWriteMain answers that in Go, so a
//     surface can say so before Postgres refuses.
//   - Any other branch, including one with no owner, is not there: it is not
//     listed, and acting on it answers as if it did not exist.
package access

import (
	"sync"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Level is what an account may do to a branch.
type Level int

const (
	// None: the branch is out of reach, and is reported as not found.
	None Level = iota
	// Use: open it, query it, read its Blackbox, branch from it.
	Use
	// Manage: also delete, reset, checkpoint, cut an import over.
	Manage
)

// adminTTL is how long an admin check is remembered. Asking Postgres costs a
// round trip into a container. A grant or revoke recorded in the security log
// clears what is remembered within epochEvery (see Admin); this is the bound for
// one that is not, such as a GRANT typed into psql.
const adminTTL = 30 * time.Second

// epochEvery is how often a Checker asks the security log whether who is an
// admin has changed. Cheap (one indexed lookup in auth.db), but asked on every
// request otherwise, and a second is well inside what anyone notices.
const epochEvery = time.Second

// Checker applies the rule. The zero value is not usable; use New.
type Checker struct {
	store   *auth.Store
	isAdmin func(email string) bool

	mu     sync.Mutex
	admins map[string]adminEntry
	now    func() time.Time

	// The last AdminEpoch seen, and when it was asked. A change empties admins.
	epoch      int64
	epochAt    time.Time
	adminEpoch func() (int64, error)
}

type adminEntry struct {
	admin bool
	at    time.Time
}

// New returns a Checker that reads owners from store and asks main who is an
// admin.
func New(store *auth.Store) *Checker {
	return &Checker{
		store: store,
		isAdmin: func(email string) bool {
			ok, err := branch.IsAdmin("main", email)
			return err == nil && ok
		},
		admins: map[string]adminEntry{},
		now:    time.Now,
		adminEpoch: func() (int64, error) {
			if store == nil {
				return 0, nil
			}
			return store.AdminEpoch()
		},
	}
}

// NewWith is New with another way to tell an admin: for tests, and for any
// caller that already knows.
func NewWith(store *auth.Store, isAdmin func(email string) bool) *Checker {
	c := New(store)
	c.isAdmin = isAdmin
	return c
}

// Admin reports whether an account is an admin.
func (c *Checker) Admin(u auth.User) bool {
	if u.Email == "" {
		return false
	}
	c.mu.Lock()
	c.forgetIfChanged()
	e, ok := c.admins[u.Email]
	c.mu.Unlock()
	if ok && c.now().Sub(e.at) < adminTTL {
		return e.admin
	}
	admin := c.isAdmin(u.Email)
	c.mu.Lock()
	c.admins[u.Email] = adminEntry{admin: admin, at: c.now()}
	c.mu.Unlock()
	return admin
}

// forgetIfChanged empties the remembered answers when the security log has
// recorded a grant or revoke since they were given. Asked at most every
// epochEvery; a log that cannot be read leaves things to the TTL. c.mu is held.
func (c *Checker) forgetIfChanged() {
	now := c.now()
	if !c.epochAt.IsZero() && now.Sub(c.epochAt) < epochEvery {
		return
	}
	c.epochAt = now
	n, err := c.adminEpoch()
	if err != nil {
		return
	}
	if n != c.epoch {
		c.epoch = n
		c.admins = map[string]adminEntry{}
	}
}

// Level is what u may do to the branch called name ("" is main).
func (c *Checker) Level(u auth.User, name string) Level {
	if name == "" {
		name = "main"
	}
	if c.Admin(u) {
		return Manage
	}
	if owner, ok := c.store.BranchOwner(name); ok && owner == u.ID && u.ID != 0 {
		return Manage
	}
	if name == "main" {
		return Use
	}
	return None
}

// MayWriteMain reports whether u may change main: an admin always, and anyone
// else in mode "all" or with a grant of write. A store that cannot be read
// answers no: Postgres is what enforces this, and a refusal said early is only
// a courtesy.
func (c *Checker) MayWriteMain(u auth.User) bool {
	if c.store != nil && u.ID != 0 {
		if mode, err := c.store.MainWriteMode(); err == nil && mode == auth.MainWriteAll {
			return true
		}
		if ok, err := c.store.HasMainWriteGrant(u.ID); err == nil && ok {
			return true
		}
	}
	return c.Admin(u)
}

// MayWrite is MayWriteMain for a branch by name: off main, Use is enough,
// since a branch is its owner's (and an admin's) to change.
func (c *Checker) MayWrite(u auth.User, name string) bool {
	if name == "" || name == "main" {
		return c.MayWriteMain(u)
	}
	return c.Can(u, name, Use)
}

// Can reports whether u may do at least need to the branch.
func (c *Checker) Can(u auth.User, name string, need Level) bool {
	return c.Level(u, name) >= need
}

// Own records u as the owner of a branch it has just made.
func (c *Checker) Own(u auth.User, name string) error {
	return c.store.SetBranchOwner(name, u.ID)
}

// Forget drops a deleted branch's owner.
func (c *Checker) Forget(name string) { _ = c.store.ForgetBranch(name) }
