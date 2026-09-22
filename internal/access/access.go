// SPDX-License-Identifier: AGPL-3.0-or-later

// Package access decides what an account may do to a branch. It is the one
// rule every surface applies — the control plane, the Agent API, the Gateway
// and MCP — so a branch cannot be closed on one and open on another.
//
//   - An admin (a superuser or a member of db_admin on main) may do anything.
//   - The account that made a branch owns it, and may use and manage it.
//   - main is shared: every account may use it. What it may do there is what
//     Postgres lets its role do.
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
// round trip into a container; a revoked grant takes at most this long to bite.
const adminTTL = 30 * time.Second

// Checker applies the rule. The zero value is not usable; use New.
type Checker struct {
	store   *auth.Store
	isAdmin func(email string) bool

	mu     sync.Mutex
	admins map[string]adminEntry
	now    func() time.Time
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
