// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"strings"
)

// The other half of a failover between machines: the copy's role passwords.
//
// Every password the engine uses inside Postgres is derived from the install
// secret in ~/.fox (AgentRolePassword, ClientRolePassword, UserRolePassword and
// the rest, all through rolePassword). A standby on another machine holds a
// copy of the *primary's* cluster, so its roles carry passwords derived from
// the primary's secret — and `node join` deliberately carries no secret, since
// a token that did could be used to own the database rather than to copy it.
//
// Phase 7 measured what that costs: promote such a standby and the local
// gateway authenticates against those roles with passwords of its own, and
// every client connection fails. The decision taken for phase 2 is that the
// secret still never leaves the primary — a promoted node rewrites the
// passwords instead.
//
// It can, because it does not need to know the old ones: psql inside the
// container reaches Postgres over its Unix socket, which the official image's
// pg_hba trusts, which is the same door syncRolePassword has always used. No
// client is affected: clients authenticate at the gateway with an API key, and
// the gateway derives the role password locally — so after the rewrite the two
// agree again. The one thing it cannot do is help a standby that has *not* been
// promoted: a copy in recovery cannot be written to at all, which is why
// cross-machine reads need a role made on the primary instead.

// roleClass says which of the engine's derivations a role's password comes
// from, or that the role is none of ours.
type roleClass int

const (
	roleUnknown     roleClass = iota
	roleSuper                 // the bootstrap superuser
	roleClient                // the shared application role
	roleReplica               // the replication role
	roleRealtime              // the change feed's decoder
	roleUser                  // a per-person role, named by email address
	roleAgent                 // an agent's role, named for its branch
	roleAgentClient           // the engine's agent sessions (db_agent)
)

// classifyRole decides which derivation names a role, given a way to ask
// whether a name is a branch on this install.
//
// Pure, and tested, because the cost of getting it wrong is asymmetric. A role
// classified as ours that is not — a role somebody made by hand, an extension's
// role — would have its password overwritten with one derived for a name it
// does not own, and the thing that used it would stop working with no
// explanation. So anything unrecognised is left alone, and "unrecognised" is
// the default rather than the exception.
func classifyRole(name string, isBranch func(string) bool) roleClass {
	switch name {
	case pgUser:
		return roleSuper
	case ClientRole:
		return roleClient
	case ReplicationRole:
		return roleReplica
	case RealtimeRole:
		return roleRealtime
	case AgentClientRole:
		return roleAgentClient
	}
	// A per-user role is named by the address it belongs to, and an address is
	// the only name here that can contain '@' — ErrBadName rejects it for a
	// branch, and these are the only two kinds of name the engine creates. An
	// agent key's role ("agent:<email>") contains one too, and its password is
	// derived the same way, from its own name (AgentKeyRolePassword).
	if strings.Contains(name, "@") {
		return roleUser
	}
	if isBranch != nil && isBranch(name) {
		return roleAgent
	}
	return roleUnknown
}

// rolePasswordFor is the password this install derives for a role it manages.
func rolePasswordFor(class roleClass, name string) (string, bool) {
	switch class {
	case roleSuper:
		return pgPass(), true
	case roleClient:
		return ClientRolePassword(), true
	case roleReplica:
		return ReplicationRolePassword(), true
	case roleRealtime:
		return RealtimeRolePassword(), true
	case roleUser:
		return UserRolePassword(name), true
	case roleAgent:
		return AgentRolePassword(name), true
	case roleAgentClient:
		return AgentClientRolePassword(), true
	}
	return "", false
}

// rolePasswordSQL is the script that rewrites them: one statement per role,
// and the names and passwords are quoted as literals rather than interpolated.
//
// Pure, so what it does to a list of roles can be read in a test instead of
// against a live cluster — and so the one property that matters can be
// asserted: a role the engine does not manage appears nowhere in it.
func rolePasswordSQL(roles []string, isBranch func(string) bool) (sql string, touched []string) {
	var b strings.Builder
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		class := classifyRole(r, isBranch)
		pw, ok := rolePasswordFor(class, r)
		if !ok {
			continue
		}
		// format %I/%L through a DO block, so a role name is an identifier and
		// a password is a literal whatever either of them contains.
		fmt.Fprintf(&b, "DO $do$ BEGIN EXECUTE format('ALTER ROLE %%I WITH PASSWORD %%L', %s, %s); END $do$;\n",
			bodyLiteral(r), bodyLiteral(pw))
		touched = append(touched, r)
	}
	return b.String(), touched
}

// loginRoles lists the roles that can log in on a container. Group roles
// (db_admin) have no password to rewrite, and Postgres's own pg_* roles are not
// ours to touch.
const loginRolesSQL = `SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolname NOT LIKE 'pg\_%' ORDER BY rolname`

// RewriteRolePasswords sets every role the engine manages on a branch's
// container to the password this install derives for it, and reports which it
// touched.
//
// Idempotent, and a no-op in effect on a machine whose secret already made
// these passwords — which is every single-machine install, and why a failover
// there is unaffected by this.
func RewriteRolePasswords(name string) ([]string, error) {
	if name == "" {
		// Whichever container is serving as the primary, since that is the one
		// a client reaches and the only one that can be written to.
		name = primaryBranch()
	}
	out := haQuery(container(name), loginRolesSQL)
	roles := strings.Split(out, "\n")
	if len(roles) == 0 || strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("could not list the roles on %q", name)
	}
	sql, touched := rolePasswordSQL(roles, Exists)
	if sql == "" {
		return nil, nil
	}
	if err := psqlStdin(name, sql); err != nil {
		return nil, fmt.Errorf("rewriting the role passwords on %q: %w", name, err)
	}
	return touched, nil
}
