// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
)

// Agents identified by how they logged in, not by what their session says.
//
// The Blackbox decides "agent or person" from session_user, which a session
// cannot change (bb._ctx). Two kinds of agent session used to escape that:
//
//   - The engine's own agent sessions — MCP's run_sql and the provenance-
//     recorded agent calls (ExecuteChange) — logged in as the shared db_client
//     and declared themselves agents in bb.actor_kind, a setting the agent's
//     own SQL could overwrite to step out of the agent-only guardrails.
//   - An AI agent given a person's API key logged in through the Gateway as
//     that person's role, and so was a person.
//
// Both now log in as agents. The engine's sessions use db_agent, a member of
// db_client with exactly its access. An agent key (auth.KindAgent) logs in as
// "agent:<email>", a per-account role that is a member of both: the account's
// data access, never its admin grant, and an agent to the Blackbox.
//
// A branch keeps the Blackbox it was cloned with until `fox ledger upgrade`,
// and an older bb._ctx does not know these roles: it would take db_agent for a
// person, which is worse than the setting it replaces. So each is used only on
// a branch whose Blackbox knows it. Elsewhere the engine's sessions keep the
// shared role they always used, and an agent key is refused with the command
// that fixes it, since there is no older behaviour to keep for it.

// AgentClientRole is the role the engine's own agent sessions log in as.
const AgentClientRole = "db_agent"

// agentKeyRolePrefix begins the role an agent key logs in as. A colon, not the
// "agent-" of an agent branch's role, so the two can never be confused.
const agentKeyRolePrefix = "agent:"

// AgentKeyRole is the role an agent key belonging to email logs in as.
func AgentKeyRole(email string) string { return agentKeyRolePrefix + email }

// AgentClientRolePassword is db_agent's password, derived like every other.
func AgentClientRolePassword() string { return rolePassword("agent-client", AgentClientRole) }

// AgentKeyRolePassword is the password of an agent key's role. Derived as a
// per-user role's is, from the role's own name: the name contains '@', so a
// failover that rewrites passwords (classifyRole) treats it as one and arrives
// at the same password.
func AgentKeyRolePassword(email string) string { return UserRolePassword(AgentKeyRole(email)) }

// ErrAgentRolesNeedUpgrade is returned on a branch whose Blackbox predates
// agent roles.
var ErrAgentRolesNeedUpgrade = errors.New("this branch's Blackbox predates agent roles")

// agentRolesReady records the branches on which db_agent has been provisioned
// by this process. Only success is remembered: a branch upgraded with
// `fox ledger upgrade` is picked up on the next call, without a restart.
//
// Entries are kept per container, not per branch name. A branch deleted and
// made again by another process (the CLI, while the Gateway runs) is a new
// clone, possibly of a parent with an older Blackbox, and forgetBranchRoles only
// clears the cache of the process that did it. Trusting a name would then log
// an agent in to a Blackbox that records it as a person.
var agentRolesReady sync.Map

// branchIdentity names the container serving a branch, or "" when it cannot be
// read. A variable so tests can supply one.
var branchIdentity = func(name string) string {
	out, err := capture("docker", "inspect", "-f", "{{.Id}}", container(name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// agentCacheKey is the cache key for something provisioned on one branch's
// container. ok is false when the container is unknown, and then nothing may
// be read from or written to a cache.
func agentCacheKey(name, id, what string) (key string, ok bool) {
	if id == "" {
		return "", false
	}
	return name + "\x00" + id + "\x00" + what, true
}

// ctxKnowsAgentRolesSQL asks whether the branch's bb._ctx classifies db_agent.
// The text of the function is the only version marker the base ledger has.
const ctxKnowsAgentRolesSQL = `SELECT coalesce((SELECT position('db_agent' in prosrc) > 0 FROM pg_proc WHERE oid = to_regprocedure('bb._ctx()')), false)`

// ensureAgentRoles makes sure db_agent exists on a branch with this install's
// password, or reports ErrAgentRolesNeedUpgrade when the branch's Blackbox
// would not recognise it. ledger.sql creates the role on main; this covers a
// branch cloned before it did, and sets the password, which ledger.sql cannot.
func ensureAgentRoles(name string) error {
	if name == "" {
		name = "main"
	}
	key, cacheable := agentCacheKey(name, branchIdentity(name), AgentClientRole)
	if cacheable {
		if _, ok := agentRolesReady.Load(key); ok {
			return nil
		}
	}
	out, err := capture("docker", "exec", "--env-file", pgEnvFile(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc", ctxKnowsAgentRolesSQL)
	if err != nil {
		return fmt.Errorf("asking %q's Blackbox about agent roles: %w", name, err)
	}
	if strings.TrimSpace(out) != "t" {
		return ErrAgentRolesNeedUpgrade
	}
	defer lockRole("agent\x00" + name + "\x00" + AgentClientRole)()
	if err := provisionRole(name, agentClientRoleSQL(AgentClientRolePassword())); err != nil {
		return err
	}
	if cacheable {
		agentRolesReady.Store(key, struct{}{})
	}
	return nil
}

// agentClientRoleSQL creates db_agent if it is missing and sets its password.
func agentClientRoleSQL(password string) string {
	return retryingRoleDO("", fmt.Sprintf(`      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %[1]s) THEN
        EXECUTE format('CREATE ROLE %%I LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS INHERIT IN ROLE db_client', %[1]s);
      END IF;
      EXECUTE format('ALTER ROLE %%I WITH LOGIN NOSUPERUSER PASSWORD %%L', %[1]s, %[2]s);
      EXECUTE format('ALTER ROLE %%I SET role = db_client', %[1]s);`, bodyLiteral(AgentClientRole), bodyLiteral(password)))
}

// agentKeyRoleSQL creates an agent key's role if it is missing and sets its
// password. A member of db_client for the account's data access, and of
// db_agent so the Blackbox records it as an agent. Never of db_admin: an agent
// holding an admin's key still cannot override a guardrail.
func agentKeyRoleSQL(role, password string) string {
	return retryingRoleDO(fmt.Sprintf("r text := %s;", bodyLiteral(role)), fmt.Sprintf(`      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
        EXECUTE format('CREATE ROLE %%I LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS INHERIT IN ROLE db_client, %s', r);
      END IF;
      EXECUTE format('ALTER ROLE %%I WITH LOGIN NOSUPERUSER PASSWORD %%L', r, %s);
      EXECUTE format('ALTER ROLE %%I SET role = db_client', r);`, AgentClientRole, bodyLiteral(password)))
}

// EnsureAgentKeyRole makes sure the role an agent key belonging to email logs
// in as exists on a branch. ErrAgentRolesNeedUpgrade means the branch's
// Blackbox would record that role as a person, and the Gateway refuses.
func EnsureAgentKeyRole(branchName, email string) error {
	if branchName == "" {
		branchName = "main"
	}
	if err := ensureAgentRoles(branchName); err != nil {
		return err
	}
	role := AgentKeyRole(email)
	key, cacheable := agentCacheKey(branchName, branchIdentity(branchName), role)
	if cacheable {
		if _, ok := agentRolesReady.Load(key); ok {
			return nil
		}
	}
	defer lockRole("agent\x00" + branchName + "\x00" + role)()
	if cacheable {
		if _, ok := agentRolesReady.Load(key); ok {
			return nil
		}
	}
	if err := provisionRole(branchName, agentKeyRoleSQL(role, AgentKeyRolePassword(email))); err != nil {
		return err
	}
	if cacheable {
		agentRolesReady.Store(key, struct{}{})
	}
	return nil
}

// agentLoginRole is the role an engine agent session should log in as on a
// branch: db_agent where the branch's Blackbox knows it, otherwise the shared
// client role it always used. The second result says which.
func agentLoginRole(name string) (role string, asAgent bool) {
	if err := ensureAgentRoles(name); err != nil {
		if !errors.Is(err, ErrAgentRolesNeedUpgrade) {
			// stderr, never stdout: `fox mcp` speaks JSON-RPC on stdout.
			log.Printf("agent role on %q: %v (using %s)", name, err, ClientRole)
		}
		return ClientRole, false
	}
	return AgentClientRole, true
}
