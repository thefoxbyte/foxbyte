// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"log"
	"strings"
)

// The engine's own agent sessions (MCP's run_sql and execute_change), named by
// how they log in (G1's remainder; F1 design, section 9).
//
// They used to log in as the shared db_agent and name their agent with
// bb.actor, a setting. bb._ctx records a shared role's actor from that setting,
// so the agent's own SQL could change it: `SET bb.actor = 'bob'` before a
// CREATE TABLE put bob's name on the record. Now each logs in as a role whose
// name is the agent's, so the Blackbox reads it from session_user, which a
// session cannot change:
//
//   - on an agent's own branch, that branch's role, agent-<id>, which is how
//     the agent connects anyway;
//   - elsewhere, the account's agent role, agent:<email>, which an agent key
//     already logs in as through the Gateway: the account's data access,
//     never its admin grant, and an agent to the Blackbox.
//
// Where neither can be had the session still runs, and says less rather than
// something forgeable:
//
//   - a branch whose Blackbox predates agent roles keeps the path it always
//     had (db_client, the name in bb.actor) until `fox ledger upgrade`, since
//     its bb._ctx would take db_agent for a person, which is worse;
//   - any other failure logs in as the shared agent role with the name as
//     claimed (bb.claimed_actor), which the Blackbox records as a claim, never
//     as the actor.

// engineLoginMode says what a session's record can be trusted for.
type engineLoginMode int

const (
	loginOwn     engineLoginMode = iota // a role of the agent's own: session_user is the agent
	loginLegacy                         // an old Blackbox: the shared role, the name in bb.actor
	loginClaimed                        // the shared agent role, the name only claimed
)

// engineLogin is the role an engine agent session logs in as, and how.
type engineLogin struct {
	role, password string
	mode           engineLoginMode
}

// engineAgentLogin picks the login for an engine agent session on a branch,
// acting for account (an email, or an agent key's "agent:<email>"; "" or a
// name that is not an account for the engine's own sessions, which keep the
// shared role and their label).
func engineAgentLogin(branchName, account string) engineLogin {
	if branchName == "" {
		branchName = "main"
	}
	shared := func(mode engineLoginMode) engineLogin {
		role, asAgent := agentLoginRole(branchName)
		pw := ClientRolePassword()
		if asAgent {
			pw = AgentClientRolePassword()
		}
		return engineLogin{role: role, password: pw, mode: mode}
	}
	// An agent's own branch: its own role, made with the branch.
	if strings.HasPrefix(branchName, "agent-") {
		if err := ensureAgentRoles(branchName); err != nil {
			return shared(loginLegacy)
		}
		return engineLogin{role: branchName, password: AgentRolePassword(branchName), mode: loginOwn}
	}
	email := strings.TrimPrefix(account, agentKeyRolePrefix)
	if !strings.Contains(email, "@") {
		return shared(loginLegacy)
	}
	switch err := EnsureAgentKeyRole(branchName, email); {
	case err == nil:
		return engineLogin{role: AgentKeyRole(email), password: AgentKeyRolePassword(email), mode: loginOwn}
	case errors.Is(err, ErrAgentRolesNeedUpgrade):
		return shared(loginLegacy)
	default:
		// stderr, never stdout: `fox mcp` speaks JSON-RPC on stdout.
		log.Printf("agent role for %s on %q: %v (its name is recorded as claimed)", email, branchName, err)
		return shared(loginClaimed)
	}
}

// engineSessionOptions is what a session logging in this way is told, as
// PGOPTIONS: the agent's name only where nothing better says it.
func engineSessionOptions(l engineLogin, branchName, actor string) string {
	switch l.mode {
	case loginLegacy:
		if strings.HasPrefix(branchName, "agent-") {
			return "" // the branch carries its actor as a database default
		}
		return "-c bb.actor=" + actor + " -c bb.actor_kind=agent"
	case loginClaimed:
		return "-c bb.claimed_actor=" + actor + " -c bb.actor_kind=agent"
	}
	return ""
}
