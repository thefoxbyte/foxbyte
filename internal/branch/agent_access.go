// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/foxbyte/foxbyte/internal/auth"
)

// How an agent reaches its branch.
//
// The branch's Postgres publishes no host port on purpose (see startContainer):
// a direct connection would bypass the Gateway, its API key, TLS and the
// Blackbox attribution. The container address the Agent Branch API used to hand
// out therefore only resolves inside the VM, so on macOS and Windows an agent
// running on the host was given a database it could not open.
//
// So an agent connects the way every other client does — through the Gateway —
// with two additions that keep it no more privileged than before:
//
//   - its key is scoped to its own branch, so it cannot reach the control plane
//     or another agent's data (auth.CreateScopedAPIKey, honoured by Authn and by
//     the Gateway);
//   - the Gateway logs it in as the branch's own "agent-<id>" role, whose
//     password is derived below, so session_user remains the agent and the
//     recorded actor stays non-forgeable.
const (
	// EnvGatewayHostPort overrides where agents are told to reach the Gateway.
	// Needed when `fox gateway --addr` is not the default, or when the Gateway
	// is published somewhere other than localhost.
	EnvGatewayHostPort = "FOX_GATEWAY_HOSTPORT"

	defaultGatewayHostPort = "localhost:6432"
)

// AgentRolePassword derives an agent role's password from the per-install
// secret. Deriving rather than storing means the Gateway can log in as the role
// without the password being kept anywhere or passed between processes, and a
// password for one branch is useless on another.
func AgentRolePassword(branchName string) string {
	m := hmac.New(sha256.New, []byte(pgPass()))
	m.Write([]byte("fox-agent-role:" + branchName))
	return hex.EncodeToString(m.Sum(nil))
}

// gatewayHostPort is where an agent should reach the Gateway.
func gatewayHostPort() string {
	if v := strings.TrimSpace(os.Getenv(EnvGatewayHostPort)); v != "" {
		return v
	}
	return defaultGatewayHostPort
}

// splitGatewayHostPort reports the Gateway's host and port separately, for the
// host/port fields of Info.
func splitGatewayHostPort() (string, string) {
	host, port, err := net.SplitHostPort(gatewayHostPort())
	if err != nil {
		return gatewayHostPort(), ""
	}
	return host, port
}

// agentGatewayDSN builds an agent's connection string. The database name is the
// branch (the Gateway's routing key), the user is the branch's agent role, and
// the password is a branch-scoped API key. An empty password is used for
// listings, where the key is not known — it is shown once, when the branch is
// created.
func agentGatewayDSN(branchName, key string) string {
	u := url.URL{Scheme: "postgresql", Host: gatewayHostPort(), Path: "/" + branchName}
	if key == "" {
		u.User = url.User(branchName)
	} else {
		u.User = url.UserPassword(branchName, key)
	}
	u.RawQuery = "sslmode=require"
	return u.String()
}

// mintAgentKey issues the branch-scoped key that goes in an agent's DSN.
//
// It opens the store itself because an agent branch is created from three
// places — the Agent Branch API, `fox mcp` and the CLI — and only the first has
// an authenticated caller to inherit a store from.
func mintAgentKey(branchName string) (string, error) {
	store, err := auth.OpenFromEnv()
	if err != nil {
		return "", err
	}
	defer store.Close()
	uid, ok := store.AnyUserID()
	if !ok {
		return "", fmt.Errorf("no account exists yet to own the key — run `fox start` first")
	}
	key, _, err := store.CreateScopedAPIKey(uid, "agent "+branchName, branchName)
	if err != nil {
		return "", err
	}
	return key, nil
}

// revokeAgentKeys deletes the keys scoped to a branch, so an agent's credential
// does not outlive the branch it was issued for. Best-effort: failing to revoke
// must not stop the branch being deleted, but it must not pass unnoticed — the
// key would still open a branch that is about to stop existing.
func revokeAgentKeys(branchName string) {
	store, err := auth.OpenFromEnv()
	if err != nil {
		log.Printf("agent branch %s: opening the key store to revoke its key: %v", branchName, err)
		return
	}
	defer store.Close()
	if err := store.RevokeScopeKeys(branchName); err != nil {
		log.Printf("agent branch %s: could not revoke its branch-scoped key: %v", branchName, err)
	}
}
