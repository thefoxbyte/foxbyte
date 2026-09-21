// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"net/url"
	"strings"
	"testing"
)

// The Gateway logs an agent in as its branch's own role using this password, so
// it must be reproducible from the install secret alone — and specific to one
// branch, or a key for one agent would open another's role.
func TestAgentRolePassword(t *testing.T) {
	a := AgentRolePassword("agent-alice")
	if a == "" {
		t.Fatal("AgentRolePassword returned an empty password")
	}
	if again := AgentRolePassword("agent-alice"); again != a {
		t.Errorf("not deterministic: %q then %q", a, again)
	}
	if b := AgentRolePassword("agent-bob"); b == a {
		t.Error("two branches derived the same password")
	}
	if a == pgPass() {
		t.Error("the derived password is the install secret itself")
	}
	if len(a) != 64 { // hex of SHA-256
		t.Errorf("length = %d, want 64 hex characters", len(a))
	}
}

// The DSN has to survive being parsed by a driver: the database is the branch
// (the Gateway's routing key), the user is the agent's role, and TLS is asked
// for, since the Gateway serves it.
func TestAgentGatewayDSN(t *testing.T) {
	t.Setenv(EnvGatewayHostPort, "localhost:6432")
	got := agentGatewayDSN("agent-alice", "key_secret/key+value")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("unparsable DSN %q: %v", got, err)
	}
	if u.Scheme != "postgresql" || u.Host != "localhost:6432" {
		t.Errorf("scheme/host = %q/%q, want postgresql/localhost:6432", u.Scheme, u.Host)
	}
	if u.Path != "/agent-alice" {
		t.Errorf("database = %q, want /agent-alice (the branch is the routing key)", u.Path)
	}
	if u.User.Username() != "agent-alice" {
		t.Errorf("user = %q, want agent-alice", u.User.Username())
	}
	if pw, _ := u.User.Password(); pw != "key_secret/key+value" {
		t.Errorf("password = %q, want it round-tripped through escaping", pw)
	}
	// Carried over from the DSN this replaced: an agent is never the superuser.
	if u.User.Username() == pgUser {
		t.Errorf("the agent DSN must not log in as the superuser %q", pgUser)
	}
	if !strings.Contains(u.RawQuery, "sslmode=require") {
		t.Errorf("query = %q, want sslmode=require", u.RawQuery)
	}

	// Listings show the DSN without the key: it is returned once, at creation.
	bare, err := url.Parse(agentGatewayDSN("agent-alice", ""))
	if err != nil {
		t.Fatalf("unparsable bare DSN: %v", err)
	}
	if _, ok := bare.User.Password(); ok {
		t.Error("a listing DSN must not carry a password")
	}
}

func TestGatewayHostPort(t *testing.T) {
	t.Setenv(EnvGatewayHostPort, "")
	if got := gatewayHostPort(); got != defaultGatewayHostPort {
		t.Errorf("default = %q, want %q", got, defaultGatewayHostPort)
	}
	host, port := splitGatewayHostPort()
	if host != "localhost" || port != "6432" {
		t.Errorf("split = %q/%q, want localhost/6432", host, port)
	}

	// `fox gateway --addr` is configurable, so agents must be able to be told
	// where it really is.
	t.Setenv(EnvGatewayHostPort, "db.internal:7000")
	if got := gatewayHostPort(); got != "db.internal:7000" {
		t.Errorf("override = %q, want db.internal:7000", got)
	}
	if host, port := splitGatewayHostPort(); host != "db.internal" || port != "7000" {
		t.Errorf("split override = %q/%q, want db.internal/7000", host, port)
	}
}
