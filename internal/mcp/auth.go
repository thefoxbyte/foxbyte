// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// Authentication for the MCP server.
//
// The tools here create databases, run SQL and branch main: everything the
// engine can do. The server used to take none, relying on whoever started the
// process being trusted, which left two holes. Nothing tied a session to an
// account, so its changes were recorded against the shared role rather than
// anyone in particular; and a stdio server bridged to anything reachable (a
// socket, a container, a remote runner) handed all sixteen tools to whatever
// was on the other end. It now requires an API key, the same kind of key the
// Gateway and the REST API take, and acts as that key's account. A key scoped
// to one branch (an agent's) reaches only that branch.

// identity is who this server acts as for the life of the process.
type identity struct {
	Actor string // the key's account, recorded as the Blackbox actor
	Scope string // "" for an account key; a branch name for a scoped one
}

// me is set once, by authenticate, before any request is served.
var me identity

// ErrNoKey is returned when no key was given at all -- told apart from a wrong
// key so the message can explain how to make one.
var ErrNoKey = errors.New("no API key")

// KeyHelp is printed when the key is missing or rejected. stdout carries the
// MCP protocol, so this goes to stderr.
const KeyHelp = `fox mcp needs an API key: its tools create databases, run SQL and branch main,
and every change is recorded against the account the key belongs to.

  fox apikey create you@example.com mcp

Then give it to the MCP server as FOX_API_KEY (or --key) -- in a client
config that is the "env" block next to "command". A key scoped to one branch
limits the server to that branch.`

// authenticate verifies the key the server was started with and returns who it
// acts as. It reads the same store the control plane and Gateway use.
func authenticate(key string) (identity, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return identity{}, ErrNoKey
	}
	store, err := auth.OpenFromEnv()
	if err != nil {
		return identity{}, fmt.Errorf("opening the account store: %w", err)
	}
	u, scope, ok := store.VerifyKey(key)
	if !ok {
		return identity{}, errors.New("that API key is not valid (it may have been revoked)")
	}
	if u.Email == "" {
		return identity{}, errors.New("that API key has no account")
	}
	return identity{Actor: u.Email, Scope: scope}, nil
}

// Tools a branch-scoped key may not use at all: they either reach beyond one
// branch or act on main. An account key (no scope) is unaffected.
var scopedKeyRefuses = map[string]string{
	"create_branch":        "creating another agent's branch",
	"delete_branch":        "deleting another agent's branch",
	"list_branches":        "listing every agent's branch",
	"blackbox_diff":        "comparing two branches",
	"branch_before_change": "branching main",
}

// applyScope enforces a branch-scoped key on one tool call: it refuses the
// tools that reach past a single branch, and pins every "branch" argument to
// the key's own branch -- an absent one included, so a default of "main" can
// never be what a scoped key gets. Returns the arguments to use.
func applyScope(tool string, args []byte) ([]byte, error) {
	if me.Scope == "" {
		return args, nil
	}
	if what, refused := scopedKeyRefuses[tool]; refused {
		return nil, fmt.Errorf("this API key is limited to branch %q, so %s is out of reach", me.Scope, what)
	}
	var m map[string]any
	if len(args) > 0 {
		if err := json.Unmarshal(args, &m); err != nil {
			return nil, fmt.Errorf("arguments are not a JSON object: %w", err)
		}
	}
	if m == nil {
		m = map[string]any{}
	}
	if v, ok := m["branch"]; ok {
		if name, _ := v.(string); name != "" && name != me.Scope {
			return nil, fmt.Errorf("this API key is limited to branch %q, so %q is out of reach", me.Scope, name)
		}
	}
	m["branch"] = me.Scope
	out, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return out, nil
}
