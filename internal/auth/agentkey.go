// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// An agent key is the key to hand an AI agent instead of your own.
//
// An agent given a person's key used to be that person: the Gateway logged it
// in as the person's role, the Blackbox recorded its changes as a human's, and
// the guardrails that apply only to agents did not apply to it. An agent key
// opens the same branches its owner can, as an agent: the Gateway logs it in
// as "agent:<email>" (branch.AgentKeyRole), which the Blackbox records as an
// agent whatever the session says, and which never holds the owner's admin
// grant, so it cannot override a guardrail either.
//
//	account key   key_   control plane, gateway, stream: the owner's full access, as the owner
//	agent key     key_   gateway and Agent API: the owner's branches, as an agent
//	scoped key    key_   that branch's SQL, and its stream
//	realtime key  rtk_   that branch's stream. Nothing else.
//
// Refused by the control plane (Authn): the console's SQL runs as a person, so
// an agent key there would be a person again. Accepted by the Agent API
// (AuthnAgents), whose every branch is an agent's anyway.
const KindAgent = "agent"

// CreateAgentKey mints an agent key for an account and returns the secret,
// which is shown once and never stored.
func (s *Store) CreateAgentKey(userID int64, name string) (string, KeyInfo, error) {
	if strings.TrimSpace(name) == "" {
		name = "agent"
	}
	secret := KeyPrefix + randToken(24)
	id := randToken(8)
	prefix := secret[:12]
	now := time.Now().Unix()
	if _, err := s.db.Exec(`INSERT INTO api_keys(id,user_id,name,key_hash,prefix,created,scope,kind) VALUES(?,?,?,?,?,?,'',?)`,
		id, userID, name, hashKey(secret), prefix, now, KindAgent); err != nil {
		return "", KeyInfo{}, err
	}
	return secret, KeyInfo{ID: id, Name: name, Prefix: prefix, Created: now, Kind: KindAgent}, nil
}

// AuthnAgents is Authn that also accepts an agent key. It is for the Agent API
// alone: everything it does is on an agent's branch, under the agent's own
// scoped key, so an agent may use it with the key it was given.
func (s *Store) AuthnAgents(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.userFromRequest(r)
		if !ok {
			if key := requestKey(r); key != "" {
				if ku, scope, kind, kok := s.VerifyKeyKind(key); kok && scope == "" && kind == KindAgent {
					u, ok = ku, true
					r = r.WithContext(context.WithValue(r.Context(), agentKeyCtx, true))
				}
			}
		}
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

type agentKeyCtxKey struct{}

var agentKeyCtx agentKeyCtxKey

// ViaAgentKey reports whether a request AuthnAgents let through came with an
// agent key rather than the account's own credential. Application identity
// needs to know: an agent key of an application's account is not the
// application (CheckAppToken).
func ViaAgentKey(ctx context.Context) bool {
	v, _ := ctx.Value(agentKeyCtx).(bool)
	return v
}

// requestKey is the API key a request carries, as a bearer token or in
// X-API-Key, or "".
func requestKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return r.Header.Get("X-API-Key")
}
