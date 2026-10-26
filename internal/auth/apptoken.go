// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"time"
)

// CheckAppToken is application identity's check in Go, for what the engine
// records outside an application's own transaction: an agent session started
// through the Agent API "for" a user (F1 design, section 16). Inside a
// transaction the check is bb.act_for (internal/ledger/identity.sql); this one
// takes the same token and applies the same rules in the same order, so a
// token means one thing wherever it is presented:
//
//   - the header is exactly EdDSA, an optional "typ":"JWT", and a kid;
//   - iss and kid name a registered key, and the signature verifies under it;
//   - the key is not revoked;
//   - the caller is the application's own account, never its agent keys (in
//     SQL, session_user is the account's own role);
//   - aud is this install, branch (when present) the branch named, and the
//     times within 30 seconds of now and no longer than the application allows.
//
// It answers with the state to record and never errors: a token that fails is
// "none" with the reason, and Refuse says the application asked for failures
// to be refused rather than recorded.

// AppAssertion is what a token checked to.
type AppAssertion struct {
	Actor  string `json:"app_actor,omitempty"`
	State  string `json:"app_state"` // asserted | none
	Issuer string `json:"app_issuer,omitempty"`
	Kid    string `json:"app_kid,omitempty"`
	Tenant string `json:"app_tenant,omitempty"`
	Note   string `json:"app_note,omitempty"`
	// Refuse: the token failed, and its application registered on_invalid
	// "refuse". The caller should refuse what it was asked to do.
	Refuse bool `json:"-"`
}

const skew = 30 // seconds, as in bb.act_for

// CheckAppToken checks token as presented by caller, who authenticated with an
// agent key when viaAgentKey, for branch (empty: no branch claim allowed to
// fail on), at now.
func (s *Store) CheckAppToken(token string, caller User, viaAgentKey bool, branch string, now time.Time) AppAssertion {
	refused := func(reason string, refuse bool) AppAssertion {
		return AppAssertion{State: "none", Note: "token refused: " + reason, Refuse: refuse}
	}
	if token == "" || len(token) > 8192 {
		return refused("malformed", false)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return refused("malformed", false)
	}
	hb, err1 := b64url(parts[0])
	bb, err2 := b64url(parts[1])
	sig, err3 := b64url(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return refused("malformed", false)
	}
	var hdr, body map[string]any
	if json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(bb, &body) != nil || hdr == nil || body == nil {
		return refused("malformed", false)
	}
	// The fixed header, before the payload is trusted for anything.
	alg, _ := hdr["alg"].(string)
	kid, kidOK := hdr["kid"].(string)
	typ, hasTyp := hdr["typ"]
	if alg != "EdDSA" || !kidOK || (hasTyp && typ != "JWT") {
		return refused("header", false)
	}
	for k := range hdr {
		if k != "alg" && k != "typ" && k != "kid" {
			return refused("header", false)
		}
	}
	iss, _ := text(body["iss"])
	app, err := s.App(iss)
	if err != nil {
		return refused("unknown key", false)
	}
	var key *AppKey
	for i := range app.Keys {
		if app.Keys[i].Kid == kid {
			key = &app.Keys[i]
		}
	}
	if key == nil {
		return refused("unknown key", false)
	}
	refuse := app.OnInvalid == "refuse"
	pub, err := hex.DecodeString(key.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return refused("bad signature", refuse)
	}
	if key.Revoked != nil && *key.Revoked <= now.Unix() {
		return refused("revoked key", refuse)
	}
	// Binding: only the application's own account. An agent key of that
	// account logs in as another role in SQL, and is refused here too.
	if viaAgentKey || app.Account == "" || caller.Email != app.Account {
		return refused("wrong session role", refuse)
	}
	installID, err := s.InstallID()
	if err != nil {
		return refused("wrong audience", refuse)
	}
	sub, _ := text(body["sub"])
	tenant, _ := text(body["tenant"])
	iat, iatOK := number(body["iat"])
	exp, expOK := number(body["exp"])
	nowS := float64(now.UnixNano()) / 1e9
	aud, _ := text(body["aud"])
	bclaim, hasBranch := text(body["branch"])
	_, present := body["branch"]
	hasBranch = hasBranch || present
	switch {
	case sub == "" || len(sub) > 256:
		return refused("malformed", refuse)
	case aud != installID:
		return refused("wrong audience", refuse)
	case hasBranch && bclaim != branch:
		return refused("wrong branch", refuse)
	case !iatOK || !expOK || exp < iat:
		return refused("malformed", refuse)
	case iat > nowS+skew:
		return refused("not yet valid", refuse)
	case exp < nowS-skew:
		return refused("expired", refuse)
	case exp-iat > float64(app.MaxLife):
		return refused("life too long", refuse)
	}
	return AppAssertion{Actor: sub, State: "asserted", Issuer: app.Name, Kid: key.Kid, Tenant: tenant}
}

// text is a claim as Postgres's ->> reads it: a string as itself, any other
// JSON value as its JSON text, and no value for a JSON null or no claim.
func text(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		return x, true
	default:
		b, err := json.Marshal(x)
		return string(b), err == nil
	}
}

// b64url decodes base64url with or without padding, refusing anything else,
// as bb_f1.b64url does.
func b64url(s string) ([]byte, error) {
	if strings.ContainsAny(s, "+/") {
		return nil, base64.CorruptInputError(0)
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// number reads a JSON number as Postgres's ::numeric would: a JSON number, or
// a string holding one.
func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case string:
		var f float64
		if err := json.NewDecoder(bytes.NewReader([]byte(x))).Decode(&f); err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}
