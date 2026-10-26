// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// tokenFor signs a token with priv; hdr and claims override the defaults.
func tokenFor(priv ed25519.PrivateKey, hdr, claims map[string]any, flip bool) string {
	h := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": "k1"}
	for k, v := range hdr {
		if v == nil {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sig := ed25519.Sign(priv, []byte(in))
	if flip {
		sig[0] ^= 1
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// The same rules as bb.act_for, in the same order, with the same words: what
// the integration suite asserts of the SQL, asserted here of the Go.
func TestCheckAppToken(t *testing.T) {
	s := testStore(t)
	app, _ := s.CreateUser("shop@example.com", "password123")
	other, _ := s.CreateUser("other@example.com", "password123")
	strict, _ := s.CreateUser("strict@example.com", "password123")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	spub, spriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := s.RegisterApp("shop", "shop@example.com", 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAppKey("shop", "k1", pub); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterApp("strict", "strict@example.com", 0, "refuse"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAppKey("strict", "k1", spub); err != nil {
		t.Fatal(err)
	}
	aud, _ := s.InstallID()
	now := time.Now()
	claims := func(over map[string]any) map[string]any {
		c := map[string]any{"iss": "shop", "sub": "alice", "aud": aud, "iat": now.Unix(), "exp": now.Unix() + 300}
		for k, v := range over {
			c[k] = v
		}
		return c
	}
	ok := tokenFor(priv, nil, claims(nil), false)
	if a := s.CheckAppToken(ok, app, false, "agent-x", now); a.State != "asserted" || a.Actor != "alice" || a.Issuer != "shop" || a.Kid != "k1" || a.Note != "" {
		t.Fatalf("a valid token: %+v", a)
	}
	if a := s.CheckAppToken(tokenFor(priv, nil, claims(map[string]any{"tenant": "acme", "branch": "agent-x"}), false), app, false, "agent-x", now); a.Tenant != "acme" || a.State != "asserted" {
		t.Errorf("tenant and branch: %+v", a)
	}
	for _, c := range []struct {
		name, token string
		caller      User
		agent       bool
		when        time.Time
		reason      string
	}{
		{"empty", "", app, false, now, "malformed"},
		{"two parts", "a.b", app, false, now, "malformed"},
		{"not base64", "a.b.c!", app, false, now, "malformed"},
		{"oversized", string(make([]byte, 8193)), app, false, now, "malformed"},
		{"HS256", tokenFor(priv, map[string]any{"alg": "HS256"}, claims(nil), false), app, false, now, "header"},
		{"none", tokenFor(priv, map[string]any{"alg": "none"}, claims(nil), false), app, false, now, "header"},
		{"no kid", tokenFor(priv, map[string]any{"kid": nil}, claims(nil), false), app, false, now, "header"},
		{"extra header", tokenFor(priv, map[string]any{"jku": "https://x"}, claims(nil), false), app, false, now, "header"},
		{"typ JWS", tokenFor(priv, map[string]any{"typ": "JWS"}, claims(nil), false), app, false, now, "header"},
		{"unknown kid", tokenFor(priv, map[string]any{"kid": "k9"}, claims(nil), false), app, false, now, "unknown key"},
		{"unknown iss", tokenFor(priv, nil, claims(map[string]any{"iss": "nope"}), false), app, false, now, "unknown key"},
		{"a bit changed", tokenFor(priv, nil, claims(nil), true), app, false, now, "bad signature"},
		{"another key", tokenFor(evil, nil, claims(nil), false), app, false, now, "bad signature"},
		{"another account", ok, other, false, now, "wrong session role"},
		{"the account's agent key", ok, app, true, now, "wrong session role"},
		{"another install", tokenFor(priv, nil, claims(map[string]any{"aud": "install-other"}), false), app, false, now, "wrong audience"},
		{"another branch", tokenFor(priv, nil, claims(map[string]any{"branch": "main"}), false), app, false, now, "wrong branch"},
		{"no sub", tokenFor(priv, nil, claims(map[string]any{"sub": ""}), false), app, false, now, "malformed"},
		{"expired", ok, app, false, now.Add(331 * time.Second), "expired"},
		{"not yet valid", tokenFor(priv, nil, claims(map[string]any{"iat": now.Unix() + 60, "exp": now.Unix() + 120}), false), app, false, now, "not yet valid"},
		{"too long a life", tokenFor(priv, nil, claims(map[string]any{"exp": now.Unix() + 301}), false), app, false, now, "life too long"},
	} {
		a := s.CheckAppToken(c.token, c.caller, c.agent, "agent-x", c.when)
		if a.State != "none" || a.Note != "token refused: "+c.reason || a.Actor != "" || a.Refuse {
			t.Errorf("%s: %+v, want none with %q, not refused", c.name, a, c.reason)
		}
	}
	// 30 seconds of skew either way, as in SQL.
	if a := s.CheckAppToken(ok, app, false, "agent-x", now.Add(329*time.Second)); a.State != "asserted" {
		t.Errorf("within the skew after expiry: %+v", a)
	}
	// on_invalid refuse: a failure after the key is found says to refuse; one
	// before it is known whose key it is cannot.
	st := tokenFor(spriv, nil, claims(map[string]any{"iss": "strict"}), false)
	if a := s.CheckAppToken(st, other, false, "agent-x", now); !a.Refuse || a.Note != "token refused: wrong session role" {
		t.Errorf("refuse: %+v", a)
	}
	if a := s.CheckAppToken(st, strict, false, "agent-x", now); a.State != "asserted" || a.Refuse {
		t.Errorf("strict, valid: %+v", a)
	}
	if a := s.CheckAppToken(tokenFor(spriv, map[string]any{"kid": "k9"}, claims(map[string]any{"iss": "strict"}), false), strict, false, "agent-x", now); a.Refuse {
		t.Errorf("an unknown key cannot say to refuse: %+v", a)
	}
	// Revoked from a moment.
	if err := s.RevokeAppKey("shop", "k1", nil); err != nil {
		t.Fatal(err)
	}
	if a := s.CheckAppToken(ok, app, false, "agent-x", time.Now().Add(time.Second)); a.Note != "token refused: revoked key" {
		t.Errorf("revoked: %+v", a)
	}
}
