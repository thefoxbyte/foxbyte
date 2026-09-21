// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The console is served by the control plane over TLS, so OAuth must call back
// there and send the browser back there, and the session cookie must be Secure.
func TestURLDefaults(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	pub, web := urlDefaults(env(nil))
	if pub != "https://localhost:8080" || web != pub {
		t.Errorf("defaults = %q, %q; want https://localhost:8080 for both", pub, web)
	}
	pub, web = urlDefaults(env(map[string]string{"FOX_PUBLIC_URL": "https://db.example.com/"}))
	if pub != "https://db.example.com" || web != "https://db.example.com" {
		t.Errorf("public URL set: %q, %q; the web origin should follow it, without a trailing slash", pub, web)
	}
	pub, web = urlDefaults(env(map[string]string{"FOX_PUBLIC_URL": "https://api.example.com", "FOX_WEB_ORIGIN": "https://app.example.com"}))
	if pub != "https://api.example.com" || web != "https://app.example.com" {
		t.Errorf("both set: %q, %q", pub, web)
	}
}

func TestSessionCookieSameSite(t *testing.T) {
	cookie := func(cfg Config) *http.Cookie {
		rec := httptest.NewRecorder()
		(&Store{cfg: cfg}).setCookie(rec, "tok")
		return rec.Result().Cookies()[0]
	}
	same := cookie(Config{PublicURL: DefaultPublicURL, WebOrigin: DefaultPublicURL})
	if !same.Secure || same.SameSite != http.SameSiteLaxMode {
		t.Errorf("same-origin console: Secure=%v SameSite=%v; want Secure, Lax", same.Secure, same.SameSite)
	}
	cross := cookie(Config{PublicURL: "https://api.example.com", WebOrigin: "https://app.example.com"})
	if !cross.Secure || cross.SameSite != http.SameSiteNoneMode {
		t.Errorf("separately hosted UI: Secure=%v SameSite=%v; want Secure, None", cross.Secure, cross.SameSite)
	}
}
