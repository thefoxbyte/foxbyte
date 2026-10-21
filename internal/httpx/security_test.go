// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func headersFor(t *testing.T, policy, host string, overTLS bool) http.Header {
	t.Helper()
	h := SecurityHeaders(policy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = host
	if overTLS {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result().Header
}

func TestEveryResponseCarriesTheBaseline(t *testing.T) {
	h := headersFor(t, "", "db.example.com", false)
	for k, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if h.Get("Content-Security-Policy") != "" {
		t.Error("an empty policy still set a Content-Security-Policy")
	}
	if headersFor(t, APIPolicy, "x", false).Get("Content-Security-Policy") != APIPolicy {
		t.Error("the policy given was not set")
	}
}

// HSTS binds a host name, not a port: never to this machine, never over HTTP.
func TestHSTSOnlyOverTLSToARealName(t *testing.T) {
	for _, c := range []struct {
		host string
		tls  bool
		want bool
	}{
		{"db.example.com", true, true},
		{"db.example.com:8080", true, true},
		{"db.example.com", false, false},
		{"localhost:8080", true, false},
		{"127.0.0.1:8080", true, false},
		{"[::1]:8080", true, false},
		{"127.0.0.2", true, false},
	} {
		got := headersFor(t, "", c.host, c.tls).Get("Strict-Transport-Security") != ""
		if got != c.want {
			t.Errorf("host %q tls %v: HSTS %v, want %v", c.host, c.tls, got, c.want)
		}
	}
}

// The console's policy keeps scripts to this server and the page unframeable.
func TestTheConsolePolicy(t *testing.T) {
	for _, must := range []string{"script-src 'self';", "frame-ancestors 'none'", "object-src 'none'", "connect-src 'self'"} {
		if !strings.Contains(ConsolePolicy, must) {
			t.Errorf("ConsolePolicy lacks %q", must)
		}
	}
	if strings.Contains(ConsolePolicy, "script-src 'self' 'unsafe-inline'") || strings.Contains(ConsolePolicy, "unsafe-eval") {
		t.Error("ConsolePolicy lets inline or eval'd script run")
	}
}

// The console's fonts are bundled, so the page may load nothing from another
// site: no stylesheet, no font file. Opening the console contacts this server
// only.
func TestTheConsolePolicyLoadsNothingFromElsewhere(t *testing.T) {
	for _, must := range []string{"style-src 'self' 'unsafe-inline';", "font-src 'self';"} {
		if !strings.Contains(ConsolePolicy, must) {
			t.Errorf("ConsolePolicy lacks %q", must)
		}
	}
	if strings.Contains(ConsolePolicy, "https:") || strings.Contains(ConsolePolicy, "http:") {
		t.Errorf("ConsolePolicy names another origin: %s", ConsolePolicy)
	}
}
