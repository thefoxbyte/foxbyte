// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": true, "localhost:8080": true, "[::1]:6432": true, "127.0.0.2:1": true,
		":8080": false, "0.0.0.0:8080": false, "[::]:8080": false, "10.0.0.5:8080": false, "example.com:80": false,
	} {
		if got := IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestAllowedOrigin(t *testing.T) {
	const conf = "https://localhost:8080"
	cases := map[string]bool{
		"https://localhost:8080":  true,  // the UI itself
		"https://127.0.0.1:8080":  true,  // the same UI by address
		"https://[::1]:8080":      true,  //
		"http://localhost:8080":   false, // another scheme
		"https://localhost:3000":  false, // any other local page — a dev server, a tool's UI
		"http://localhost:5173":   false, // the UI dev server, unless FOX_DEV_CORS
		"https://evil.example":    false,
		"":                        false,
		"https://localhost.evil.": false,
	}
	t.Setenv("FOX_DEV_CORS", "")
	for o, want := range cases {
		if got := AllowedOrigin(conf, o); got != want {
			t.Errorf("AllowedOrigin(%q) = %v, want %v", o, got, want)
		}
	}
	t.Setenv("FOX_DEV_CORS", "1")
	if !AllowedOrigin(conf, "http://localhost:5173") {
		t.Error("FOX_DEV_CORS=1 should admit the local UI dev server")
	}
	if AllowedOrigin(conf, "https://evil.example") {
		t.Error("FOX_DEV_CORS must not admit a remote origin")
	}
	// A UI on its own origin is allowed exactly, and local pages are not.
	t.Setenv("FOX_DEV_CORS", "")
	if !AllowedOrigin("https://db.example.com", "https://db.example.com") || AllowedOrigin("https://db.example.com", "https://localhost:8080") {
		t.Error("a hosted UI origin is matched wrong")
	}
}

func TestCORSHeaders(t *testing.T) {
	h := CORS("https://localhost:8080")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for origin, want := range map[string]string{"https://localhost:8080": "https://localhost:8080", "https://evil.example": ""} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != want {
			t.Errorf("origin %q: Allow-Origin %q, want %q", origin, got, want)
		}
	}
}

func TestLimitBodies(t *testing.T) {
	var read int
	h := LimitBodies(10, func(r *http.Request) bool { return r.URL.Path == "/upload" })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		read = len(b)
	}))
	body := strings.Repeat("x", 100)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api", strings.NewReader(body)))
	if read != 10 {
		t.Errorf("capped route read %d bytes, want 10", read)
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/upload", strings.NewReader(body)))
	if read != 100 {
		t.Errorf("exempt route read %d bytes, want 100", read)
	}
}
