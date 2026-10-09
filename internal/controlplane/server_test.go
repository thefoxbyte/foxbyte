// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestNameValidation(t *testing.T) {
	valid := []string{"qa", "agent-bob", "feature-123", "a", "x1-y2-z3"}
	invalid := []string{
		"",                      // empty
		"-bad",                  // leading dash
		"Bad",                   // uppercase
		"a b",                   // space
		"under_score",           // underscore
		strings.Repeat("a", 50), // too long (max 41)
	}
	for _, n := range valid {
		if !nameRe.MatchString(n) {
			t.Errorf("expected %q to be valid", n)
		}
	}
	for _, n := range invalid {
		if nameRe.MatchString(n) {
			t.Errorf("expected %q to be invalid", n)
		}
	}
}

// An API path that matched no route answers JSON, not the console's HTML.
//
// This is what crashed the Realtime page on a Standard build. The paid routes
// are not compiled into that binary, so /realtime/v1/branches/main/tables fell
// through to the console's catch-all and came back as index.html with status
// 200. The console's request helper turned that into an empty object, the page
// read a missing field out of it, and the error named a property rather than
// the absent route. Every other client would have failed just as obscurely.
//
// A console page address must still get index.html, or reloading a deep link
// breaks.
func TestUnmatchedAPIPathsAnswerJSON(t *testing.T) {
	mux := http.NewServeMux()
	serveUI(mux, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<!doctype html><html></html>")}})

	t.Run("an API path that does not exist", func(t *testing.T) {
		for _, p := range []string{
			"/api/branches/main/realtime/activity", // Enterprise-only: absent in a Standard build
			"/realtime/v1/branches/main/tables",
			"/api/does-not-exist",
		} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
			if rec.Code != 404 {
				t.Errorf("GET %s: status %d, want 404", p, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
				t.Errorf("GET %s: Content-Type %q, want JSON — a client cannot parse HTML", p, ct)
			}
			// And it says what is wrong, rather than leaving the caller to
			// discover it as a parse failure three layers up.
			if !strings.Contains(rec.Body.String(), "no such endpoint") {
				t.Errorf("GET %s: body %q does not say the endpoint is missing", p, rec.Body.String())
			}
		}
	})

	t.Run("a console page address still gets the app", func(t *testing.T) {
		// These are the router's addresses, not endpoints. Serving 404 here
		// would break a reload of any deep link.
		for _, p := range []string{"/realtime", "/dashboard", "/console", "/", "/branches/main"} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
			if rec.Code != 200 {
				t.Errorf("GET %s: status %d, want 200", p, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "<!doctype html>") {
				t.Errorf("GET %s did not return the console", p)
			}
		}
	})
}
