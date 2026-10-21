// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"net"
	"net/http"
)

// ConsolePolicy is the Content-Security-Policy for the console's page.
//
// Scripts come only from this server, so a string that reaches the page as
// markup cannot run as code. Styles may be inline, since React writes them per
// element. Stylesheets and font files come from this server too: the fonts are
// bundled into the build, so opening the console asks no other site for
// anything. The page talks to this server and nothing else, and no other site
// may frame it, which is what stops a page elsewhere from dressing up the
// console's buttons (clickjacking).
const ConsolePolicy = "default-src 'self'; script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"font-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// APIPolicy is the Content-Security-Policy for a server that answers only
// machines: nothing it returns is a page, so nothing may load or frame it.
const APIPolicy = "default-src 'none'; frame-ancestors 'none'"

// hstsAge is a year: long enough to matter, and what browsers' preload rules ask.
const hstsAge = "max-age=31536000"

// SecurityHeaders sets the headers every response from a FoxByte server should
// carry. policy is a Content-Security-Policy for every response, or "" for a
// server that sets one on its pages itself.
//
//   - X-Frame-Options: DENY, for browsers that predate frame-ancestors.
//   - X-Content-Type-Options: nosniff, so a JSON answer or an uploaded file is
//     never run as a script because it looked like one.
//   - Referrer-Policy: same-origin, so a branch name in a URL does not leave in
//     the Referer of a link to another site.
//   - Strict-Transport-Security, on TLS only and never to a loopback name. HSTS
//     binds a host name, not a port: sent from https://localhost:8080 it would
//     force https onto every http://localhost dev server the person runs.
func SecurityHeaders(policy string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			if policy != "" {
				h.Set("Content-Security-Policy", policy)
			}
			h.Set("X-Frame-Options", "DENY")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "same-origin")
			if r.TLS != nil && !loopbackHost(r.Host) {
				h.Set("Strict-Transport-Security", hstsAge)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// loopbackHost reports whether a Host header names this machine.
func loopbackHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if host == "" || isLocalHost(host) || host == "[::1]" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
