// SPDX-License-Identifier: AGPL-3.0-or-later

// Package httpx holds what the control plane and the Agent API both need to be
// safe on a network: the server's timeouts, a cap on request bodies, the
// browser origins allowed to call them, and whether an address is loopback.
package httpx

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Server returns an http.Server with timeouts. The bare http.ListenAndServe has
// none, so a client that opens connections and sends its headers one byte at a
// time holds them open for ever. There is no write timeout: imports and
// pipeline runs stream their progress for as long as they take.
func Server(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
}

// MaxBody is the largest request body a JSON endpoint reads. A SQL script in
// the console or a pipeline spec fits comfortably; anything larger is refused
// rather than held in memory.
const MaxBody = 8 << 20

// LimitBodies caps every request body at max bytes, except requests for which
// exempt returns true (a file upload has its own, larger limit).
func LimitBodies(max int64, exempt func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && (exempt == nil || !exempt(r)) {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsLoopback reports whether a listen address is reachable only from this
// machine. An empty host (":8080"), 0.0.0.0 and :: listen on every interface.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsLoopbackConn reports whether a connection came from this machine.
func IsLoopbackConn(remote net.Addr) bool {
	if remote == nil {
		return false
	}
	return IsLoopback(remote.String())
}

// AllowedOrigin reports whether a browser page at reqOrigin may call the API
// with the user's cookies. Allowed: the configured UI origin, and the same
// scheme and port on another name for this machine (localhost, 127.0.0.1, [::1])
// when the configured one is itself local. Any other local port is allowed only
// with FOX_DEV_CORS=1, for the hot-reloading UI dev server: without that, any
// page served from any local port — a dev server, a tool's web UI — could act
// as the signed-in user.
func AllowedOrigin(configured, reqOrigin string) bool {
	if reqOrigin == "" {
		return false
	}
	if reqOrigin == configured {
		return true
	}
	req, err := url.Parse(reqOrigin)
	if err != nil || !isLocalHost(req.Hostname()) {
		return false
	}
	if devCORS() {
		return true
	}
	conf, err := url.Parse(configured)
	if err != nil || !isLocalHost(conf.Hostname()) {
		return false
	}
	return req.Scheme == conf.Scheme && port(req) == port(conf)
}

func devCORS() bool {
	switch strings.ToLower(strings.TrimSpace(brand.Getenv("DEV_CORS"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func isLocalHost(h string) bool {
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// CORS answers cross-origin requests for the allowed origins only. For any
// other origin no Access-Control-Allow-Origin is sent, so the browser keeps the
// response from the page.
func CORS(configured string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Origin")
			if o := r.Header.Get("Origin"); AllowedOrigin(configured, o) {
				w.Header().Set("Access-Control-Allow-Origin", o)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
