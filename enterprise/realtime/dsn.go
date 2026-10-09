//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// The realtime DSN: one string an application is given, in the shape its
// developers already know.
//
//	fox-realtime://rtk_<secret>@127.0.0.1:8080/mybranch?sslmode=require
//
// Deliberately a connection string rather than an endpoint plus a header,
// because that is how a database is configured everywhere else — one value in
// one environment variable, not three that have to agree.
//
// The key sits in userinfo, where a Postgres URL puts its password, and a
// client turns it into an Authorization header. It is never a path segment and
// never a query parameter: a URL path is written to access logs, kept in
// browser history and sent on in Referer, so a secret that appears in one has
// to be treated as disclosed. Userinfo is stripped by that same logging, which
// is the whole reason the convention exists.
//
// sslmode carries libpq's meanings, because the audience has met them and
// because the default install matches one of them exactly: the control plane
// serves a self-signed certificate, which is encryption without a verifiable
// identity — `require`. A real certificate is `verify-full`. Plain HTTP exists
// only as the loopback fallback when no certificate could be made at all, and
// has to be asked for by name.
const (
	// Scheme is the DSN's URL scheme.
	Scheme = "fox-realtime"

	// APIPrefix is the realtime front door: its own namespace on the port the
	// console already uses, so an application needs no second address, no
	// second certificate and no second firewall rule. Separate from /api/
	// because it is reached with a different kind of credential and must not
	// inherit the control plane's auth gate.
	APIPrefix = "/realtime/v1"
)

// SSLMode is how a client should treat the server's certificate.
type SSLMode string

const (
	// SSLRequire encrypts without verifying the certificate. The default,
	// because a default install serves a self-signed one.
	SSLRequire SSLMode = "require"
	// SSLVerifyFull encrypts and verifies, for an install with a real
	// certificate and a name that matches it.
	SSLVerifyFull SSLMode = "verify-full"
	// SSLDisable is plain HTTP — only the loopback fallback, and only when
	// asked for by name.
	SSLDisable SSLMode = "disable"
)

func (m SSLMode) valid() bool {
	switch m {
	case SSLRequire, SSLVerifyFull, SSLDisable:
		return true
	}
	return false
}

// TLS reports whether the connection is encrypted.
func (m SSLMode) TLS() bool { return m != SSLDisable }

// Verify reports whether the certificate must check out.
func (m SSLMode) Verify() bool { return m == SSLVerifyFull }

// DSN is a parsed realtime connection string.
type DSN struct {
	Host   string // host:port, as dialled
	Branch string
	Key    string // the realtime key; empty in a DSN printed without one
	SSL    SSLMode
}

// String renders the DSN, key included. It is a secret: print it once, into
// something that stores secrets, and prefer Redacted anywhere else.
func (d DSN) String() string { return d.format(d.Key) }

// Redacted renders the DSN with the key replaced by its visible prefix, for
// logs, listings and anything a screenshot might reach.
func (d DSN) Redacted() string {
	key := ""
	if d.Key != "" {
		key = redactKey(d.Key)
	}
	return d.format(key)
}

func redactKey(k string) string {
	if len(k) <= 12 {
		return k + "…"
	}
	return k[:12] + "…"
}

func (d DSN) format(key string) string {
	u := url.URL{Scheme: Scheme, Host: d.Host, Path: "/" + d.Branch}
	if key != "" {
		u.User = url.User(key)
	}
	if d.SSL != "" && d.SSL != SSLRequire {
		u.RawQuery = "sslmode=" + string(d.SSL)
	}
	return u.String()
}

// BaseURL is the HTTP origin the DSN points at.
func (d DSN) BaseURL() string {
	scheme := "https"
	if !d.SSL.TLS() {
		scheme = "http"
	}
	return scheme + "://" + d.Host
}

// StreamURL is the feed this DSN subscribes to. since is the commit_lsn of the
// last change the client saw, and is omitted when empty — which means "from
// now", not "from the beginning".
//
// The key is not in it, and must not be: it goes in the Authorization header.
func (d DSN) StreamURL(since string) string {
	u := d.BaseURL() + APIPrefix + "/branches/" + url.PathEscape(d.Branch) + "/stream"
	if since != "" {
		u += "?since=" + url.QueryEscape(since)
	}
	return u
}

// TablesURL lists what this branch can stream, so an application can discover
// the shape it is subscribing to instead of being told out of band.
func (d DSN) TablesURL() string {
	return d.BaseURL() + APIPrefix + "/branches/" + url.PathEscape(d.Branch) + "/tables"
}

// ParseDSN reads a realtime connection string.
//
// Errors name the DSN's own grammar rather than the URL library's, because the
// person reading them is holding a connection string they were given and has no
// reason to know how it is parsed.
func ParseDSN(raw string) (DSN, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DSN{}, fmt.Errorf("empty realtime URL")
	}
	// The scheme is checked before url.Parse, not after. A bare "host:port/b"
	// — the likeliest way to get this wrong — makes url.Parse fail with "first
	// path segment in URL cannot contain colon", which tells someone holding a
	// connection string nothing they can act on.
	if !strings.HasPrefix(raw, Scheme+"://") {
		return DSN{}, fmt.Errorf("a realtime URL starts with %s:// (got %q)", Scheme, raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return DSN{}, fmt.Errorf("not a realtime URL: %w", err)
	}
	if u.Host == "" {
		return DSN{}, fmt.Errorf("no host in %q: expected %s://<key>@host:port/<branch>", raw, Scheme)
	}
	// A port is required rather than defaulted. The control plane's port is
	// configurable, so guessing one produces a connection refused somewhere
	// the user did not ask to connect — a worse error than this one.
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return DSN{}, fmt.Errorf("no port in %q: expected %s://<key>@host:port/<branch>", u.Host, Scheme)
	}
	d := DSN{Host: u.Host, SSL: SSLRequire}
	if u.User != nil {
		// The key may be given as userinfo's username (what this package
		// prints) or as its password (what someone transcribing a Postgres URL
		// is likely to type). Both are accepted; neither is in the path.
		if pw, ok := u.User.Password(); ok && pw != "" {
			d.Key = pw
		} else {
			d.Key = u.User.Username()
		}
	}
	d.Branch = strings.Trim(u.Path, "/")
	if d.Branch == "" {
		return DSN{}, fmt.Errorf("no branch in %q: expected %s://<key>@host:port/<branch>", raw, Scheme)
	}
	if strings.Contains(d.Branch, "/") {
		return DSN{}, fmt.Errorf("%q names more than one path segment; a realtime URL ends at the branch", u.Path)
	}
	if q := u.Query(); q.Has("sslmode") {
		d.SSL = SSLMode(q.Get("sslmode"))
		if !d.SSL.valid() {
			return DSN{}, fmt.Errorf("sslmode=%q is not one of require, verify-full, disable", q.Get("sslmode"))
		}
	}
	return d, nil
}
