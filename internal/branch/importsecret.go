// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"net/url"
	"strings"
)

// An import connects to a source somebody else named, from inside a branch
// container. Before this file, two things there carried the install's
// superuser password: the container's environment (PGPASSWORD, from the
// env-file every branch container is started with, and which every docker exec
// and the server's own walreceiver inherit) and nothing in the source address
// to stop libpq using it. A postgres:// source with no password in it made
// pg_dump, psql and a continuous import's subscription offer that password to
// whatever server answered, and a server can ask for it in clear text (audit
// GW-1). Two layers close it, so that neither alone has to be right:
//
//   - noAmbientPassword writes an explicit, empty password (and no password
//     file) into a source that carries none. libpq takes an option given in the
//     address over its environment, and refuses to send an empty password, so
//     the source is asked with nothing rather than with the superuser's.
//     This is the layer that covers CREATE SUBSCRIPTION, whose connection is
//     made by the server process, not by anything a docker exec can change.
//   - noAmbientPasswordEnv clears PGPASSWORD and PGPASSFILE for the docker
//     exec that runs the import's own tools. The local side of an import
//     (psql into the branch) uses the Unix socket, which needs no password.
//
// Branch containers still carry PGPASSWORD in their environment. Taking it out
// is the deeper fix, but an existing container keeps the environment it was
// created with, and the HA standby's replication may rely on it, so the two
// layers above deliberately do not depend on that.

// noAmbientPasswordEnv is the docker exec flags that keep the container's own
// credentials away from a client connecting to an import's source.
var noAmbientPasswordEnv = []string{"-e", "PGPASSWORD=", "-e", "PGPASSFILE=/dev/null"}

// noAmbientPassword returns a postgres:// or postgresql:// source that names
// its password explicitly: as given when it has one (in the user info or as a
// password= parameter), or empty when it has none, with passfile=/dev/null
// unless a password file is named. Anything that is not a postgres URI is
// returned unchanged.
func noAmbientPassword(src string) string {
	if !isPostgresDSN(src) {
		return src
	}
	scheme, rest, _ := strings.Cut(src, "://")
	authority, tail := rest, ""
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authority, tail = rest[:i], rest[i:]
	}
	path, query, _ := strings.Cut(tail, "?")
	hasPassword := false
	if at := strings.LastIndexByte(authority, '@'); at >= 0 && strings.Contains(authority[:at], ":") {
		hasPassword = true // user:password@ — even an empty one is explicit
	}
	hasPassfile := false
	if query != "" {
		for _, kv := range strings.Split(query, "&") {
			k, _, _ := strings.Cut(kv, "=")
			if dk, err := url.QueryUnescape(k); err == nil {
				k = dk
			}
			switch strings.TrimSpace(k) {
			case "password":
				hasPassword = true
			case "passfile":
				hasPassfile = true
			}
		}
	}
	var add []string
	if !hasPassword {
		add = append(add, "password=")
	}
	if !hasPassfile {
		add = append(add, "passfile="+url.QueryEscape("/dev/null"))
	}
	if len(add) == 0 {
		return src
	}
	if query != "" {
		query += "&"
	}
	return scheme + "://" + authority + path + "?" + query + strings.Join(add, "&")
}
