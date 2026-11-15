// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
)

// pinImportSource is the import guard for a source an import is about to
// connect to. It returns the connection string to use and the "name:ip" pins
// for branch.As.
//
// An admin's source passes or fails the guard and is used as given, as always.
// Anyone else's is held to the addresses the guard checked:
//
//   - postgres:// gains libpq's hostaddr, one address per host. libpq then
//     connects there and uses the name only for TLS, so nothing is looked up
//     again — not by pg_dump, not by a continuous import's subscription.
//   - mysql:// and mariadb:// are used as given; their tools run in throwaway
//     containers, and the pins become --add-host entries there. A MySQL client
//     connects to the host it is given and to nothing the server names.
//   - mongodb:// is held to one host, connected to directly (pinMongoSource),
//     and pinned like MySQL. A MongoDB client otherwise learns the other
//     members of a replica set from the server it reached and connects to
//     them too, and those names come from the remote server, not the guard.
//   - mongodb+srv:// is refused: it asks DNS which hosts to connect to, and
//     a record can name several, or different ones next time.
func pinImportSource(src string, admin bool) (string, []string, error) {
	if admin {
		return src, nil, checkImportSource(src, true)
	}
	if strings.HasPrefix(src, "mongodb+srv://") {
		return "", nil, fmt.Errorf("a mongodb+srv:// address lets DNS choose the servers to connect to, so only an admin may import from one; " +
			"use the mongodb:// address of a single member instead (mongodb://user:pass@host:27017/db)")
	}
	if strings.HasPrefix(src, "mongodb://") {
		var err error
		if src, err = pinMongoSource(src); err != nil {
			return "", nil, err
		}
	}
	found, err := vetImportSource(src, false)
	if err != nil {
		return "", nil, err
	}
	pins := make([]string, 0, len(found))
	for name, ip := range found {
		pins = append(pins, name+":"+ip)
	}
	sort.Strings(pins)
	if strings.HasPrefix(src, "postgres://") || strings.HasPrefix(src, "postgresql://") {
		if src, err = withHostaddr(src, found); err != nil {
			return "", nil, err
		}
	}
	return src, pins, nil
}

// mongoDiscoveryOptions are the URI options that let a MongoDB client go past
// the one host it was given: to the members a replica set names, or through a
// load balancer's mode (which cannot be combined with a direct connection).
// MongoDB reads option names without regard to case.
var mongoDiscoveryOptions = map[string]bool{
	"replicaset": true, "directconnection": true, "loadbalanced": true,
	"srvservicename": true, "srvmaxhosts": true,
}

// pinMongoSource rewrites an ordinary account's mongodb:// address so the
// client talks to the one host the guard checked and nothing else: a single
// host, directConnection=true, and no option that turns discovery back on.
// The rest of the address (credentials, database, other options) is kept as
// written. mongosh, which runs the import, honours directConnection as the
// drivers do, and still reads when the member named is a secondary.
func pinMongoSource(src string) (string, error) {
	scheme, userinfo, hosts, tail := splitURI(src)
	if strings.Contains(hosts, ",") {
		return "", fmt.Errorf("this MongoDB address lists several hosts, and an import from it would also connect to whichever members the server names; " +
			"only an admin may import from one. Use the address of a single member instead")
	}
	path, query, _ := strings.Cut(tail, "?")
	var keep []string
	for _, kv := range strings.Split(query, "&") {
		if kv == "" {
			continue
		}
		k, _, _ := strings.Cut(kv, "=")
		if uk, err := url.QueryUnescape(k); err == nil {
			k = uk
		}
		if mongoDiscoveryOptions[strings.ToLower(strings.TrimSpace(k))] {
			continue
		}
		keep = append(keep, kv)
	}
	keep = append(keep, "directConnection=true")
	if path == "" {
		path = "/"
	}
	return scheme + "://" + userinfo + hosts + path + "?" + strings.Join(keep, "&"), nil
}

// splitURI cuts scheme://userinfo@hosts/path?query into its parts. userinfo
// keeps its "@", and tail is everything from the first / or ?.
func splitURI(src string) (scheme, userinfo, hosts, tail string) {
	scheme, rest, _ := strings.Cut(src, "://")
	hosts = rest
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		hosts, tail = rest[:i], rest[i:]
	}
	if i := strings.LastIndexByte(hosts, '@'); i >= 0 {
		userinfo, hosts = hosts[:i+1], hosts[i+1:]
	}
	return scheme, userinfo, hosts, tail
}

// withHostaddr adds libpq's hostaddr to a postgres:// address: for each host it
// will try, the address that host was checked at.
func withHostaddr(src string, found map[string]string) (string, error) {
	_, _, authority, tail := splitURI(src)
	query := ""
	if _, q, ok := strings.Cut(tail, "?"); ok {
		query = q
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return "", fmt.Errorf("cannot read the options in this connection string: %v", err)
	}
	if len(q["hostaddr"]) > 0 {
		return src, nil // addresses already, checked as such; libpq looks nothing up
	}
	list := authority
	if hs := q["host"]; len(hs) > 0 {
		list = strings.Join(hs, ",") // libpq takes the host from the query when it is there
	}
	var addrs []string
	for _, hp := range strings.Split(list, ",") {
		h := hostOnly(hp)
		if ip := net.ParseIP(h); ip != nil {
			addrs = append(addrs, ip.String())
			continue
		}
		ip, ok := found[h]
		if !ok {
			return "", fmt.Errorf("cannot hold %s to the address it was checked at", h)
		}
		addrs = append(addrs, ip)
	}
	sep := "?"
	if strings.Contains(tail, "?") {
		sep = "&"
	}
	return src + sep + "hostaddr=" + url.QueryEscape(strings.Join(addrs, ",")), nil
}
