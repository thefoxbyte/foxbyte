// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

// fakeDNS answers lookups from a table, so these tests need no network.
func fakeDNS(t *testing.T, a map[string][]string) {
	t.Helper()
	oldIP := lookupIP
	t.Cleanup(func() { lookupIP = oldIP })
	lookupIP = func(h string) ([]net.IP, error) {
		var out []net.IP
		for _, s := range a[h] {
			out = append(out, net.ParseIP(s))
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no such host %s", h)
		}
		return out, nil
	}
}

// An admin's source is used as given: the guard passes or fails it, nothing more.
func TestAnAdminsSourceIsUsedAsGiven(t *testing.T) {
	fakeDNS(t, map[string][]string{"db.example.com": {"203.0.113.7"}, "mg.example.com": {"203.0.113.9"}, "m2.example.com": {"203.0.113.10"}})
	for _, src := range []string{
		"postgres://u:p@db.example.com:5432/app",
		// An admin's MongoDB replica set is still discovered as before.
		"mongodb://mg.example.com:27017,m2.example.com:27017/app?replicaSet=rs0",
	} {
		got, pins, err := pinImportSource(src, true)
		if err != nil || got != src || pins != nil {
			t.Fatalf("%s: got %q %v %v", src, got, pins, err)
		}
	}
}

func TestAPostgresSourceIsHeldToTheCheckedAddress(t *testing.T) {
	fakeDNS(t, map[string][]string{
		"db.example.com": {"2001:db8::1", "203.0.113.7"},
		"b.example.com":  {"198.51.100.2"},
	})
	for _, c := range []struct{ in, want string }{
		{"postgres://u:p@db.example.com:5432/app", "postgres://u:p@db.example.com:5432/app?hostaddr=203.0.113.7"},
		{"postgresql://db.example.com/app?sslmode=verify-full", "postgresql://db.example.com/app?sslmode=verify-full&hostaddr=203.0.113.7"},
		// Several hosts: one address each, in order; an address stays itself.
		{"postgres://db.example.com:5432,198.51.100.9:5433/app", "postgres://db.example.com:5432,198.51.100.9:5433/app?hostaddr=203.0.113.7%2C198.51.100.9"},
		// libpq takes the host from the query when it is there.
		{"postgres://db.example.com/app?host=b.example.com", "postgres://db.example.com/app?host=b.example.com&hostaddr=198.51.100.2"},
		// Already addresses: nothing is looked up, nothing to add.
		{"postgres://db.example.com/app?hostaddr=203.0.113.9", "postgres://db.example.com/app?hostaddr=203.0.113.9"},
	} {
		got, _, err := pinImportSource(c.in, false)
		if err != nil || got != c.want {
			t.Errorf("%s:\n got %q (%v)\nwant %q", c.in, got, err, c.want)
		}
	}
}

func TestOtherSourcesArePinnedForTheirContainers(t *testing.T) {
	fakeDNS(t, map[string][]string{"my.example.com": {"203.0.113.8"}, "mg.example.com": {"203.0.113.9"}})
	for _, c := range []struct {
		in, want string
		pins     []string
	}{
		{"mysql://u:p@my.example.com:3306/app", "mysql://u:p@my.example.com:3306/app", []string{"my.example.com:203.0.113.8"}},
		{"mongodb://mg.example.com:27017/app", "mongodb://mg.example.com:27017/app?directConnection=true", []string{"mg.example.com:203.0.113.9"}},
	} {
		got, pins, err := pinImportSource(c.in, false)
		if err != nil || got != c.want || !reflect.DeepEqual(pins, c.pins) {
			t.Errorf("%s: got %q %v %v, want %q %v", c.in, got, pins, err, c.want, c.pins)
		}
	}
}

// An ordinary account's MongoDB import connects to the one host it named and
// no other: discovery options are dropped, whatever their case, and a direct
// connection is asked for. Everything else in the address is kept as written.
func TestAMongoSourceIsHeldToOneDirectHost(t *testing.T) {
	fakeDNS(t, map[string][]string{"mg.example.com": {"203.0.113.9"}})
	for _, c := range []struct{ in, want string }{
		{"mongodb://u:p%40x@mg.example.com/app?replicaSet=rs0&authSource=admin",
			"mongodb://u:p%40x@mg.example.com/app?authSource=admin&directConnection=true"},
		{"mongodb://mg.example.com:27017/?REPLICASET=rs0&directConnection=false&tls=true",
			"mongodb://mg.example.com:27017/?tls=true&directConnection=true"},
		{"mongodb://mg.example.com?loadBalanced=true", "mongodb://mg.example.com/?directConnection=true"},
		{"mongodb://mg.example.com/app?replica%53et=rs0", "mongodb://mg.example.com/app?directConnection=true"},
	} {
		got, _, err := pinImportSource(c.in, false)
		if err != nil || got != c.want {
			t.Errorf("%s:\n got %q (%v)\nwant %q", c.in, got, err, c.want)
		}
	}
}

// A seed list, or an SRV record, names hosts the guard would hold the import
// to only in part; for an ordinary account both are refused, saying why.
func TestAMongoSeedListOrSRVIsRefused(t *testing.T) {
	fakeDNS(t, map[string][]string{"mg.example.com": {"203.0.113.9"}, "m2.example.com": {"203.0.113.10"}})
	for src, want := range map[string]string{
		"mongodb://mg.example.com:27017,m2.example.com:27017/app": "several hosts",
		"mongodb+srv://cl.example.com/app":                        "mongodb+srv",
	} {
		if _, _, err := pinImportSource(src, false); err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "admin") {
			t.Errorf("%s: %v, want a refusal mentioning %q", src, err, want)
		}
	}
}

// The guard still decides: pinning never lets through what it refused.
func TestPinningStillRefusesPrivateAddresses(t *testing.T) {
	fakeDNS(t, map[string][]string{"in.example.com": {"10.0.0.5"}})
	for _, src := range []string{"postgres://in.example.com/app", "mongodb://in.example.com/app"} {
		if _, _, err := pinImportSource(src, false); err == nil || !strings.Contains(err.Error(), "only an admin") {
			t.Fatalf("%s: a private address passed: %v", src, err)
		}
	}
}
