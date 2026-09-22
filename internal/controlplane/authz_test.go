// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/access"
	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// withACL gives the package an access rule over a temp store: admin@x.com is
// the admin, alice owns alice-dev.
func withACL(t *testing.T) (*auth.Store, auth.User, auth.User, auth.User) {
	t.Helper()
	s, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	admin, _ := s.CreateUser("admin@x.com", "password1")
	alice, _ := s.CreateUser("alice@x.com", "password1")
	bob, _ := s.CreateUser("bob@x.com", "password1")
	old := acl
	acl = access.NewWith(s, func(e string) bool { return e == "admin@x.com" })
	t.Cleanup(func() { acl = old })
	_ = acl.Own(alice, "alice-dev")
	return s, admin, alice, bob
}

func TestAuthorizeBranchRoutes(t *testing.T) {
	s, admin, alice, bob := withACL(t)
	h := s.Authn(authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) })))
	keyOf := func(u auth.User) string { k, _, _ := s.CreateAPIKey(u.ID, "t"); return k }
	ka, kb, kadm := keyOf(alice), keyOf(bob), keyOf(admin)
	for _, tc := range []struct {
		key, method, path string
		want              int
	}{
		{kb, "GET", "/api/branches/alice-dev/ledger", 404},   // not bob's: not there
		{kb, "POST", "/api/branches/alice-dev/query", 404},   //
		{kb, "DELETE", "/api/branches/alice-dev", 404},       //
		{kb, "POST", "/api/branches/alice-dev/suspend", 404}, //
		{kb, "GET", "/api/ledger/diff?a=main&b=alice-dev", 404},
		{ka, "GET", "/api/branches/alice-dev/ledger", 299}, // the owner
		{ka, "DELETE", "/api/branches/alice-dev", 299},     //
		{kb, "POST", "/api/branches/main/query", 299},      // main is shared
		{kb, "DELETE", "/api/branches/main", 403},          // but not bob's to manage
		{kb, "POST", "/api/branches/main/ledger/checkpoint", 403},
		{kadm, "DELETE", "/api/branches/alice-dev", 299},   // an admin
		{kadm, "GET", "/api/branches/unowned/ledger", 299}, //
		{ka, "GET", "/api/branches/unowned/ledger", 404},   // no owner: an admin's
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Header.Set("Authorization", "Bearer "+tc.key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
}

func TestImportHosts(t *testing.T) {
	for src, want := range map[string][]string{
		"postgres://u:p@db.example.com:5432/app":            {"db.example.com"},
		"postgresql://u@[::1]:5432/app":                     {"::1"},
		"mongodb://u:p@h1:27017,h2:27017/app?replicaSet=r":  {"h1", "h2"},
		"postgres://u@public.example.com/app?host=10.0.0.5": {"public.example.com", "10.0.0.5"},
		"postgres:///app":                                   {"localhost"},
		"mysql://u:p%40x@my.example.com/app":                {"my.example.com"},
	} {
		got, err := importHosts(src)
		sort.Strings(got)
		sort.Strings(want)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("importHosts(%q) = %v, %v; want %v", src, got, err, want)
		}
	}
}

func TestImportSourceRule(t *testing.T) {
	old := lookupIP
	t.Cleanup(func() { lookupIP = old })
	lookupIP = func(h string) ([]net.IP, error) {
		switch h {
		case "db.example.com":
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		case "internal.corp":
			return []net.IP{net.ParseIP("10.1.2.3")}, nil
		case "localhost":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return nil, errors.New("no such host")
	}
	for _, tc := range []struct {
		src         string
		user, admin bool // allowed for an ordinary account, for an admin
	}{
		{"postgres://u@db.example.com/app", true, true},
		{"postgres://u@internal.corp/app", false, true},
		{"postgres://u@10.0.0.5/app", false, true},
		{"postgres://u@localhost/app", false, true},
		{"postgres:///app", false, true},
		{"postgres://u@objstore:9000/app", false, true}, // a container name
		{"postgres://u@db.example.com/app?host=127.0.0.1", false, true},
		{"postgres://u@169.254.169.254/app", false, false}, // metadata, for nobody
		{"postgres://u@metadata.google.internal/app", false, false},
		{"postgres://u@[fe80::1]/app", false, false},
		{"postgres://u@0.0.0.0/app", false, false},
	} {
		if got := checkImportSource(tc.src, false) == nil; got != tc.user {
			t.Errorf("%s as an account: allowed=%v, want %v", tc.src, got, tc.user)
		}
		if got := checkImportSource(tc.src, true) == nil; got != tc.admin {
			t.Errorf("%s as an admin: allowed=%v, want %v", tc.src, got, tc.admin)
		}
	}
}
