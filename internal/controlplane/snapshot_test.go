// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Everybody reads one shared list and each still sees only their own part of
// it. This is the property a snapshot could quietly lose: the list is cached,
// and who may see what must never be.
func TestSharedBranchListIsFilteredPerCaller(t *testing.T) {
	s, admin, alice, bob := withACL(t)
	var reads atomic.Int64
	snap := branch.NewSnapshot(time.Hour, time.Second, func() ([]branch.BranchInfo, error) {
		reads.Add(1)
		return []branch.BranchInfo{{Name: "main", Primary: true}, {Name: "alice-dev"}, {Name: "bobs-secret"}}, nil
	})
	old := listBranches
	listBranches = snap.Get
	t.Cleanup(func() { listBranches = old })

	api := http.NewServeMux()
	registerAPI(api)
	h := s.Authn(api)

	get := func(u auth.User) []string {
		t.Helper()
		key, _, err := s.CreateAPIKey(u.ID, "t")
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/api/branches", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", u.Email, w.Code, w.Body)
		}
		var out []branch.BranchInfo
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		names := []string{}
		for _, b := range out {
			names = append(names, b.Name)
		}
		sort.Strings(names)
		return names
	}
	// Bob first, then the owner, then Bob again: an order that would show a
	// result kept per list rather than per caller.
	if got, want := get(bob), []string{"main"}; !reflect.DeepEqual(got, want) {
		t.Errorf("bob sees %v, want %v", got, want)
	}
	if got, want := get(alice), []string{"alice-dev", "main"}; !reflect.DeepEqual(got, want) {
		t.Errorf("alice sees %v, want %v", got, want)
	}
	if got, want := get(admin), []string{"alice-dev", "bobs-secret", "main"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the admin sees %v, want %v", got, want)
	}
	if got, want := get(bob), []string{"main"}; !reflect.DeepEqual(got, want) {
		t.Errorf("bob sees %v afterwards, want %v", got, want)
	}
	if n := reads.Load(); n != 1 {
		t.Errorf("%d reads of the branches for 4 requests, want 1", n)
	}
}

// And the same for what the import page polls.
func TestSharedReplicationListIsFilteredPerCaller(t *testing.T) {
	s, _, alice, bob := withACL(t)
	old := listReplicating
	listReplicating = func() ([]branch.Replication, error) {
		return []branch.Replication{{Branch: "alice-dev", Replicating: true}}, nil
	}
	t.Cleanup(func() { listReplicating = old })
	api := http.NewServeMux()
	registerAPI(api)
	h := s.Authn(api)
	seen := func(u auth.User) int {
		t.Helper()
		key, _, _ := s.CreateAPIKey(u.ID, "t")
		r := httptest.NewRequest("GET", "/api/replication", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", u.Email, w.Code, w.Body)
		}
		var out []branch.Replication
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return len(out)
	}
	if n := seen(bob); n != 0 {
		t.Errorf("bob sees %d replications on a branch that is not his", n)
	}
	if n := seen(alice); n != 1 {
		t.Errorf("alice sees %d, want 1", n)
	}
}
