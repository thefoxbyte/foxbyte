// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// An agent may propose a change to main and must not be able to approve its own:
// the review step is the whole point of promotion. No tool decides a request, so
// there is nothing for a key to reach — this keeps that true.
func TestNoToolDecidesAChangeRequest(t *testing.T) {
	for _, name := range toolNames(t) {
		switch name {
		case "approve_change_request", "reject_change_request", "decide_change_request", "merge_branch":
			t.Errorf("%q decides a change request; deciding belongs to someone who can manage the target", name)
		}
	}
}

// The tools an agent needs to take part: propose, and see what happened.
//
// Proposing is gated, so this needs the entitlement; seeing what happened is
// not, and is asserted unlicensed below.
func TestPromotionToolsArePresent(t *testing.T) {
	if !edition.Enterprise {
		t.Skip("promotion cannot be entitled in a Standard build")
	}
	entitleTools(t, edition.Promotion)
	have := map[string]bool{}
	for _, n := range toolNames(t) {
		have[n] = true
	}
	for _, want := range []string{"request_changes", "list_change_requests"} {
		if !have[want] {
			t.Errorf("%q is not advertised", want)
		}
	}
}

// A tool this install cannot serve is left out of the list, and refused by name
// if a client asks anyway from a list it cached earlier.
//
// Hiding beats showing locked here, and only here: this list is read by a
// model, which would otherwise plan around a tool, call it, and have to recover
// from a refusal. A console is read by a person who can act on an upsell.
func TestGatedToolsAreNotAdvertisedWithoutALicence(t *testing.T) {
	edition.SetEntitlement(nil)
	t.Cleanup(func() { edition.SetEntitlement(nil) })
	for _, n := range toolNames(t) {
		if _, gated := gatedTools[n]; gated {
			t.Errorf("%q is advertised with no licence for it", n)
		}
	}
	// What reads, stays.
	have := map[string]bool{}
	for _, n := range toolNames(t) {
		have[n] = true
	}
	for _, want := range []string{"list_change_requests", "policy_check", "blackbox_entries"} {
		if !have[want] {
			t.Errorf("%q reads and must not be gated, but is not advertised", want)
		}
	}
}

func TestGatedToolsAreRefusedByName(t *testing.T) {
	edition.SetEntitlement(nil)
	t.Cleanup(func() { edition.SetEntitlement(nil) })
	for name := range gatedTools {
		res := callTool([]byte(`{"name":"` + name + `","arguments":{}}`))
		if res["isError"] != true {
			t.Errorf("%q was not refused without a licence: %v", name, res)
		}
	}
}

// entitleTools gives this process the named features for one test.
func entitleTools(t *testing.T, features ...edition.Feature) {
	t.Helper()
	has := map[edition.Feature]bool{}
	for _, f := range features {
		has[f] = true
	}
	edition.SetEntitlement(func(f edition.Feature) bool { return has[f] })
	t.Cleanup(func() { edition.SetEntitlement(nil) })
}

// A branch-scoped key can only ever propose its own branch's changes: naming
// another branch is refused outright, and leaving it out means its own.
func TestRequestChangesIsScoped(t *testing.T) {
	me = identity{Actor: "agent@example.com", Scope: "agent-alice"}
	t.Cleanup(func() { me = identity{} })

	if _, err := applyScope("request_changes", []byte(`{"branch":"someone-else","target":"main"}`)); err == nil {
		t.Error("a scoped key was allowed to propose another branch's changes")
	}
	out, err := applyScope("request_changes", []byte(`{"target":"main"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); !contains(got, `"branch":"agent-alice"`) {
		t.Errorf("an absent branch should become the key's own: %s", got)
	}
	// The target is left as asked: reaching it is checked against the account's
	// access, not pinned, because proposing into main is the normal case.
	if got := string(out); !contains(got, `"target":"main"`) {
		t.Errorf("the target was rewritten: %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// toolNames lists what the server advertises.
func toolNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, tl := range toolList() {
		n, _ := tl["name"].(string)
		names = append(names, n)
	}
	if len(names) == 0 {
		t.Fatal("the server advertises no tools")
	}
	return names
}
