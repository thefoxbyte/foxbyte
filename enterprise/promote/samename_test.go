//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package promote

import (
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// A branch deleted and made again under the same name numbers its Blackbox
// entries from where its parent was, as the first one did. An earlier
// request's entry 140 is therefore not this branch's entry 140: it was
// recorded at another time, usually as another command.
func TestAnEntryIsCarriedOnlyIfItIsTheSameEntry(t *testing.T) {
	at := time.Date(2026, 11, 24, 13, 19, 7, 431_000_000, time.UTC)
	r := ledger.Row{ID: 140, At: at, CommandTag: "CREATE TABLE", Statement: "CREATE TABLE t (id int)"}
	snap := func(at, tag string) map[int64]branch.RequestEntry {
		return map[int64]branch.RequestEntry{140: {ID: 140, At: at, CommandTag: tag}}
	}
	for name, c := range map[string]struct {
		promoted map[int64]branch.RequestEntry
		want     bool
	}{
		"the same entry, as plan wrote it":    {snap("2026-11-24T13:19:07Z", "CREATE TABLE"), true},
		"another entry with its id":           {snap("2026-11-24T12:01:55Z", "CREATE TABLE"), false},
		"its id, its second, another command": {snap("2026-11-24T13:19:07Z", "GRANT"), false},
		"a snapshot with no time":             {snap("", "GRANT"), true}, // as before: by id
		"a time that does not parse":          {snap("yesterday", "GRANT"), true},
		"not carried at all":                  {map[int64]branch.RequestEntry{139: {ID: 139}}, false},
	} {
		if got := carried(r, c.promoted); got != c.want {
			t.Errorf("%s: carried = %v, want %v", name, got, c.want)
		}
		if replayable(r, c.promoted) == c.want {
			t.Errorf("%s: replayable disagrees with carried", name)
		}
	}
}

// A target deleted and made again under the same name inherits nothing from
// the old one but the requests the store keeps under its name; its own record
// (bb.applied_requests) says which of them it holds.
func TestOnlyTheRequestsTheTargetHoldsCount(t *testing.T) {
	snapshot, err := branch.MarshalEntries([]branch.RequestEntry{entry(11, "a", "human", "CREATE TABLE", "public.t", "CREATE TABLE t (id int)")})
	if err != nil {
		t.Fatal(err)
	}
	req := func(id int64, uid, status string, applied int) auth.ChangeRequest {
		return auth.ChangeRequest{ID: id, UID: uid, Source: "dev", Target: "main", Status: status, Applied: applied, Entries: snapshot}
	}
	held := req(3, "aa11", auth.RequestApproved, 1)
	gone := req(4, "bb22", auth.RequestApproved, 1) // applied to a branch that had this name before
	unnamed := req(5, "", auth.RequestApproved, 1)  // from before requests had names: no record to look for
	failed := req(6, "cc33", auth.RequestFailed, 0) // applied nothing anyway
	recorded := map[branch.AppliedKey]int{branch.AppliedKeyOf(held): 1, {ID: 4, UID: "another store's"}: 1}

	got := heldBy([]auth.ChangeRequest{held, gone, unnamed, failed}, recorded)
	ids := map[int64]bool{}
	for _, c := range got {
		ids[c.ID] = true
	}
	if !ids[3] || ids[4] || !ids[5] || !ids[6] || len(got) != 3 {
		t.Errorf("kept %v; want 3 (held), 5 (no name) and 6, not 4", ids)
	}
	_, sessions := alreadyPromoted("dev", "main", got)
	if sessions["request-4"] {
		t.Error("a request this target does not hold still counts as its own changes")
	}
	// A target with no record at all (one no named request was ever applied
	// to) holds none of the named ones.
	if got := heldBy([]auth.ChangeRequest{held, unnamed}, map[branch.AppliedKey]int{}); len(got) != 1 || got[0].ID != 5 {
		t.Errorf("with an empty record: %+v", got)
	}
}

// The case the console's change-request test met: both branches deleted and
// made again from the same parent, so the new source's entries have the ids an
// earlier request carried from the old one. The new CREATE TABLE is offered,
// and the function that needs it is not offered without it.
func TestABranchMadeAgainOffersItsOwnChanges(t *testing.T) {
	shared := rowsFrom(1, "", "public.a", "public.b")
	last := shared[len(shared)-1].RowHash
	old := rowsFrom(3, last, "public.old_t", "public.old_t_add(integer)")
	var earlier []branch.RequestEntry
	for _, r := range old {
		earlier = append(earlier, branch.RequestEntry{ID: r.ID, At: r.At.UTC().Format("2006-01-02T15:04:05Z"),
			CommandTag: r.CommandTag, Object: r.ObjectIdentity, Statement: r.Statement})
	}
	snapshot, err := branch.MarshalEntries(earlier)
	if err != nil {
		t.Fatal(err)
	}
	history := []auth.ChangeRequest{{ID: 6, UID: "aa11", Source: "e2eui", Target: "e2eui3",
		Status: auth.RequestApproved, Applied: len(earlier), Entries: snapshot}}

	// The new source: the same ids, recorded an hour later.
	src := append([]ledger.Row(nil), shared...)
	for _, r := range rowsFrom(3, last, "public.new_t", "public.new_t_add(integer)") {
		r.At = r.At.Add(time.Hour)
		r.RowHash = ledger.RowHash(r)
		src = append(src, r)
	}
	// The new target holds no request: it was made from the parent again.
	promoted, fromUs := alreadyPromoted("e2eui", "e2eui3", heldBy(history, map[branch.AppliedKey]int{}))
	p := newForkPlan(promoted, fromUs)
	branch.WalkRowsFork(src, shared, p.visitor())
	var objs []string
	for _, r := range p.candidates {
		objs = append(objs, r.ObjectIdentity)
	}
	if len(objs) != 2 || objs[0] != "public.new_t" || objs[1] != "public.new_t_add(integer)" {
		t.Errorf("offered %v; want the new table and its function", objs)
	}

	// Either half alone is enough: a target kept, its record holding the
	// request, still has none of the new source's entries.
	promoted, fromUs = alreadyPromoted("e2eui", "e2eui3", heldBy(history, map[branch.AppliedKey]int{{ID: 6, UID: "aa11"}: 2}))
	p = newForkPlan(promoted, fromUs)
	branch.WalkRowsFork(src, shared, p.visitor())
	if len(p.candidates) != 2 {
		t.Errorf("with the target holding the old request, %d offered; want 2", len(p.candidates))
	}
	// And the old source itself, its request held: nothing is offered again.
	oldSrc := append(append([]ledger.Row(nil), shared...), old...)
	p = newForkPlan(promoted, fromUs)
	branch.WalkRowsFork(oldSrc, shared, p.visitor())
	if len(p.candidates) != 0 {
		t.Errorf("the entries the target already holds were offered again: %d", len(p.candidates))
	}
}
