//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package promote

import (
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func entry(id int64, actor, kind, tag, obj, sql string) branch.RequestEntry {
	return branch.RequestEntry{ID: id, At: "2026-09-28T10:00:00Z", Actor: actor, ActorKind: kind,
		CommandTag: tag, Object: obj, Statement: sql}
}

// What a branch has already had applied elsewhere must not be offered again, and
// must not make its next round look like a conflict.
func TestAlreadyPromoted(t *testing.T) {
	snapshot, err := branch.MarshalEntries([]branch.RequestEntry{entry(11, "a", "human", "CREATE TABLE", "public.t", "CREATE TABLE t (id int)")})
	if err != nil {
		t.Fatal(err)
	}
	history := []auth.ChangeRequest{
		{ID: 3, Source: "dev", Target: "main", Status: auth.RequestApproved, Applied: 1, Entries: snapshot},
		{ID: 4, Source: "dev", Target: "main", Status: auth.RequestRejected, Applied: 0, Entries: snapshot},
		{ID: 5, Source: "other", Target: "main", Status: auth.RequestApproved, Applied: 1, Entries: snapshot},
		{ID: 6, Source: "dev", Target: "staging", Status: auth.RequestApproved, Applied: 1, Entries: snapshot},
	}
	ids, sessions := alreadyPromoted("dev", "main", history)
	if !ids[11] {
		t.Error("an entry applied by an earlier request is not remembered")
	}
	if !sessions["request-3"] {
		t.Error("the session the statements were applied under is not remembered")
	}
	// A rejected request applied nothing; another source's and another target's
	// requests say nothing about this pair.
	for _, no := range []string{"request-4", "request-5", "request-6"} {
		if sessions[no] {
			t.Errorf("%s should not count for dev → main", no)
		}
	}
	if len(sessions) != 1 {
		t.Errorf("sessions = %v, want only request-3", sessions)
	}
}

// A request with no statements is refused rather than producing an empty
// transaction that reports success.
func TestApplyRequestRefusesNothing(t *testing.T) {
	if _, err := apply(1, "main", "someone@example.com", nil); err != branch.ErrNothingToPromote {
		t.Errorf("applying an empty request gave %v, want branch.ErrNothingToPromote", err)
	}
}

// Names are checked before anything reaches a container.
func TestBuildRequestChecksNames(t *testing.T) {
	if _, _, err := build("dev", "dev", nil); err == nil {
		t.Error("a branch was allowed to be its own source and target")
	}
	if _, _, err := build("../etc", "main", nil); err == nil {
		t.Error("a source that is not a branch name was accepted")
	}
	if _, _, err := build("dev", "../etc", nil); err == nil {
		t.Error("a target that is not a branch name was accepted")
	}
}
