// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// Pseudonymising a deleted account rewrites events that are already anchored,
// and `fox audit verify` still passes: their row hashes, which the anchors
// signed, do not change, and their seals vouch for what they now say.
func TestPseudonymisedLogStillVerifiesAgainstAnchors(t *testing.T) {
	s, _ := logWith(t, 0)
	s.Audit(auth.EvLoginOK, "alice@x.com", "alice@x.com", "10.0.0.1", "")
	addEvents(s, 3)
	s.Audit(auth.EvAccountDeleted, "admin@x.com", "alice@x.com", "10.9.9.9", "")
	if a, err := CheckpointSecurityLog(s); err != nil || a == nil || a.ToID != 5 {
		t.Fatalf("anchor: %+v, %v", a, err)
	}
	if _, err := s.PseudonymiseSecurityLog("alice@x.com", "admin@x.com"); err != nil {
		t.Fatal(err)
	}
	if rep := fullVerify(t, s); !rep.Intact {
		t.Fatalf("after pseudonymising: %+v", rep)
	}
	// The checkpoint after it anchors the pseudonymisation event, starting
	// from an anchored event that was itself rewritten.
	if a, err := CheckpointSecurityLog(s); err != nil || a == nil || a.ToID != 6 {
		t.Fatalf("the next anchor: %+v, %v", a, err)
	}
	rep := fullVerify(t, s)
	if !rep.Intact || rep.UnanchoredRows != 0 {
		t.Fatalf("after anchoring it: %+v", rep)
	}
	evs, _ := s.SecurityEvents(0, 0)
	for _, e := range evs {
		if strings.Contains(e.Actor+e.Subject+e.Detail, "alice@x.com") || e.IP == "10.0.0.1" {
			t.Errorf("event %d still holds her data: %+v", e.ID, e)
		}
	}
}

// A prune removes only anchored events, anchors the record of it, and leaves
// a log that verifies against every anchor, including those over removed
// events.
func TestPrunedLogVerifies(t *testing.T) {
	s, _ := anchoredLog(t, 4) // anchor 1–4
	addEvents(s, 3)           // 5–7
	if a, err := CheckpointSecurityLog(s); err != nil || a == nil || a.ToID != 7 {
		t.Fatalf("second anchor: %+v, %v", a, err)
	}
	addEvents(s, 2) // 8–9, not anchored

	// Up to the last anchor (7), never past it, even though 8 and 9 are old
	// enough too.
	res, err := s.PruneSecurityEvents(time.Now().Add(time.Second), 7, "engine")
	if err != nil || res.UpTo != 7 {
		t.Fatalf("prune: %+v, %v", res, err)
	}
	// Not anchored yet: a removal nothing outside the store vouches for.
	if rep := fullVerify(t, s); rep.Intact {
		t.Fatalf("a prune of anchored events verified before it was anchored: %+v", rep)
	}
	if a, err := CheckpointSecurityLog(s); err != nil || a == nil || a.ToID != res.EventID {
		t.Fatalf("anchoring the prune: %+v, %v", a, err)
	}
	rep := fullVerify(t, s)
	if !rep.Intact || rep.Rows != 3 {
		t.Fatalf("after the prune was anchored: %+v", rep)
	}

	// A second prune, part-way through an anchor's range.
	addEvents(s, 1)
	if _, err := CheckpointSecurityLog(s); err != nil {
		t.Fatal(err)
	}
	if res, err = s.PruneSecurityEvents(time.Now().Add(time.Second), 8, "engine"); err != nil || res.UpTo != 8 {
		t.Fatalf("second prune: %+v, %v", res, err)
	}
	if _, err := CheckpointSecurityLog(s); err != nil {
		t.Fatal(err)
	}
	if rep := fullVerify(t, s); !rep.Intact {
		t.Fatalf("after a prune inside an anchor's range: %+v", rep)
	}
}

// PruneSecurityLog does nothing until the operator sets a retention.
func TestPruneSecurityLogNeedsARetention(t *testing.T) {
	s, _ := anchoredLog(t, 3)
	t.Setenv(auth.SecurityLogRetentionEnv, "")
	if res, err := PruneSecurityLog(s, "engine"); err != nil || res.Removed != 0 {
		t.Fatalf("with no retention: %+v, %v", res, err)
	}
	t.Setenv(auth.SecurityLogRetentionEnv, "400d")
	if res, err := PruneSecurityLog(s, "engine"); err != nil || res.Removed != 0 {
		t.Fatalf("with nothing that old: %+v, %v", res, err)
	}
	t.Setenv(auth.SecurityLogRetentionEnv, "400")
	if _, err := PruneSecurityLog(s, "engine"); err == nil {
		t.Fatal("a retention with no unit was accepted")
	}
}
