// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// entitle gives this process the named features for one test.
func entitle(t *testing.T, features ...edition.Feature) {
	t.Helper()
	has := map[edition.Feature]bool{}
	for _, f := range features {
		has[f] = true
	}
	edition.SetEntitlement(func(f edition.Feature) bool { return has[f] })
	t.Cleanup(func() { edition.SetEntitlement(nil) })
}

// And the other half of the same rule: with the feature, it gets past the gate
// and fails for an ordinary reason instead (there is no database in a unit
// test). What is asserted is that the refusal is no longer the licence.
//
// Enterprise only, and not because the test is awkward in Standard: in a
// Standard build edition.Has is false whatever an entitlement says, because the
// code the feature unlocks is not in the binary. That is asserted on its own
// below.
func TestCheckpointGetsPastTheGateWithTheFeature(t *testing.T) {
	if !edition.Enterprise {
		t.Skip("a Standard build cannot entitle a paid feature at all")
	}
	entitle(t, edition.Anchors)
	_, _, err := Checkpoint("main")
	if errors.Is(err, ErrAnchorsNotLicensed) {
		t.Error("Checkpoint() still refused on the licence with the feature entitled")
	}
}

// The free side of the line, asserted so it cannot drift.
//
// The security log's own anchors are not gated. That is the accountability
// trail — who signed in, what was refused, and now the licence itself — and the
// rule the editions follow is that safety stays free. It would also be a poor
// look for the record of licensing to be the thing a licence switches off.
func TestTheSecurityLogIsStillAnchoredWithoutTheFeature(t *testing.T) {
	edition.SetEntitlement(nil)
	store, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for i := 0; i < 3; i++ {
		store.Audit(auth.EvLoginOK, "a@x.com", "", "127.0.0.1", "")
	}
	t.Setenv(brand.EnvName("ANCHOR_DIR"), t.TempDir())

	a, err := CheckpointSecurityLog(store)
	if errors.Is(err, ErrAnchorsNotLicensed) {
		t.Fatal("the security log's anchors were refused as a paid feature")
	}
	if err != nil {
		t.Fatalf("CheckpointSecurityLog: %v", err)
	}
	if a == nil {
		t.Fatal("no anchor was written for a log with events in it")
	}
}
