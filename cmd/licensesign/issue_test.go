// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// "all" has to mean every feature this build knows about, or an evaluation
// licence quietly stops covering whatever was added last. Keeping the list in
// step by hand is exactly the job this exists to remove.
func TestFeaturesAllIsEveryFeature(t *testing.T) {
	got, err := featureList("all")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(edition.Features()) {
		t.Fatalf("all gave %d features, this build has %d: %v", len(got), len(edition.Features()), got)
	}
	have := strings.Join(got, ",")
	for _, f := range edition.Features() {
		if !strings.Contains(have, string(f)) {
			t.Errorf("all does not include %q", f)
		}
	}
}

func TestFeaturesNamedExplicitly(t *testing.T) {
	got, err := featureList("anchors, policy ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "anchors" || got[1] != "policy" {
		t.Errorf("featureList = %v", got)
	}
	if _, err := featureList("  "); err == nil {
		t.Error("an empty feature list was accepted")
	}
}
