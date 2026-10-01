// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"strings"
	"testing"
)

// CONTRIBUTING.md promises contributors a CLA. For months it promised one that
// did not exist: the text said "we will provide the CLA link on your first pull
// request", there was no file and no link, and the first outside pull request
// arrived and was merged without one. A promise in a contributor guide is a
// commitment to a stranger, so it is held to the file actually being there.
func TestContributorGuidePromisesOnlyWhatExists(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return string(b)
	}

	guide := read("../../CONTRIBUTING.md")
	if !strings.Contains(guide, "CLA.md") {
		t.Error("CONTRIBUTING.md asks for a CLA but does not link CLA.md, so nobody can find it")
	}

	cla := read("../../CLA.md")
	// The parts a contributor is entitled to have spelled out before signing:
	// what they keep, what they grant, and that a paid edition is among the
	// places their work may end up. Open core without that last sentence is a
	// surprise, and a bad one.
	for what, want := range map[string]string{
		"that the contributor keeps their copyright": "keep",
		"the grant of a copyright licence":           "Grant of copyright licence",
		"the grant of a patent licence":              "Grant of patent licence",
		"that terms may be commercial":               "commercial",
		"the employer case":                          "employer",
		"how to sign it":                             "How to sign",
	} {
		if !strings.Contains(cla, want) {
			t.Errorf("CLA.md does not cover %s (looked for %q)", what, want)
		}
	}
}
