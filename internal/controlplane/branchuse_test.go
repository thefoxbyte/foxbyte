// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"path/filepath"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// A branch's use is written down, and not once a query: at most every
// touchEvery per branch.
func TestThrottledTouch(t *testing.T) {
	s, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	touch := throttledTouch(s)
	touch("dev")
	first, ok := s.BranchUsedAt("dev")
	if !ok {
		t.Fatal("not recorded")
	}
	touch("dev")
	if again, _ := s.BranchUsedAt("dev"); !again.Equal(first) {
		t.Fatal("written twice within the window")
	}
	touch("qa")
	if _, ok := s.BranchUsedAt("qa"); !ok {
		t.Fatal("another branch waited on the first one's window")
	}
}
