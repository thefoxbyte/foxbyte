// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"testing"
	"time"
)

func TestBranchUse(t *testing.T) {
	s := testStore(t)
	if _, ok := s.BranchUsedAt("dev"); ok {
		t.Fatal("a branch never used has a time")
	}
	before := time.Now().Add(-time.Second)
	if err := s.TouchBranch("dev"); err != nil {
		t.Fatal(err)
	}
	at, ok := s.BranchUsedAt("dev")
	if !ok || at.Before(before) {
		t.Fatalf("%v %v", at, ok)
	}
	if err := s.TouchBranch("dev"); err != nil {
		t.Fatal("a second touch", err)
	}
	if _, ok := s.BranchUsedAt("main"); ok {
		t.Fatal("one branch's use reached another")
	}
}
