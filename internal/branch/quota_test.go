// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"testing"
	"time"
)

// withQuota stands in for the store's owner count and the rate's clock.
func withQuota(t *testing.T, owned map[int64]int) func(time.Duration) {
	t.Helper()
	oldOwned, oldNow := ownedBranches, createRate.now
	now := time.Unix(2_000_000, 0)
	ownedBranches = func(id int64) (int, error) { return owned[id], nil }
	createRate.mu.Lock()
	createRate.now = func() time.Time { return now }
	createRate.seen = map[int64][]time.Time{}
	createRate.mu.Unlock()
	t.Cleanup(func() {
		createRate.mu.Lock()
		ownedBranches, createRate.now = oldOwned, oldNow
		createRate.seen = map[int64][]time.Time{}
		createRate.mu.Unlock()
	})
	return func(d time.Duration) { now = now.Add(d) }
}

func TestBranchLimitPerAccount(t *testing.T) {
	withQuota(t, map[int64]int{7: 20, 8: 19})
	if err := AllowBranchCreate(7, false); !errors.Is(err, ErrBranchQuota) {
		t.Errorf("at the limit: %v, want ErrBranchQuota", err)
	}
	if err := AllowBranchCreate(8, false); err != nil {
		t.Errorf("one under the limit: %v", err)
	}
	// Admins, and the command line (no account), are not limited.
	if err := AllowBranchCreate(7, true); err != nil {
		t.Errorf("admin at the limit: %v", err)
	}
	if err := AllowBranchCreate(0, false); err != nil {
		t.Errorf("the command line: %v", err)
	}
	t.Setenv("FOX_MAX_BRANCHES_PER_ACCOUNT", "0")
	if err := AllowBranchCreate(7, false); err != nil {
		t.Errorf("limit off: %v", err)
	}
	t.Setenv("FOX_MAX_BRANCHES_PER_ACCOUNT", "25")
	if err := AllowBranchCreate(7, false); err != nil {
		t.Errorf("limit raised: %v", err)
	}
}

func TestCreateRatePerAccount(t *testing.T) {
	advance := withQuota(t, map[int64]int{})
	for i := range 10 {
		if err := AllowBranchCreate(3, false); err != nil {
			t.Fatalf("create %d of 10: %v", i+1, err)
		}
	}
	if err := AllowBranchCreate(3, false); !errors.Is(err, ErrCreateRate) {
		t.Fatalf("the 11th in a minute: %v, want ErrCreateRate", err)
	}
	// Another account has its own allowance, and an admin has none to use up.
	if err := AllowBranchCreate(4, false); err != nil {
		t.Errorf("another account: %v", err)
	}
	if err := AllowBranchCreate(3, true); err != nil {
		t.Errorf("admin: %v", err)
	}
	advance(61 * time.Second)
	if err := AllowBranchCreate(3, false); err != nil {
		t.Errorf("a minute later: %v", err)
	}
	t.Setenv("FOX_BRANCH_CREATES_PER_MINUTE", "0")
	for range 20 {
		if err := AllowBranchCreate(3, false); err != nil {
			t.Fatalf("rate off: %v", err)
		}
	}
}
