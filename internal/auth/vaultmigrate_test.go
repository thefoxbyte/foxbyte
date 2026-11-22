// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestVaultMigrationRunsAndTheirKeys(t *testing.T) {
	s := testStore(t)
	r, err := s.StartVaultMigration(VaultMigrationRun{Branch: "rehearse", BranchMade: 1700000000, Parent: "main", Kind: "aadhaar", Actor: "ops@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == 0 || r.State != "running" || !strings.Contains(r.VaultActor, "ops@example.com") || !strings.HasSuffix(r.VaultActor, "(vault migration "+strconv.FormatInt(r.ID, 10)+")") {
		t.Fatalf("a run starts running, with an actor of its own in the vault: %+v", r)
	}
	if err := s.AddVaultMigrationRefs(r.ID, []string{"AR1", "AR2", "AR3"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddVaultMigrationRefs(r.ID, []string{"AR3"}); err != nil {
		t.Fatal("a key kept twice is kept once, without an error:", err)
	}
	if err := s.FinishVaultMigration(r.ID, `{"distinct":3}`, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.VaultMigration(r.ID)
	if err != nil || got.State != "done" || got.Finished == nil || got.Report != `{"distinct":3}` || got.Parent != "main" || got.BranchMade != 1700000000 {
		t.Fatalf("the run reads back as finished: %+v %v", got, err)
	}
	c, err := s.VaultMigrationRefCounts(r.ID)
	if err != nil || c != (VaultMigrationRefCounts{Made: 3, Pending: 3}) {
		t.Fatalf("three keys made, none settled: %+v %v", c, err)
	}
	refs, _ := s.PendingVaultMigrationRefs(r.ID, 2)
	if len(refs) != 2 || refs[0] != "AR1" {
		t.Fatalf("the pending keys, at most the limit: %v", refs)
	}
	if err := s.SettleVaultMigrationRefs(r.ID, []string{"AR1"}, []string{"AR2"}); err != nil {
		t.Fatal(err)
	}
	c, _ = s.VaultMigrationRefCounts(r.ID)
	if c != (VaultMigrationRefCounts{Made: 3, Pending: 1, Deleted: 1, Kept: 1}) {
		t.Fatalf("one deleted, one kept, one to settle: %+v", c)
	}

	f, _ := s.StartVaultMigration(VaultMigrationRun{Branch: "main", Kind: "aadhaar", Actor: "ops@example.com"})
	if err := s.FinishVaultMigration(f.ID, "{}", errors.New("not rehearsed")); err != nil {
		t.Fatal(err)
	}
	all, _ := s.VaultMigrations("", 0)
	mine, _ := s.VaultMigrations("rehearse", 0)
	if len(all) != 2 || all[0].ID != f.ID || all[0].State != "failed" || all[0].Error != "not rehearsed" || len(mine) != 1 {
		t.Fatalf("newest first; a failed run keeps its error; by branch: %+v %+v", all, mine)
	}
	if _, err := s.VaultMigration(999); !errors.Is(err, ErrNoVaultMigration) {
		t.Fatal("a run that is not there:", err)
	}
}
