// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// stubVault stands in for the vault: refs for the request's numbers, and
// what deleting them did.
func stubVault(t *testing.T, refs []string) *[]string {
	t.Helper()
	deleted := &[]string{}
	oldRefs, oldDel := erasureVaultRefs, erasureVaultDelete
	erasureVaultRefs = func(*auth.Store, *ErasureEngine, []ErasureValue, string) ([]string, string) { return refs, "" }
	erasureVaultDelete = func(_ *auth.Store, _ string, rs []string, purpose string) (int, error) {
		if !strings.HasPrefix(purpose, "erasure request #") {
			t.Errorf("the vault was asked to delete for %q", purpose)
		}
		*deleted = append(*deleted, rs...)
		return len(rs), nil
	}
	oldPh := placeholdersOn
	placeholdersOn = func(stmt string, forms []string) string { return erase(stmt, forms) + " /*placeholders*/" }
	t.Cleanup(func() { erasureVaultRefs, erasureVaultDelete, placeholdersOn = oldRefs, oldDel, oldPh })
	return deleted
}

// What the install keeps of the person beside the branches: history entries
// holding a value go, every actor's; saved queries holding one are listed for
// their owners and kept; a decided change request is rewritten, an open one
// listed and left; the vault's record is deleted.
func TestErasureRemovesTheCopiesBesideTheBranches(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main", Rows: 1}, fp: "fp"}
	f.install(t)
	deleted := stubVault(t, []string{"ARTESTREF0000000000000000000"})
	s := erasureStore(t)
	for _, e := range []auth.HistoryEntry{
		{Actor: "dev@x", Branch: "main", Source: "console", SQL: "SELECT * FROM people WHERE email = 'ASHA@example.com'", OK: true},
		{Actor: "ops@x", Branch: "dev", Source: "console", SQL: "UPDATE people SET n = 1 WHERE id = 3", Error: "duplicate key asha@example.com", OK: false},
		{Actor: "ops@x", Branch: "main", Source: "console", SQL: "SELECT 1", OK: true},
	} {
		if _, err := s.RecordQuery(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SaveQuery("dev@x", "find asha", "SELECT * FROM people WHERE email = 'asha@example.com'"); err != nil {
		t.Fatal(err)
	}
	entries := `[{"id":5,"command":"UPDATE","object":"public.people","sql":"UPDATE people SET email = 'asha@example.com' WHERE id = 1"}]`
	decided, _ := s.CreateChangeRequest(auth.CLIUser, "dev", "main", 0, entries)
	if _, err := s.ClaimChangeRequest(decided.ID, auth.CLIUser, auth.RequestRejected, "rejected: it sets asha@example.com"); err != nil {
		t.Fatal(err)
	}
	open, _ := s.CreateChangeRequest(auth.CLIUser, "qa", "main", 0, entries)

	v, err := NewErasure(s, "main", asha, nil, "", "dpo@x")
	if err != nil {
		t.Fatal(err)
	}
	c := v.Plan.Copies
	if c == nil || c.History != 2 || len(c.Saved) != 1 || c.Saved[0].Owner != "dev@x" || c.Requests != 1 ||
		len(c.OpenRequests) != 1 || c.OpenRequests[0] != open.ID || c.Vault != 1 {
		t.Fatalf("the plan's copies: %+v", c)
	}
	if strings.Join(f.vaultRefs, ",") != "ARTESTREF0000000000000000000" {
		t.Errorf("the branches were not planned with the vault's keys: %v", f.vaultRefs)
	}

	got, err := ApplyErasure(s, v.ID, asha, "dpo@x")
	if err != nil {
		t.Fatal(err)
	}
	d := got.Result.Copies
	if d == nil || d.History != 2 || d.Requests != 1 || d.Vault != 1 || len(*deleted) != 1 {
		t.Fatalf("done: %+v (vault deleted %v)", d, *deleted)
	}
	if n, _ := s.HistoryHolding([]string{"asha@example.com"}); n != 0 {
		t.Errorf("%d history entries still hold the value", n)
	}
	if saved, _ := s.SavedHolding([]string{"asha@example.com"}); len(saved) != 1 {
		t.Error("a saved query was deleted, not listed")
	}
	after, _ := s.ChangeRequest(decided.ID)
	if strings.Contains(strings.ToLower(after.Entries+after.Note), "asha@example.com") || !strings.Contains(after.Entries, "/*placeholders*/") {
		t.Errorf("the decided request still holds the value: %s | %s", after.Entries, after.Note)
	}
	if o, _ := s.ChangeRequest(open.ID); o.Entries != entries {
		t.Errorf("an open request was changed: %s", o.Entries)
	}
}

// A law that keeps the Aadhaar number keeps its vault record.
func TestErasureKeepsTheVaultRecordALawKeeps(t *testing.T) {
	f := &fakeErasure{plan: ErasurePlan{Branch: "main", Rows: 1, Tables: []ErasureTable{{Schema: "public", Table: "kyc",
		Action: ErasureActKeptLaw, Exceptions: []ErasureException{{Citation: "PML Rules, Rule 10", Categories: []string{"aadhaar"}}}}}}, fp: "fp"}
	f.install(t)
	deleted := stubVault(t, []string{"ARTESTREF0000000000000000000"})
	s := erasureStore(t)
	v, _ := NewErasure(s, "main", asha, nil, "", "dpo@x")
	got, err := ApplyErasure(s, v.ID, asha, "dpo@x")
	if err != nil {
		t.Fatal(err)
	}
	if d := got.Result.Copies; d.Vault != 0 || d.VaultKept != 1 || len(*deleted) != 0 || !strings.Contains(strings.Join(d.Notes, " "), "a law keeps the number") {
		t.Fatalf("%+v %v", d, *deleted)
	}
}

func TestErase(t *testing.T) {
	if got := erase("Duplicate key (email)=(Asha@Example.com)", []string{"asha@example.com", "abc"}); got != "Duplicate key (email)=([erased])" {
		t.Errorf("erase = %q", got)
	}
	if !holds("x ASHA@example.com y", []string{"asha@example.com"}) || holds("x", []string{"x"}) {
		t.Error("holds")
	}
}
