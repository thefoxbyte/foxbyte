// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"strings"
	"testing"
)

// Declarations are kept, each with who and when; a new one replaces the old
// in what holds, and a withdrawal leaves the item open (13.4b).
func TestVaultDeclarations(t *testing.T) {
	s := testStore(t)
	if _, err := s.DeclareVault("aadhaar", "hosting", "on premises, Mumbai DC", "ops@x.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeclareVault("aadhaar", "hosting", "on premises, Pune DC", "admin@x.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeclareVault("aadhaar", "dr", "Chennai, keys in its own HSM", "admin@x.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeclareVault("text", "hosting", "elsewhere", "admin@x.com"); err != nil {
		t.Fatal(err)
	}
	cur, err := s.VaultDeclarations("aadhaar", false)
	if err != nil || len(cur) != 2 || cur[0].Item != "dr" || cur[1].Value != "on premises, Pune DC" || cur[1].DeclaredBy != "admin@x.com" {
		t.Fatalf("current: %+v %v", cur, err)
	}
	d, _ := s.VaultDeclarationOf("aadhaar", "hosting")
	if d == nil || d.Value != "on premises, Pune DC" || d.DeclaredAt.IsZero() {
		t.Fatalf("hosting: %+v", d)
	}
	// Withdrawn: open again, and the history keeps all three statements.
	if _, err := s.DeclareVault("aadhaar", "hosting", "  ", "admin@x.com"); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.VaultDeclarationOf("aadhaar", "hosting"); d != nil {
		t.Fatalf("withdrawn, still: %+v", d)
	}
	if cur, _ := s.VaultDeclarations("aadhaar", false); len(cur) != 1 || cur[0].Item != "dr" {
		t.Fatalf("after the withdrawal: %+v", cur)
	}
	if all, _ := s.VaultDeclarations("aadhaar", true); len(all) != 4 || all[0].Value != "" {
		t.Fatalf("history: %+v", all)
	}
	if all, _ := s.VaultDeclarations("", true); len(all) != 5 {
		t.Fatalf("every kind: %d", len(all))
	}
	if _, err := s.DeclareVault("aadhaar", "dr", strings.Repeat("x", MaxVaultDeclaration+1), "a@x.com"); !errors.Is(err, ErrVaultDeclaration) {
		t.Fatalf("too long: %v", err)
	}
	if _, err := s.DeclareVault("aadhaar", "", "x", "a@x.com"); !errors.Is(err, ErrVaultDeclaration) {
		t.Fatalf("no item: %v", err)
	}
}
