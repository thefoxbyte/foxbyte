// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempMaskFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldM, oldU, oldE := maskedPath, unmaskPath, maskExempt
	t.Cleanup(func() {
		maskedPath, unmaskPath, maskExempt = oldM, oldU, oldE
		masked.byKey, unmasks.byKey = nil, nil
	})
	maskedPath = func() string { return filepath.Join(dir, "masked-accounts.json") }
	unmaskPath = func() string { return filepath.Join(dir, "unmask-grants.json") }
	maskExempt = func(string, string) bool { return false }
}

// Unmask on a branch: real values there, masks elsewhere, its reads audited
// there only; a branch's grants go with it.
func TestUnmaskOnABranch(t *testing.T) {
	tempMaskFiles(t)
	if err := SaveMaskedAccounts([]MaskedAccount{{Email: "m@x.io"}}); err != nil {
		t.Fatal(err)
	}
	if !accountMasked("dev", "m@x.io") || readsAudited("dev", "m@x.io") {
		t.Fatal("masked, with no unmask")
	}
	if err := changeUnmasks(func(UnmaskGrant) bool { return true }, &UnmaskGrant{Email: "m@x.io", Branch: "dev", By: "cli:a"}); err != nil {
		t.Fatal(err)
	}
	if accountMasked("dev", "M@X.IO") || !readsAudited("dev", "m@x.io") {
		t.Error("unmask on dev: real values there, reads audited")
	}
	if !accountMasked("main", "m@x.io") || readsAudited("main", "m@x.io") {
		t.Error("unmask on dev reaches main")
	}
	if got := strings.Join(UnmaskGrantsOf("m@x.io"), " "); got != "dev" {
		t.Errorf("the grants: %q", got)
	}
	if st, err := os.Stat(unmaskPath()); err != nil || os.PathSeparator == '/' && st.Mode().Perm() != 0o600 {
		t.Errorf("the file: %v %v", st, err)
	}
	forgetBranchUnmasks("dev")
	if b, _ := os.ReadFile(unmaskPath()); strings.TrimSpace(string(b)) != "[]" {
		t.Errorf("no grants left is [], not %q", b)
	}
	if hasUnmask("dev", "m@x.io") || !accountMasked("dev", "m@x.io") {
		t.Error("a deleted branch's grant stays, and would reach a branch made later with its name")
	}
	// An account no longer masked is not audited as an unmask holder.
	_ = changeUnmasks(func(UnmaskGrant) bool { return true }, &UnmaskGrant{Email: "m@x.io", Branch: "dev"})
	_ = SaveMaskedAccounts(nil)
	if readsAudited("dev", "m@x.io") || accountMasked("dev", "m@x.io") {
		t.Error("an unmasked account")
	}
}

// The audit role is set by a superuser's ALTER ROLE, so the account cannot
// undo it, and taken off with RESET; a role not there yet is left alone.
func TestAuditedReadsSQL(t *testing.T) {
	on, off := auditedReadsSQL("o'k@x.io", true), auditedReadsSQL("o'k@x.io", false)
	if !strings.Contains(on, "SET pgaudit.role = bb_audit_read") || !strings.Contains(off, "RESET pgaudit.role") {
		t.Errorf("on:\n%s\noff:\n%s", on, off)
	}
	for _, s := range []string{on, off} {
		if !strings.Contains(s, "'o''k@x.io'") || !strings.Contains(s, "pg_roles WHERE rolname = r") {
			t.Errorf("the role, quoted and looked up by name:\n%s", s)
		}
	}
}

// Without Enterprise, unmask is refused and nothing is written.
func TestUnmaskNotLicensed(t *testing.T) {
	tempMaskFiles(t)
	old := masker
	t.Cleanup(func() { masker = old })
	masker = nil
	if err := Unmask("m@x.io", "dev", "cli:a", false); !errors.Is(err, ErrNotLicensed) {
		t.Fatalf("unmask: %v", err)
	}
	if _, err := os.Stat(unmaskPath()); err == nil {
		t.Error("a grant was written without the licence")
	}
}
