// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Aadhaar is masked by display only: a hash applications join on would be a
// reference key, which UIDAI forbids (design, section 7).
func TestCheckMaskRuleAadhaar(t *testing.T) {
	for _, r := range []string{MaskHash, MaskFake} {
		for _, c := range []string{"aadhaar", "Aadhaar"} {
			err := CheckMaskRule(r, c)
			if !errors.Is(err, ErrInvalidRequest) || !strings.Contains(err.Error(), "never hashed or faked") {
				t.Errorf("%s on %s: %v", r, c, err)
			}
		}
	}
	for _, r := range []string{MaskPartial, MaskEmpty} {
		if err := CheckMaskRule(r, "aadhaar"); err != nil {
			t.Errorf("%s on aadhaar: %v", r, err)
		}
	}
	if err := CheckMaskRule("redact", "email"); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("an unknown rule: %v", err)
	}
	if err := CheckMaskRule(MaskHash, "email"); err != nil {
		t.Errorf("hash on email: %v", err)
	}
}

func TestDefaultMaskRule(t *testing.T) {
	for c, want := range map[string]string{
		"aadhaar": MaskPartial, "pan": MaskPartial, "card": MaskPartial, "mobile": MaskPartial, "gstin": MaskPartial,
		"ifsc": MaskPartial, "email": MaskHash, "name": MaskFake, "address": MaskEmpty, "": MaskEmpty, "EMAIL": MaskHash,
	} {
		if got := DefaultMaskRule(c); got != want {
			t.Errorf("%q: %s, want %s", c, got, want)
		}
		if err := CheckMaskRule(DefaultMaskRule(c), c); err != nil {
			t.Errorf("the default for %q is refused: %v", c, err)
		}
	}
}

// A masked reader is in db_masked and out of db_client, reads the masks first,
// and its failing statements are never logged with their text.
func TestMaskedRoleSQL(t *testing.T) {
	sql := maskedRoleSQL("o'brien@example.com", "pa'ss")
	for _, want := range []string{
		"CREATE ROLE db_masked NOLOGIN",
		"NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS",
		"REVOKE db_client FROM %I",
		"GRANT db_masked TO %I",
		"SET role = db_masked",
		"SET search_path = bb_mask, public",
		"SET log_min_error_statement = panic",
		"'o''brien@example.com'",
		"'pa''ss'",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q:\n%s", want, sql)
		}
	}
	un := unmaskedRoleSQL("o'brien@example.com")
	for _, want := range []string{"REVOKE db_masked FROM %I", "GRANT db_client TO %I", "SET role = db_client",
		"RESET search_path", "RESET log_min_error_statement", "pg_has_role(r, 'db_masked', 'MEMBER')"} {
		if !strings.Contains(un, want) {
			t.Errorf("unmasking is missing %q:\n%s", want, un)
		}
	}
	if !strings.Contains(endSessionsSQL("a@b.c"), "pg_terminate_backend") {
		t.Error("the sessions are not ended")
	}
}

// The masked accounts' file: read again when it changes, and an admin or the
// branch's owner is never masked.
func TestAccountMasked(t *testing.T) {
	dir := t.TempDir()
	oldPath, oldExempt := maskedPath, maskExempt
	t.Cleanup(func() { maskedPath, maskExempt = oldPath, oldExempt; masked.byKey = nil })
	maskedPath = func() string { return filepath.Join(dir, "masked-accounts.json") }
	exempt := map[string]bool{}
	maskExempt = func(b, e string) bool { return exempt[b+"/"+e] }

	if accountMasked("main", "a@x.io") || len(MaskedAccounts()) != 0 {
		t.Fatal("masked with no file")
	}
	if err := SaveMaskedAccounts([]MaskedAccount{{Email: "A@x.io", By: "cli:root", At: "2026-11-05T10:00:00Z"}}); err != nil {
		t.Fatal(err)
	}
	if !accountMasked("main", "a@x.io") || !accountMasked("dev", "A@X.IO") {
		t.Fatal("a listed account is not masked")
	}
	exempt["dev/a@x.io"] = true
	if accountMasked("dev", "a@x.io") || !accountMasked("main", "a@x.io") {
		t.Fatal("the owner of dev is masked there, or exempt everywhere")
	}
	if st, err := os.Stat(maskedPath()); err != nil || st.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Fatalf("the file's mode: %v %v", st, err)
	}
	// A change made by another process is seen.
	time.Sleep(10 * time.Millisecond)
	if err := SaveMaskedAccounts([]MaskedAccount{{Email: "b@x.io"}, {Email: "c@x.io"}}); err != nil {
		t.Fatal(err)
	}
	if accountMasked("main", "a@x.io") || !accountMasked("main", "b@x.io") || len(MaskedAccounts()) != 2 {
		t.Fatalf("the change is not seen: %v", MaskedAccounts())
	}
	_ = os.Remove(maskedPath())
	if accountMasked("main", "b@x.io") {
		t.Fatal("still masked with the file gone")
	}
}

// Without Enterprise's masker every change is refused as not licensed, and
// nothing is written.
func TestMaskingNotLicensed(t *testing.T) {
	old := masker
	t.Cleanup(func() { masker = old })
	masker = nil
	oldPath := maskedPath
	t.Cleanup(func() { maskedPath = oldPath })
	maskedPath = func() string { return filepath.Join(t.TempDir(), "masked-accounts.json") }
	for name, err := range map[string]error{
		"setup":   SetupMasking("main", "cli:me"),
		"rule":    SetMaskRule("main", MaskRule{Schema: "public", Table: "t", Column: "c", Rule: MaskHash}),
		"drop":    DropMaskRule("main", "public", "t", "c", "", "cli:me"),
		"account": MaskAccount("a@x.io", "cli:me", false),
	} {
		if !errors.Is(err, ErrNotLicensed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(maskedPath()); err == nil {
		t.Error("an account was masked without the licence")
	}
}

// A named rule is checked before Enterprise is asked; an unnamed one is the
// category's default, chosen there.
func TestSetMaskRuleChecksFirst(t *testing.T) {
	edition.SetEntitlement(func(edition.Feature) bool { return true })
	t.Cleanup(func() { edition.SetEntitlement(nil) })
	if !edition.Has(edition.Masking) {
		t.Skip("the Standard build: the Enterprise run covers it")
	}
	old := masker
	t.Cleanup(func() { masker = old })
	var got []MaskRule
	masker = &Masker{SetRule: func(b string, r MaskRule) error { got = append(got, r); return nil }}
	if err := SetMaskRule("main", MaskRule{Rule: "hash", Category: "aadhaar"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("hashing Aadhaar: %v", err)
	}
	if err := SetMaskRule("main", MaskRule{Column: "c"}); err != nil || len(got) != 1 {
		t.Fatalf("an unnamed rule: %v %v", err, got)
	}
}

// The key is mounted read-only once masking is set up, and not before.
func TestMaskMount(t *testing.T) {
	old := MaskKeyDir
	t.Cleanup(func() { MaskKeyDir = old })
	dir := filepath.Join(t.TempDir(), "mask")
	MaskKeyDir = func() string { return dir }
	if MaskOn() || maskMount() != nil {
		t.Fatal("mounted before setup")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(maskMount(), " "); !MaskOn() || got != "-v "+dir+":/run/bb-mask:ro" {
		t.Fatalf("the mount: %q", got)
	}
}

// The cost is said before a rule is set (decision 9), from what was measured.
func TestMaskCost(t *testing.T) {
	if c := MaskCost(MaskPartial, ""); !strings.Contains(c, "nothing on writes") {
		t.Errorf("partial: %s", c)
	}
	c := MaskCost(MaskHash, "")
	if !strings.Contains(c, "3.6 times") || !strings.Contains(c, "a quarter") || strings.Contains(c, "64 KB") {
		t.Errorf("hash: %s", c)
	}
	if c := MaskCost(MaskPartial, "$.a"); !strings.Contains(c, "64 KB") || strings.Contains(c, "nothing on writes") {
		t.Errorf("a JSON path: %s", c)
	}
	if c := MaskCost("", ""); !strings.Contains(c, "3.6 times") {
		t.Errorf("an unnamed rule, which may need the key: %s", c)
	}
}
