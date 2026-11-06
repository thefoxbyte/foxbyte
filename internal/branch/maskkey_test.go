// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A domain a person names is a file name, its next key's name is one too and
// never a name a person could give, and "-" is kept for that.
func TestCheckMaskDomain(t *testing.T) {
	for _, ok := range []string{"default", "tenant_a", "t", "a23456789012345678901234"} {
		if err := CheckMaskDomain(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
		if !maskDomainOK(NextMaskKey(ok)) {
			t.Errorf("%q's next key, %q, is not a name bb_identity reads", ok, NextMaskKey(ok))
		}
		if CheckMaskDomain(NextMaskKey(ok)) == nil {
			t.Errorf("%q's next key could be a domain", ok)
		}
	}
	for _, bad := range []string{"", "Default", "1st", "a-b", "a.b", "../x", "a/b", "a b", "a234567890123456789012345", "x--next"} {
		if err := CheckMaskDomain(bad); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// The records: the default domain of an install set up before they were kept
// is its first key; a record is kept, replaced and dropped; the file is the
// owner's only.
func TestMaskKeyRecords(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldPath := MaskKeyDir, maskKeysPath
	t.Cleanup(func() { MaskKeyDir, maskKeysPath = oldDir, oldPath })
	MaskKeyDir = func() string { return filepath.Join(dir, "mask") }
	maskKeysPath = func() string { return filepath.Join(dir, "mask-keys.json") }

	if len(MaskKeys()) != 0 {
		t.Fatal("keys before masking was set up")
	}
	if err := os.Mkdir(MaskKeyDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if k, ok := MaskKeyFor(DefaultMaskDomain); !ok || k.Gen != 1 || k.Made != "" {
		t.Fatalf("a step 1 install's key: %+v %v", k, ok)
	}
	if err := RecordMaskKey(MaskKey{Domain: "tenant_b", Gen: 1, By: "cli:a"}); err != nil {
		t.Fatal(err)
	}
	if err := RecordMaskKey(MaskKey{Domain: "tenant_a", Gen: 1}); err != nil {
		t.Fatal(err)
	}
	if err := RecordMaskKey(MaskKey{Domain: "tenant_b", Gen: 2, Pending: true}); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, k := range MaskKeys() {
		names = append(names, k.Domain)
	}
	if got := strings.Join(names, " "); got != "default tenant_a tenant_b" {
		t.Errorf("the order: %s", got)
	}
	if k, _ := MaskKeyFor("tenant_b"); k.Gen != 2 || !k.Pending {
		t.Errorf("not replaced: %+v", k)
	}
	if st, err := os.Stat(maskKeysPath()); err != nil || os.PathSeparator == '/' && st.Mode().Perm() != 0o600 {
		t.Errorf("the file: %v %v", st, err)
	}
	if err := ForgetMaskKey("tenant_a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := MaskKeyFor("tenant_a"); ok {
		t.Error("still there")
	}
	b, _ := os.ReadFile(maskKeysPath())
	if strings.Contains(string(b), "key\":") {
		t.Errorf("a key in the records: %s", b)
	}
}

// What a rotation does is said before it runs.
func TestMaskRotateCost(t *testing.T) {
	c := MaskRotateCost("tenant_a")
	for _, want := range []string{"tenant_a", "21 seconds a million rows", "old masks until each table is done",
		"do not match", "There is no undo", "Partial and empty"} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q:\n%s", want, c)
		}
	}
}

// Without Enterprise every key change is refused as not licensed.
func TestMaskKeysNotLicensed(t *testing.T) {
	old := masker
	t.Cleanup(func() { masker = old })
	masker = nil
	for name, err := range map[string]error{
		"create": CreateMaskDomain("tenant_a", "cli:me"),
		"drop":   DropMaskDomain("tenant_a", "cli:me"),
		"rotate": RotateMaskKey("default", "cli:me", func(string) {}),
		"use":    UseMaskDomain("main", "public", "t", "tenant_a", "cli:me"),
	} {
		if !errors.Is(err, ErrNotLicensed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A stopped branch may use a domain if a table was put under it there, or if
// the branch was made since the domain (a copy of one that does); one made
// before and never used is not asked about. Unknown is "may".
func TestMayUseDomain(t *testing.T) {
	made := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	k := MaskKey{Domain: "tenant_a", Made: made.Format(time.RFC3339), UsedOn: []string{"used"}}
	at := map[string]time.Time{"old": made.Add(-time.Hour), "used": made.Add(-time.Hour), "new": made.Add(time.Minute), "same": made}
	madeAt := func(n string) (time.Time, bool) { t, ok := at[n]; return t, ok }
	for n, want := range map[string]bool{"old": false, "used": true, "new": true, "same": true, "unknown": true} {
		if got := mayUseDomain(k, n, madeAt); got != want {
			t.Errorf("%s: %v, want %v", n, got, want)
		}
	}
	if !mayUseDomain(MaskKey{Domain: "x"}, "old", madeAt) {
		t.Error("a domain with no making time: every stopped branch may use it")
	}
}
