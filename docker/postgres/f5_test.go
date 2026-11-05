// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres_test

import (
	"os"
	"strings"
	"testing"
)

func readLF(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// The masking hash is an oracle in a masked reader's hands (F5 design,
// section 3, E3): whichever way the extension arrives, at 0.2 or updated to
// it, nobody is given EXECUTE on it but whoever the engine grants it to.
func TestMaskHashIsNeverPublic(t *testing.T) {
	for _, f := range []string{"bb_identity/bb_identity--0.2.sql", "bb_identity/bb_identity--0.1--0.2.sql"} {
		s := readLF(t, f)
		if !strings.Contains(s, "CREATE FUNCTION bbid_mask_hmac(domain text, value text)") {
			t.Errorf("%s does not make bbid_mask_hmac", f)
		}
		if !strings.Contains(s, "REVOKE EXECUTE ON FUNCTION bbid_mask_hmac(text, text) FROM PUBLIC;") {
			t.Errorf("%s leaves bbid_mask_hmac executable by PUBLIC", f)
		}
	}
	if c := readLF(t, "bb_identity/bb_identity.control"); !strings.Contains(c, "default_version = '0.2'") {
		t.Error("bb_identity's default version should be 0.2")
	}
	mk := readLF(t, "bb_identity/Makefile")
	for _, f := range []string{"bb_identity--0.1.sql", "bb_identity--0.2.sql", "bb_identity--0.1--0.2.sql"} {
		if !strings.Contains(mk, f) {
			t.Errorf("the Makefile does not install %s", f)
		}
	}
}

// The key is read from one fixed place, a file of the server's own that
// nobody else can read, and its bytes are never in a message.
func TestMaskKeyIsAFileOfTheServersOwn(t *testing.T) {
	c := readLF(t, "bb_identity/bb_identity.c")
	for _, want := range []string{`"/run/bb-mask/%s.key"`, "st.st_uid != geteuid()", "(st.st_mode & 077) != 0", "mask_domain_ok(domain)"} {
		if !strings.Contains(c, want) {
			t.Errorf("bb_identity.c: missing %s", want)
		}
	}
	start := strings.Index(c, "/* ---- masking (F5)")
	if start < 0 {
		t.Fatal("the masking section was not found")
	}
	for _, line := range strings.Split(c[start:], "\n") {
		if strings.Contains(line, "errmsg(") && strings.Contains(line, "key[") {
			t.Errorf("a message that could carry the key: %s", strings.TrimSpace(line))
		}
	}
}
