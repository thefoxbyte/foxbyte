// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The context built into fox carries the bb_identity extension, in its own
// directory, so an image built from it has application identity too.
func TestContextCarriesTheF1Extension(t *testing.T) {
	dir := t.TempDir()
	if err := WriteContext(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"Dockerfile", "restore-entrypoint.sh", "bb_identity/bb_identity.c",
		"bb_identity/bb_identity.control", "bb_identity/bb_identity--0.1.sql", "bb_identity/Makefile"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s is not in the written context: %v", f, err)
		}
	}
}

// Every image has the extension: an install that builds its own image must get
// the same one a pull would. The prototype's WITH_F1 switch is gone.
func TestEveryImageBuildsTheExtension(t *testing.T) {
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	d := string(b)
	if strings.Contains(d, "WITH_F1") {
		t.Error("the Dockerfile still makes the extension optional (WITH_F1)")
	}
	if !strings.Contains(d, "COPY --from=f1-build /out/ /") || !strings.Contains(d, `test -f "/out/usr/lib/postgresql/${PG_MAJOR}/lib/bb_identity.so"`) {
		t.Error("the Dockerfile should build bb_identity, check the library was made, and copy it into the image")
	}
}
