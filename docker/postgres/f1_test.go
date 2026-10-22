// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The context built into fox carries the F1 prototype's extension, in its own
// directory, so an image built from it can be built WITH_F1=on too.
func TestContextCarriesTheF1Extension(t *testing.T) {
	dir := t.TempDir()
	if err := WriteContext(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"Dockerfile", "restore-entrypoint.sh", "fox_ed25519/fox_ed25519.c",
		"fox_ed25519/fox_ed25519.control", "fox_ed25519/fox_ed25519--0.1.sql", "fox_ed25519/Makefile"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s is not in the written context: %v", f, err)
		}
	}
}

// The prototype is off unless asked for: a published image must be the image
// it was before (docs/FOX_F1_Identity_Design.md, section 13).
func TestF1IsOffByDefault(t *testing.T) {
	b, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	d := string(b)
	if !strings.Contains(d, "ARG WITH_F1=off") || !strings.Contains(d, `if [ "${WITH_F1}" = "on" ]; then`) {
		t.Fatal("the Dockerfile should build the extension only when WITH_F1=on, defaulting to off")
	}
}
