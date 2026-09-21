// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// What fox builds from must be exactly what the release builds from.
func TestWriteContextMatchesTheSources(t *testing.T) {
	dir := t.TempDir()
	if err := WriteContext(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Dockerfile", "restore-entrypoint.sh"} {
		want, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from docker/postgres/%s", name, name)
		}
	}
	// Windows has no executable bit to keep: a mode written as 0755 reads back
	// without the x bits there. The context is only ever built on Linux (in the
	// VM or the WSL distro), which is where this matters.
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(filepath.Join(dir, "restore-entrypoint.sh")); err != nil || fi.Mode()&0o111 == 0 {
			t.Error("the entrypoint must stay executable: the Dockerfile COPYs it and chmods it, but a build context should not rely on that")
		}
	}
}
