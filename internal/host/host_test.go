// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

var elfMagic = []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01}

func TestIsELF(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(good, elfMagic, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("<html>404</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !isELF(good) {
		t.Error("expected ELF file to be recognized")
	}
	if isELF(bad) {
		t.Error("expected non-ELF file to be rejected")
	}
	if isELF(filepath.Join(dir, "missing")) {
		t.Error("expected a missing file to be rejected")
	}
}

func TestBundledLinuxBinaryPrefersCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)        // os.UserHomeDir on unix
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	cache := filepath.Join(home, ".fox")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cache, "fox-linux-testarch")
	if err := os.WriteFile(want, elfMagic, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := bundledLinuxBinary("testarch"); got != want {
		t.Errorf("bundledLinuxBinary = %q, want the cached copy %q", got, want)
	}
}

func TestRefreshEngineBinaryDisabled(t *testing.T) {
	t.Setenv("FOX_NO_REFRESH", "1")
	if got := refreshEngineBinary("arm64"); got != "" {
		t.Errorf("refreshEngineBinary should return \"\" when disabled, got %q", got)
	}
}

func TestDownloadFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(elfMagic)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "fox-linux-x")
	if err := downloadFile(srv.URL, dest); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	if !isELF(dest) {
		t.Error("downloaded file should pass the ELF check")
	}

	// A 404 must be an error, not a silently-written file.
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer notFound.Close()
	if err := downloadFile(notFound.URL, filepath.Join(t.TempDir(), "x")); err == nil {
		t.Error("expected an error for a 404 response")
	}
}
