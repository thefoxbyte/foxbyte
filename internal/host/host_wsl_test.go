// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"github.com/foxbyte/foxbyte/internal/brand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unicode/utf16"
)

// TC1.1 — distro name resolution.
func TestResolveWSLDistro(t *testing.T) {
	cases := map[string]string{"": brand.VMInstance, "  ": brand.VMInstance, "mine": "mine", "  spaced  ": "spaced"}
	for in, want := range cases {
		if got := resolveWSLDistro(in); got != want {
			t.Errorf("resolveWSLDistro(%q) = %q, want %q", in, got, want)
		}
	}
}

// TC1.2 — the wsl.exe argument list, including the in-guest marker and the
// staged image-context path.
func TestWSLArgs(t *testing.T) {
	got := wslArgs(brand.VMInstance, "/usr/local/bin/fox", guestEnv(), []string{"branch", "list"})
	want := []string{"-d", brand.VMInstance, "--", "env",
		"FOX_IN_GUEST=1",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"FOX_IMAGE_CONTEXT=/usr/local/share/dbengine/docker/postgres",
		"FOX_STORAGE=btrfs",
		"/usr/local/bin/fox", "branch", "list"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wslArgs = %q, want %q", got, want)
	}
}

func encodeUTF16LE(s string, bom bool) []byte {
	var b []byte
	if bom {
		b = append(b, 0xFF, 0xFE)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

// TC1.3 — parse `wsl -l -v` UTF-16LE output (BOM + `*` default marker + header).
func TestDecodeWSLList(t *testing.T) {
	raw := "  NAME            STATE           VERSION\n" +
		"* Ubuntu          Running         2\n" +
		"  foxbyte       Stopped         2\n"
	got := decodeWSLList(encodeUTF16LE(raw, true))
	want := []wslDistro{{"Ubuntu", "Running"}, {"foxbyte", "Stopped"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decodeWSLList = %+v, want %+v", got, want)
	}
	// Also tolerate plain UTF-8 (no NUL bytes).
	if got := decodeWSLList([]byte(raw)); !reflect.DeepEqual(got, want) {
		t.Errorf("decodeWSLList(utf8) = %+v, want %+v", got, want)
	}
}

// TC1.6 — Windows path → WSL /mnt path.
func TestWinPathToMnt(t *testing.T) {
	cases := map[string]string{
		`C:\Users\x\fox-linux-amd64`: "/mnt/c/Users/x/fox-linux-amd64",
		`D:\a b\file`:                "/mnt/d/a b/file",
		`/already/posix`:             "/already/posix",
	}
	for in, want := range cases {
		if got := winPathToMnt(in); got != want {
			t.Errorf("winPathToMnt(%q) = %q, want %q", in, got, want)
		}
	}
}

// TC1.5 — the kernel release read back from `uname -r` inside the distro, which
// arrives UTF-16LE-wrapped and newline-terminated from wsl.exe.
func TestParseKernelRelease(t *testing.T) {
	const rel = "6.6.87.2-microsoft-standard-WSL2"
	if got := parseKernelRelease(encodeUTF16LE(rel+"\n", true)); got != rel {
		t.Errorf("parseKernelRelease(utf16) = %q, want %q", got, rel)
	}
	if got := parseKernelRelease([]byte(rel + "\r\n")); got != rel {
		t.Errorf("parseKernelRelease(utf8) = %q, want %q", got, rel)
	}
	if got := parseKernelRelease([]byte("  \n")); got != "" {
		t.Errorf("parseKernelRelease(blank) = %q, want empty", got)
	}
}

// TC1.4 — importLocalFile rewrites a local file to a stdin stream; pass-through
// for postgres:// and non-files. (Shared launcher logic, OS-independent.)
func TestImportLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "people.csv")
	if err := os.WriteFile(path, []byte("id,name\n1,a\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, f, ok := importLocalFile([]string{"import", "--from", path, "--as", "p"})
	if !ok || f == nil {
		t.Fatalf("expected rewrite for a local file; ok=%v", ok)
	}
	defer f.Close()
	want := []string{"import", "--from", "-", "--kind", "csv", "--srcname", "people.csv", "--as", "p"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("rewrite = %q, want %q", out, want)
	}

	if _, _, ok := importLocalFile([]string{"import", "--from", "postgres://h/db"}); ok {
		t.Error("postgres:// should pass through (ok=false)")
	}
	if _, _, ok := importLocalFile([]string{"import", "--from", filepath.Join(dir, "nope.csv")}); ok {
		t.Error("missing file should pass through (ok=false)")
	}
	if _, _, ok := importLocalFile([]string{"branch", "list"}); ok {
		t.Error("non-import command should pass through (ok=false)")
	}
}
