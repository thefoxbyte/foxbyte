// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// compress writes data as a .zst the way the release build does: a long window,
// so the decoder has to accept one.
func compress(t *testing.T, path string, data []byte) {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf, zstd.WithWindowSize(1<<27), zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestUnpackZstdRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// Repetitive and random halves: something that compresses, and something
	// that does not, as a rootfs full of binaries has both.
	data := bytes.Repeat([]byte("PostgreSQL 18 on btrfs\n"), 50_000)
	noise := make([]byte, 1<<20)
	_, _ = rand.Read(noise)
	data = append(data, noise...)

	src := filepath.Join(dir, "foxbyte-distro.tar.zst")
	compress(t, src, data)

	file, done, err := importableDistro(src, dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "foxbyte-distro.tar"); file != want {
		t.Errorf("unpacked to %s, want %s", file, want)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("unpacked %d bytes that differ from the %d compressed", len(got), len(data))
	}
	done()
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Error("done() should remove the unpacked tar; the compressed image is what is kept")
	}
}

// A damaged download must fail without leaving a tar behind: `wsl --import`
// would take a truncated one for a whole distro.
func TestUnpackZstdLeavesNothingOnDamage(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "foxbyte-distro.tar.zst")
	compress(t, src, bytes.Repeat([]byte("distro "), 200_000))
	b, _ := os.ReadFile(src)
	if err := os.WriteFile(src, b[:len(b)/2], 0o644); err != nil { // cut short
		t.Fatal(err)
	}
	if _, _, err := importableDistro(src, dir); err == nil {
		t.Fatal("a truncated image should not unpack")
	}
	for _, left := range []string{"foxbyte-distro.tar", "foxbyte-distro.tar.partial"} {
		if _, err := os.Stat(filepath.Join(dir, left)); !os.IsNotExist(err) {
			t.Errorf("%s was left behind after a failed unpack", left)
		}
	}
}

// A gzip image, from a release before the switch, is imported as it is.
func TestImportableDistroPassesGzipThrough(t *testing.T) {
	file, done, err := importableDistro(`C:\x\foxbyte-distro.tar.gz`, t.TempDir())
	if err != nil || file != `C:\x\foxbyte-distro.tar.gz` {
		t.Errorf("got %q, %v", file, err)
	}
	done()
}

// The release build's --long window must fit what the decoder accepts, or every
// Windows install fails to unpack an image the build produced without complaint.
func TestDistroBuildWindowFitsTheDecoder(t *testing.T) {
	b, err := os.ReadFile("../../deploy/wsl-distro/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`zstd [^\n]*--long=(\d+)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("deploy/wsl-distro/build.sh should compress the distro with zstd --long=<n>")
	}
	n, _ := strconv.Atoi(string(m[1]))
	if uint64(1)<<n > maxDistroWindow {
		t.Errorf("build.sh uses --long=%d (a %d MiB window); the decoder accepts at most %d MiB",
			n, (1<<n)>>20, maxDistroWindow>>20)
	}
}

func TestDistroImagesPreferZstd(t *testing.T) {
	if len(distroImageNames) < 2 || distroImageNames[0] != "foxbyte-distro.tar.zst" {
		t.Errorf("setup should prefer the zstd image and still accept gzip: %v", distroImageNames)
	}
}
