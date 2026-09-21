// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// distroImageNames are the prebuilt Windows distro — Ubuntu with Docker, the
// btrfs tools, the engine and the container images already in place — in the
// order setup prefers them. Importing one replaces an apt install, a docker
// build and three registry pulls on the user's machine.
//
// Releases publish it zstd-compressed: at the same content it is a markedly
// smaller download than gzip, and zstd unpacks fast enough that the download
// saved is not spent again waiting for it. But `wsl --import` and the tar.exe
// built into Windows are only dependable with gzip, so fox unpacks the zstd
// image itself (unpackZstd) and imports the plain tar. Releases before the
// switch published gzip, which `wsl --import` reads as it is.
var distroImageNames = []string{"foxbyte-distro.tar.zst", "foxbyte-distro.tar.gz"}

// maxDistroWindow is the largest zstd window unpackZstd accepts, the decoder's
// default. deploy/wsl-distro/build.sh compresses with --long=27 (128 MiB), and
// a test keeps that within this.
const maxDistroWindow = zstd.MaxWindowSize

// importableDistro returns a file `wsl --import` can read for the image at
// path: the image itself, or for a zstd image a plain tar unpacked into dir.
// done removes whatever was unpacked, and is safe to call when nothing was.
func importableDistro(path, dir string) (file string, done func(), err error) {
	if !strings.HasSuffix(path, ".zst") {
		return path, func() {}, nil
	}
	tar := filepath.Join(dir, strings.TrimSuffix(filepath.Base(path), ".zst"))
	if err := unpackZstd(path, tar); err != nil {
		return "", func() {}, err
	}
	return tar, func() { _ = os.Remove(tar) }, nil
}

// unpackZstd decompresses src into dst. It writes to dst.partial and renames at
// the end, so an interrupted unpack — a full disk, a closed window — never
// leaves a truncated tar where the import would take it for a whole one.
func unpackZstd(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dec, err := zstd.NewReader(in, zstd.WithDecoderMaxWindow(maxDistroWindow))
	if err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Base(src), err)
	}
	defer dec.Close()

	partial := dst + ".partial"
	out, err := os.Create(partial)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, dec)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(partial)
		if copyErr == nil {
			copyErr = closeErr
		}
		return fmt.Errorf("unpacking %s: %w", filepath.Base(src), copyErr)
	}
	return os.Rename(partial, dst)
}
