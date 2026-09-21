// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CopyFile copies src to dst with the given mode, replacing dst.
func CopyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".fox-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return true
}

// DirWritable reports whether this user can create files in dir.
func DirWritable(dir string) bool { return dirWritable(dir) }

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// keepPrevious copies the binary about to be replaced to prev, so the previous
// version stays available.
func keepPrevious(dest, prev string) error {
	if prev == "" || !exists(dest) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(prev), 0o755); err != nil {
		return fmt.Errorf("keeping the previous binary: %w", err)
	}
	if err := CopyFile(dest, prev, 0o755); err != nil {
		return fmt.Errorf("keeping the previous binary: %w", err)
	}
	return nil
}

// InstallBinary replaces dest with src (mode 0755), first copying the current
// dest to prev. The new file is written next to dest and renamed over it, so a
// process still running the old binary keeps its copy and dest is never
// half-written. When dest's directory isn't writable by this user it uses sudo
// (inside the Lima VM sudo needs no password).
func InstallBinary(src, dest, prev string) error {
	if !exists(src) {
		return fmt.Errorf("%s: no such file", src)
	}
	if err := keepPrevious(dest, prev); err != nil {
		return err
	}
	dir := filepath.Dir(dest)
	tmp := filepath.Join(dir, ".update.new")
	if dirWritable(dir) {
		if err := CopyFile(src, tmp, 0o755); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, dest); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		return nil
	}
	const script = `set -e; install -m 0755 "$1" "$2"; mv -f "$2" "$3"`
	cmd := exec.Command("sudo", "sh", "-c", script, "sh", src, tmp, dest)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installing %s (with sudo): %w", dest, err)
	}
	return nil
}

// retry runs f up to 10 times over ~5s: on Windows, antivirus scanners briefly
// lock freshly written executables.
func retry(f func() error) error {
	var err error
	for i := 0; i < 10; i++ {
		if err = f(); err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
}

// SwapExecutable replaces an executable that may be running — the way Windows
// allows it: a running .exe can't be overwritten or deleted, but it can be
// renamed. dest moves to dest.old (removed on the next update), src is copied
// in, and if that fails the original is put back. The current dest is first
// copied to prev.
func SwapExecutable(src, dest, prev string) error {
	if !exists(src) {
		return fmt.Errorf("%s: no such file", src)
	}
	if err := keepPrevious(dest, prev); err != nil {
		return err
	}
	old := dest + ".old"
	_ = os.Remove(old)
	moved := false
	if exists(dest) {
		if err := retry(func() error { return os.Rename(dest, old) }); err != nil {
			return fmt.Errorf("moving the running %s aside: %w", filepath.Base(dest), err)
		}
		moved = true
	}
	if err := retry(func() error { return CopyFile(src, dest, 0o755) }); err != nil {
		_ = os.Remove(dest)
		if moved {
			_ = os.Rename(old, dest)
		}
		return fmt.Errorf("installing %s: %w", filepath.Base(dest), err)
	}
	return nil
}

// ReplaceDirFromTarGz unpacks a .tar.gz into dir, keeping the directory it
// replaces as dir.prev. It unpacks into dir.new first, so dir is never left
// half-written.
func ReplaceDirFromTarGz(archive, dir string) error {
	next, prev := dir+".new", dir+".prev"
	_ = os.RemoveAll(next)
	if err := extractTarGz(archive, next); err != nil {
		_ = os.RemoveAll(next)
		return err
	}
	if exists(dir) {
		_ = os.RemoveAll(prev)
		if err := os.Rename(dir, prev); err != nil {
			_ = os.RemoveAll(next)
			return err
		}
	}
	if err := os.Rename(next, dir); err != nil {
		if exists(prev) {
			_ = os.Rename(prev, dir)
		}
		return err
	}
	return nil
}

func extractTarGz(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(archive), err)
	}
	defer gz.Close()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(archive), err)
		}
		name := filepath.Clean(filepath.FromSlash(h.Name))
		if name == "." {
			continue
		}
		target := filepath.Join(root, name)
		if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
			return fmt.Errorf("%s: entry %q points outside the directory", filepath.Base(archive), h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(h.Mode)&0o777|0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		}
	}
}
