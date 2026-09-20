// SPDX-License-Identifier: AGPL-3.0-or-later

// Package host makes `fox` a single cross-platform entry point.
//
// The branching engine needs Linux + ZFS + Docker, which don't exist natively
// on macOS or Windows. Rather than make users manage a VM by hand, `fox` hides
// it: on Linux the engine runs in-process; on macOS engine commands are
// forwarded into a Lima VM and on Windows into a WSL2 distro, transparently, so
// a user only ever types `fox …`.
//
// This file holds the OS-independent dispatch. The per-OS transport lives in
// host_darwin.go (Lima), host_windows.go (WSL2), and host_other.go (Linux/other),
// each providing forward/forwardStdin/hostSetup. Pure, testable WSL helpers are
// in host_wsl.go (untagged, so they unit-test on any OS).
package host

import (
	"context"
	"fmt"
	"github.com/foxbyte/foxbyte/internal/brand"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/foxbyte/foxbyte/internal/update"
)

// Guest environment variable marks a fox process that is already running inside
// the managed Linux VM, so it never tries to forward again.
const envInGuest = "FOX_IN_GUEST"

// localCommands run on the host machine itself and are never forwarded.
var localCommands = map[string]bool{
	"": true, "help": true, "-h": true, "--help": true,
	"version": true, "-v": true, "--version": true,
	"setup": true, "vm": true, "update": true,
}

// Maybe performs host-side dispatch.
//
//   - Linux, or already inside the guest VM: returns (false, nil) — the caller
//     runs the engine in-process.
//   - macOS/Windows engine command: forwards into the VM and returns (true, err).
//   - Local commands (version/help/setup) always return (false, nil).
func Maybe(args []string) (handled bool, err error) {
	if runtime.GOOS == "linux" || os.Getenv(envInGuest) != "" {
		return false, nil
	}
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	if localCommands[sub] {
		return false, nil
	}
	if sub == "start" {
		// Look for a newer release while the stack starts; the notice (if any)
		// is the last line printed.
		notice := StartUpdateNotice()
		err := hostForward(args)
		if err == nil {
			notice()
		}
		return true, err
	}
	return true, hostForward(args)
}

// Setup runs the one-time host bootstrap (create/start the VM) and is invoked by
// the `setup` command. Local commands reach it via the normal switch in main.
func Setup() error { return hostSetup() }

// hostForward forwards an engine command into the managed VM. `fox import --from
// <local file>` is special-cased: the file is streamed from THIS machine into the
// VM over stdin (so imports work from ANY path, not just a VM-mounted home).
func hostForward(args []string) error {
	if newArgs, f, ok := importLocalFile(args); ok {
		defer f.Close()
		return forwardStdin(newArgs, f)
	}
	return forward(args)
}

// importLocalFile detects `fox import --from <path>` where <path> is a readable
// file on THIS machine, and rewrites it to stream that file into the VM over
// stdin (`--from -`). Returns false for a postgres:// source or a path that
// isn't a local file (which is forwarded unchanged — it may exist in the VM).
func importLocalFile(args []string) ([]string, *os.File, bool) {
	if len(args) == 0 || args[0] != "import" {
		return nil, nil, false
	}
	path, fromFlag := "", false
	for i := 1; i < len(args); i++ {
		if args[i] == "--from" && i+1 < len(args) {
			path, fromFlag = args[i+1], true
			break
		}
	}
	if path == "" {
		for i := 1; i < len(args); i++ {
			if !strings.HasPrefix(args[i], "-") && !isPostgresURL(args[i]) {
				path = args[i]
				break
			}
		}
	}
	if path == "" || isPostgresURL(path) {
		return nil, nil, false
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		return nil, nil, false // not a local file — forward as-is (may exist in the VM)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, false
	}
	var rest []string
	for i := 1; i < len(args); i++ {
		if fromFlag && args[i] == "--from" && i+1 < len(args) {
			i++ // drop `--from <val>`
			continue
		}
		if !fromFlag && args[i] == path {
			continue // drop the bare source
		}
		rest = append(rest, args[i])
	}
	kind := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	out := append([]string{"import", "--from", "-", "--kind", kind, "--srcname", filepath.Base(path)}, rest...)
	return out, f, true
}

func isPostgresURL(s string) bool {
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

// cacheDir is where `fox setup` caches a freshly-downloaded engine binary. A
// user-writable path (no sudo), preferred over the installer-staged copy.
func cacheDir() string { return brand.StateDir() }

func regularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// bundledLinuxBinary looks for a prebuilt linux fox (fox-linux-<arch>): first a
// build `fox setup` freshly downloaded into the cache dir, then one the installer
// staged alongside the host binary, then ./dist for a dev build. Used by both the
// macOS (Lima) and Windows (WSL2) setup paths to seed the guest.
func bundledLinuxBinary(arch string) string {
	if c := filepath.Join(cacheDir(), "fox-linux-"+arch); regularFile(c) {
		return c
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	for _, c := range []string{
		filepath.Join(dir, "fox-linux-"+arch),
		filepath.Join(dir, "..", "share", "foxbyte", "fox-linux-"+arch),
		filepath.Join(dir, "..", "dist", "fox-linux-"+arch),
		filepath.Join(dir, "dist", "fox-linux-"+arch),
	} {
		if regularFile(c) {
			return c
		}
	}
	return ""
}

// refreshEngineBinary downloads the latest Linux engine binary into the cache dir
// so `fox setup` installs the newest build instead of reusing a stale one, and
// overwrites the previous cached build. Best-effort: on any problem it returns
// "" and setup falls back to the installer-staged binary. FOX_NO_REFRESH=1
// skips it (offline or version-pinned installs); FOX_REPO / FOX_VERSION override
// the source, matching the installer.
func refreshEngineBinary(arch string) string {
	if v := brand.Getenv("NO_REFRESH"); v == "1" || v == "true" {
		return ""
	}
	asset := "fox-linux-" + arch
	dest := filepath.Join(cacheDir(), asset)
	fmt.Println("Checking for the latest engine build…")

	if truthyEnv("FOX_NO_VERIFY") {
		// Deliberately unverified (an air-gapped mirror, or a release whose
		// checksums are unreachable). Same behaviour as before verification.
		fmt.Println("note: FOX_NO_VERIFY is set — the engine download will not be checked against SHA256SUMS.")
		url := fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", envOr("FOX_REPO", "foxbyte/foxbyte"), asset)
		if v := envOr("FOX_VERSION", "latest"); v != "latest" {
			url = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", envOr("FOX_REPO", "foxbyte/foxbyte"), v, asset)
		}
		if err := downloadFile(url, dest); err != nil || !isELF(dest) {
			_ = os.Remove(dest)
			fmt.Println("note: could not fetch a usable build — using the installed one.")
			return ""
		}
		return dest
	}

	// The engine is installed into the VM and run as root, so it is downloaded
	// through the same verified path as `fox update`: the release's SHA256SUMS
	// decides, and a file that doesn't match is never kept.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	c := update.NewClient(os.Getenv, filepath.Join(cacheDir(), "update-check.json"))
	keep := func(format string, a ...any) string {
		fmt.Printf("note: "+format+" — using the engine the installer staged.\n", a...)
		return ""
	}
	offer, err := c.Release(ctx, envOr("FOX_VERSION", "latest"), update.Target{GOOS: "linux", HostArch: arch})
	if err != nil {
		return keep("could not read the release (%v)", err)
	}
	a, ok := offer.Release.Asset(asset)
	if !ok {
		return keep("release %s has no %s", offer.Release.Tag, asset)
	}
	path, err := c.Download(ctx, a, offer.Sums[asset], cacheDir())
	if err != nil {
		return keep("%v", err)
	}
	if !isELF(path) { // verified bytes, but not a Linux binary
		_ = os.Remove(path)
		return keep("%s in release %s is not a Linux binary", asset, offer.Release.Tag)
	}
	fmt.Printf("Engine %s from %s verified against SHA256SUMS.\n", asset, offer.Release.Tag)
	return path
}

// truthyEnv reports whether an env var is set to an on-ish value.
func truthyEnv(key string) bool {
	switch strings.ToLower(strings.TrimSpace(brand.GetenvFull(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(brand.GetenvFull(key)); v != "" {
		return v
	}
	return def
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest) // atomic replace of the previous cached build
}

// isELF reports whether a file starts with the ELF magic — a cheap sanity check
// that the download is a Linux binary and not an error page.
func isELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic == [4]byte{0x7f, 'E', 'L', 'F'}
}
