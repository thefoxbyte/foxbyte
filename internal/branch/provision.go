// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"github.com/foxbyte/foxbyte/internal/brand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The branching engine needs three things on the Linux host before anything can
// start: a reachable Docker daemon, a ZFS pool (with the base dataset), and the
// Postgres+wal-g image. Historically an operator created all of these by hand
// (truncate a file, zpool create, zfs create, docker build) — that is the bulk
// of the old setup instructions. Provision does it automatically and
// idempotently, so day-to-day use collapses to a single `fox up`/`fox start`.

const (
	// pool is derived from datasetBase ("dbpool/branches" -> "dbpool").
	pool = "dbpool"
	// Pool is the same name, exported for the uninstaller.
	Pool = pool

	// Defaults for auto-creating the pool on a loopback file when no ZFS pool
	// exists yet. Overridable via env for operators with a spare block device.
	defaultZpoolFile = "/var/lib/dbpool-zpool.img"
	defaultZpoolSize = "30G"

	envZpoolDevice  = "FOX_ZPOOL_DEVICE"  // block device or file for the pool vdev
	envZpoolSize    = "FOX_ZPOOL_SIZE"    // size when creating a file vdev
	envImageContext = "FOX_IMAGE_CONTEXT" // docker build context for the image
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(brand.GetenvFull(key)); v != "" {
		return v
	}
	return def
}

// Provision makes the host ready to run the stack. Safe to call on an
// already-provisioned host: each step is a no-op when its resource exists.
func Provision() error {
	if err := ensureDocker(); err != nil {
		return err
	}
	if err := ensurePool(); err != nil {
		return err
	}
	return ensureImage()
}

// ensureDocker verifies Docker is installed and its daemon is reachable.
func ensureDocker() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("Docker is not installed or not on PATH — install Docker and retry")
	}
	if exec.Command("sudo", "docker", "info").Run() != nil {
		return fmt.Errorf("cannot reach the Docker daemon — is Docker running?")
	}
	return nil
}

func poolExists() bool {
	return exec.Command("sudo", "zpool", "list", "-H", "-o", "name", pool).Run() == nil
}

// ensurePool makes the copy-on-write substrate ready. Which substrate that is
// depends on the configured driver: ZFS on macOS and Linux, btrfs on Windows,
// where an out-of-tree module cannot be relied on. See storage.go.
func ensurePool() error {
	return activeStorage().ensureReady()
}

func imageExists() bool {
	return exec.Command("sudo", "docker", "image", "inspect", image).Run() == nil
}

// ensureImage guarantees the Postgres+wal-g image is present. It prefers pulling
// the published multi-arch image (fast, and independent of the wal-g release
// being reachable at install time) and falls back to building from the repo
// context — for contributors, offline installs, or before the image is
// published.
func ensureImage() error {
	if imageExists() {
		return nil
	}
	fmt.Printf("Fetching image %s…\n", image)
	if run("docker", "pull", image) == nil {
		return nil
	}
	ctx := envOr(envImageContext, findImageContext())
	if ctx == "" {
		return fmt.Errorf("image %s could not be pulled and no build context was found — "+
			"set %s to the docker/postgres directory, or pre-build the image", image, envImageContext)
	}
	fmt.Printf("Building image %s from %s (this can take a minute)…\n", image, ctx)
	return run("docker", "build", "-t", image, ctx)
}

// findImageContext looks for the docker/postgres build context near the current
// working directory (the repo is present in dev/self-host-from-source setups).
func findImageContext() string {
	candidates := []string{
		"docker/postgres",
		"../docker/postgres",
		"../../docker/postgres",
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "docker", "postgres"))
	}
	for _, c := range candidates {
		if fi, err := os.Stat(filepath.Join(c, "Dockerfile")); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}
