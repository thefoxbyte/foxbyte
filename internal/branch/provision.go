// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	pgcontext "github.com/thefoxbyte/foxbyte/docker/postgres"
	"github.com/thefoxbyte/foxbyte/internal/brand"
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

func imageExists(ref string) bool {
	return exec.Command("sudo", "docker", "image", "inspect", ref).Run() == nil
}

// ensureImage guarantees the Postgres+wal-g image is present. It prefers pulling
// the published multi-arch image (fast, and independent of the wal-g release
// being reachable at install time) and falls back to building from the repo
// context — for contributors, offline installs, or before the image is
// published.
func ensureImage() error { return ensureImageRef(pgImage()) }

// ensureImageRef guarantees one engine image is present: pulled, or built from
// the context for the major its tag names. `fox pg upgrade` needs the new
// major's image while the install still runs on the old one.
func ensureImageRef(image string) error {
	if imageExists(image) {
		return nil
	}
	fmt.Printf("Fetching image %s…\n", image)
	if run("docker", "pull", image) == nil {
		return nil
	}
	ctx, where := chooseImageContext(envOr(envImageContext, ""), findImageContext())
	if ctx == "" {
		dir, err := os.MkdirTemp("", "fox-image-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		if err := pgcontext.WriteContext(dir); err != nil {
			return fmt.Errorf("writing the image's build context: %w", err)
		}
		ctx = dir
	}
	fmt.Printf("Could not pull %s; building it here from %s instead (a few minutes, once)…\n", image, where)
	if err := run("docker", buildImageArgs(image, ctx)...); err != nil {
		return fmt.Errorf("image %s could not be pulled, and building it here failed too (%v).\n%s", image, err, pullHint)
	}
	return nil
}

// pullHint is what to check when neither the pull nor the local build worked.
// Both need the network: the build fetches the stock postgres image from Docker
// Hub and wal-g from GitHub.
const pullHint = "Check this machine can reach Docker Hub (docker.io) and github.com. If the pull said \"unauthorized\", " +
	"the image's package is private or not yet published for this release; the local build does not need it, " +
	"but it does need those two sites."

// chooseImageContext picks where a local build of the engine image comes from:
// FOX_IMAGE_CONTEXT, then a docker/postgres beside the working directory (a
// checkout of the repository), then the copy built into fox, which is always
// there — the empty dir says to write that one out. where names the choice.
func chooseImageContext(env, found string) (dir, where string) {
	switch {
	case env != "":
		return env, env + " (" + envImageContext + ")"
	case found != "":
		return found, found
	}
	return "", "the Dockerfile built into " + brand.CLI
}

// buildImageArgs builds the engine image for the major its tag names: one
// Dockerfile serves every supported major through its PG_MAJOR argument, so a
// local build of the 16 image for an older install is still a 16 image.
func buildImageArgs(image, ctx string) []string {
	args := []string{"build", "-t", image}
	if m := imageMajor(image); m != "" {
		args = append(args, "--build-arg", "PG_MAJOR="+m)
		if d := PostgresBaseDigests[m]; d != "" {
			args = append(args, "--build-arg", "PG_DIGEST="+d)
		}
	}
	return append(args, ctx)
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
