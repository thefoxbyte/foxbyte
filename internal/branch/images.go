// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"os/exec"
	"strings"
)

// MinIO's container images are no longer served from Docker Hub (minio/minio and
// minio/mc stopped resolving in 2026); they are still published on quay.io. The
// engine uses quay.io, pinned to the releases FoxByte was tested with, so a
// fresh install gets exactly the server existing installs run rather than
// whatever "latest" is that day. deploy/wsl-distro/build.sh preloads the same
// names (a test keeps the two in step).
const (
	MinioImage = "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z"
	MCImage    = "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z"

	// The names installs made before the move pulled from Docker Hub. An install
	// that already has one cached keeps using it, so upgrading fox needs no pull.
	legacyMinioImage = "minio/minio:latest"
	legacyMCImage    = "minio/mc:latest"

	// PGMajor is the PostgreSQL major a fresh install runs.
	PGMajor = "18"
)

// SupportedPGMajors are the PostgreSQL majors this fox can run an install on.
// A fresh install gets PGMajor; an install created under an older one keeps
// running it (pgImage follows the data, not the binary) until its owner moves
// it. The release workflow publishes an engine image for each, and a test keeps
// the workflow, the Dockerfile and the Windows preload in step with this list.
var SupportedPGMajors = []string{"16", PGMajor}

// PostgresImageFor names the engine image — stock Postgres plus wal-g, built
// from docker/postgres — for one PostgreSQL major.
func PostgresImageFor(major string) string {
	return brand.ImageRepo + "/postgres-walg:" + major
}

// pickImage chooses the image to run: an explicit override, else the pinned
// image if it is present, else a legacy image already on this machine, else the
// pinned image (which docker pulls).
func pickImage(override, pinned, legacy string, present func(string) bool) string {
	if o := strings.TrimSpace(override); o != "" {
		return o
	}
	if present(pinned) {
		return pinned
	}
	if present(legacy) {
		return legacy
	}
	return pinned
}

func imagePresent(ref string) bool {
	return exec.Command("sudo", "docker", "image", "inspect", ref).Run() == nil
}

// minioImage is the MinIO server image to run (FOX_MINIO_IMAGE overrides,
// e.g. for a registry mirror).
func minioImage() string {
	return pickImage(brand.Getenv("MINIO_IMAGE"), MinioImage, legacyMinioImage, imagePresent)
}

// mcImage is the MinIO client image used to create the WAL bucket
// (FOX_MC_IMAGE overrides).
func mcImage() string {
	return pickImage(brand.Getenv("MC_IMAGE"), MCImage, legacyMCImage, imagePresent)
}
