// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"os/exec"
	"strings"
)

// MinIO's container images are no longer served from Docker Hub (minio/minio and
// minio/mc stopped resolving in 2026); they are still published on quay.io. The
// engine uses quay.io, pinned to the releases FoxByte was tested with — by tag
// and by digest (audit v2 G23), so a pull gets exactly those bytes even if the
// tag is moved. deploy/wsl-distro/build.sh preloads the same images (a test
// keeps the two in step).
const (
	MinioImage = MinioTag + "@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
	MCImage    = MCTag + "@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"
	MinioTag   = "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z"
	MCTag      = "quay.io/minio/mc:RELEASE.2025-08-13T08-35-41Z"

	// PGMajor is the PostgreSQL major a fresh install runs.
	PGMajor = "18"
)

// PostgresBaseDigests pins the official postgres:<major>-bookworm image the
// engine image is built FROM, per major (multi-arch index digests, 22 Sep 2026).
// The Dockerfile's default, the release workflow's matrix and the Windows
// distro's build carry the same values; a test keeps them in step. Moving a
// pin picks up the base image's security fixes: Dependabot proposes it.
var PostgresBaseDigests = map[string]string{
	"16": "sha256:efedf3595f1d6f415c08568ba171029bf54052e754cc9f030e3f2412b21f3d67",
	"18": "sha256:3725f4e2499eef5134592b3b4ab79a543ed7f8e533b05b5b637af926630f6650",
}

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

// pickImage chooses the image to run: an explicit override; else the pinned
// tag when it is already on this machine (the Windows distro preloads it, and
// `docker load` drops the registry digest); else the pinned tag@digest, which
// docker pulls and checks. The unpinned minio/minio:latest that installs used
// before the move to quay.io is no longer accepted.
func pickImage(override, pinned, tag string, present func(string) bool) string {
	if o := strings.TrimSpace(override); o != "" {
		return o
	}
	if present(pinned) {
		return pinned
	}
	if present(tag) {
		return tag
	}
	return pinned
}

func imagePresent(ref string) bool {
	return exec.Command("sudo", "docker", "image", "inspect", ref).Run() == nil
}

// minioImage is the MinIO server image to run (FOX_MINIO_IMAGE overrides,
// e.g. for a registry mirror).
func minioImage() string {
	return pickImage(brand.Getenv("MINIO_IMAGE"), MinioImage, MinioTag, imagePresent)
}

// mcImage is the MinIO client image used to create the WAL bucket
// (FOX_MC_IMAGE overrides).
func mcImage() string {
	return pickImage(brand.Getenv("MC_IMAGE"), MCImage, MCTag, imagePresent)
}
