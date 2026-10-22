// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"os/exec"
	"strconv"
	"strings"
)

// The object store's images come from FoxByte's own registry.
//
// MinIO's images have moved twice. They left Docker Hub in 2026, and then quay.io
// stopped serving them anonymously: every tag there, `latest` included, answers
// 401 to a pull without credentials. The engine runs MinIO for the WAL archive and
// base backups, so the day that changed, a fresh install on macOS or Linux could
// no longer start — while existing installs carried on from their local cache, and
// Windows carried on because its distro image has always shipped the images inside
// it (deploy/wsl-distro/build.sh).
//
// So they are mirrored to ghcr.io/thefoxbyte, beside the engine image, by
// .github/workflows/mirror-images.yml — which takes them out of a published
// release's distro asset rather than from a registry that will not serve us. The
// versions are the ones FoxByte is tested with; the digests are what that workflow
// pushed, and it can be re-run with them to check that a tag still resolves to the
// same bytes (audit v2 G23).
const (
	MinioTag = "ghcr.io/thefoxbyte/minio:RELEASE.2025-09-07T16-13-09Z"
	MCTag    = "ghcr.io/thefoxbyte/mc:RELEASE.2025-08-13T08-35-41Z"

	// MinioDigest and MCDigest pin the exact bytes: the digest of the index, so one
	// pin covers both architectures and docker resolves the right one. Empty between
	// mirroring a new version and pinning what the mirror printed;
	// .github/workflows/release.yml refuses to publish while they are — and refuses
	// a pin that is not a multi-architecture index, because a mirror made only from
	// the amd64 distro image dies on Apple Silicon with "exec format error".
	MinioDigest = "sha256:3b8964634e9d00dc432b966244c1220660de2fab3643226313467a3ad62ad756"
	MCDigest    = "sha256:2aacf2bdf60f24b6a8bd1bd859034ff56d014ecd7bf621a5d1b311772f5d6687"

	// PGMajor is the PostgreSQL major a fresh install runs.
	PGMajor = "18"
)

// MinioImage and MCImage are what the engine pulls: the tag with its digest when
// there is one, so docker checks the bytes, and the bare tag before the mirror has
// run for that version.
var (
	MinioImage = withDigest(MinioTag, MinioDigest)
	MCImage    = withDigest(MCTag, MCDigest)
)

func withDigest(tag, digest string) string {
	if digest == "" {
		return tag
	}
	return tag + "@" + digest
}

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

// PGImageRevision is the engine image this fox needs, as the number the
// Dockerfile labels it with (dev.dbengine.image-revision). An install keeps the
// image it first fetched, so an image older than this is fetched again, or
// built, when the engine starts (ensureImageRef). 2 added bb_identity, which
// application identity (F1) needs. An image without the label is revision 1.
const PGImageRevision = 2

// imageRevisionLabel is the label that carries it.
const imageRevisionLabel = "dev.dbengine.image-revision"

// imageRevision reads an image's revision from its label, without starting a
// container: 1 when it has none, as every image before the label had none.
func imageRevision(ref string) int {
	out, err := capture("docker", "image", "inspect", "-f", "{{index .Config.Labels \""+imageRevisionLabel+"\"}}", ref)
	if err != nil {
		return 1
	}
	return parseImageRevision(out)
}

// parseImageRevision is imageRevision's reading of the label, pure so it is
// tested: anything that is not a positive number is revision 1.
func parseImageRevision(label string) int {
	n, err := strconv.Atoi(strings.TrimSpace(label))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// ours reports whether an image is one this fox names, and so one it may
// replace with a newer revision. An image set with FOX_PG_IMAGE is the
// operator's, and is used as it is.
func ours(ref string) bool {
	for _, m := range SupportedPGMajors {
		if ref == PostgresImageFor(m) {
			return true
		}
	}
	return false
}

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
