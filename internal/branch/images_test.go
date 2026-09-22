// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"os"
	"strings"
	"testing"
)

func TestPickImage(t *testing.T) {
	have := func(refs ...string) func(string) bool {
		return func(r string) bool {
			for _, x := range refs {
				if x == r {
					return true
				}
			}
			return false
		}
	}
	cases := []struct {
		name     string
		override string
		present  func(string) bool
		want     string
	}{
		{"fresh install pulls the pinned tag@digest", "", have(), MinioImage},
		{"pulled by digest before", "", have(MinioImage), MinioImage},
		{"the tag preloaded without a digest (the Windows distro)", "", have(MinioTag), MinioTag},
		{"the old unpinned image is not used", "", have("minio/minio:latest"), MinioImage},
		{"an override always wins", " mirror.local/minio:1 ", have(MinioImage), "mirror.local/minio:1"},
	}
	for _, c := range cases {
		if got := pickImage(c.override, MinioImage, MinioTag, c.present); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestMinioImagesArePinnedOffDockerHub(t *testing.T) {
	for _, ref := range []string{MinioImage, MCImage} {
		if !strings.HasPrefix(ref, "quay.io/minio/") {
			t.Errorf("%s: MinIO images are no longer on Docker Hub; use quay.io/minio", ref)
		}
		if strings.HasSuffix(ref, ":latest") || !strings.Contains(ref, ":RELEASE.") {
			t.Errorf("%s: pin a tested RELEASE tag, not latest", ref)
		}
		if !strings.Contains(ref, "@sha256:") {
			t.Errorf("%s: pin the digest too, so a moved tag cannot change what runs", ref)
		}
	}
}

// The Windows distro preloads the images the engine runs; if the names drift,
// `fox up` on Windows would try to pull at first start.
func TestDistroPreloadsTheEngineImages(t *testing.T) {
	b, err := os.ReadFile("../../deploy/wsl-distro/build.sh")
	if err != nil {
		t.Skip("deploy/wsl-distro/build.sh not found")
	}
	s := string(b)
	for _, ref := range []string{MinioImage, MCImage} {
		if !strings.Contains(s, ref) {
			t.Errorf("deploy/wsl-distro/build.sh does not preload %s", ref)
		}
	}
	for _, old := range []string{"docker pull -q minio/minio", "docker pull -q minio/mc"} {
		if strings.Contains(s, old) {
			t.Errorf("deploy/wsl-distro/build.sh still pulls from Docker Hub: %q", old)
		}
	}
}

// The PostgreSQL major is named in four files that cannot import Go: the
// Dockerfile's default, the release workflow's image matrix, and the Windows
// distro's preload. When they drift, nothing fails loudly — a fresh install
// pulls or builds an image the preload was meant to save, or an install on an
// older major finds no image published for it. So they are held to
// PGMajor and SupportedPGMajors here.
func TestPostgresMajorIsInStepEverywhere(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return string(b)
	}

	docker := read("../../docker/postgres/Dockerfile")
	if !strings.Contains(docker, "ARG PG_MAJOR="+PGMajor+"\n") {
		t.Errorf("docker/postgres/Dockerfile should default PG_MAJOR to %s (PGMajor)", PGMajor)
	}
	if !strings.Contains(docker, "FROM postgres:${PG_MAJOR}-") {
		t.Error("docker/postgres/Dockerfile should build FROM postgres:${PG_MAJOR}-…, so one file serves every major")
	}

	distro := read("../../deploy/wsl-distro/build.sh")
	if !strings.Contains(distro, "local pg_major="+PGMajor+"\n") {
		t.Errorf("deploy/wsl-distro/build.sh should preload the PostgreSQL %s image a fresh install runs", PGMajor)
	}
	if strings.Count(distro, "postgres-walg:$pg_major") < 2 {
		t.Error("deploy/wsl-distro/build.sh should build and save the image under postgres-walg:$pg_major")
	}

	workflow := read("../../.github/workflows/release.yml")
	var matrix []string
	for _, m := range SupportedPGMajors {
		matrix = append(matrix, `"`+m+`"`)
	}
	if want := "pg: [" + strings.Join(matrix, ", ") + "]"; !strings.Contains(workflow, want) {
		t.Errorf(".github/workflows/release.yml should publish an image for every supported major: %s", want)
	}
	if !strings.Contains(workflow, "PG_MAJOR=${{ matrix.pg }}") {
		t.Error(".github/workflows/release.yml should pass the matrix major to the build as PG_MAJOR")
	}

	// The base image is pinned by digest per major, the same everywhere.
	if !strings.Contains(docker, "ARG PG_DIGEST="+PostgresBaseDigests[PGMajor]+"\n") ||
		!strings.Contains(docker, "FROM postgres:${PG_MAJOR}-bookworm@${PG_DIGEST}") {
		t.Errorf("docker/postgres/Dockerfile should build FROM the digest-pinned base, defaulting to %s", PostgresBaseDigests[PGMajor])
	}
	if !strings.Contains(distro, "local pg_digest="+PostgresBaseDigests[PGMajor]+"\n") {
		t.Error("deploy/wsl-distro/build.sh should build on the same pinned base")
	}
	for _, m := range SupportedPGMajors {
		d := PostgresBaseDigests[m]
		if d == "" {
			t.Errorf("no base digest pinned for PostgreSQL %s", m)
			continue
		}
		if want := "- pg: \"" + m + "\"\n            base: " + d; !strings.Contains(workflow, want) {
			t.Errorf(".github/workflows/release.yml should build %s on %s", m, d)
		}
	}
	if !strings.Contains(workflow, "PG_DIGEST=${{ matrix.base }}") {
		t.Error(".github/workflows/release.yml should pass the matrix base digest as PG_DIGEST")
	}
	// wal-g is checked against its published SHA-256 before it is unpacked.
	if !strings.Contains(docker, "sha256sum -c -") || !strings.Contains(docker, "WALG_SHA256_AMD64=") || !strings.Contains(docker, "WALG_SHA256_ARM64=") {
		t.Error("docker/postgres/Dockerfile should verify the wal-g download for both architectures")
	}
}
