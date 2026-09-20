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
		{"fresh install pulls the pinned image", "", have(), MinioImage},
		{"pinned image already loaded (e.g. the Windows distro)", "", have(MinioImage, legacyMinioImage), MinioImage},
		{"existing install keeps its cached image, no pull", "", have(legacyMinioImage), legacyMinioImage},
		{"an override always wins", " mirror.local/minio:1 ", have(MinioImage), "mirror.local/minio:1"},
	}
	for _, c := range cases {
		if got := pickImage(c.override, MinioImage, legacyMinioImage, c.present); got != c.want {
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
