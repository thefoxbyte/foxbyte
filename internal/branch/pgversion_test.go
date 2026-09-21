// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"slices"
	"strings"
	"testing"
)

func TestParsePGVersion(t *testing.T) {
	for in, want := range map[string]string{
		"16\n":    "16",
		"18":      "18",
		" 9.6 \n": "9.6", // the pre-10 two-part scheme
		"":        "",
		"latest":  "",
		"16\n17":  "", // not a PG_VERSION file
	} {
		if got := parsePGVersion(in); got != want {
			t.Errorf("parsePGVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImageMajor(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/thefoxbyte/postgres-walg:16":      "16",
		"ghcr.io/thefoxbyte/postgres-walg:18":      "18",
		"ghcr.io/thefoxbyte/postgres-walg:18-v0.2": "18", // the release-pinned tag
		"mirror.local:5000/postgres-walg":          "",   // a registry port is not a tag
		"mirror.local:5000/postgres-walg:18":       "18",
		"postgres-walg:latest":                     "",
		"postgres-walg":                            "",
	} {
		if got := imageMajor(in); got != want {
			t.Errorf("imageMajor(%q) = %q, want %q", in, got, want)
		}
	}
}

// The image follows the data: an install created on an older major keeps
// running it after an update, and only a fresh install gets PGMajor.
func TestResolvePGImageFollowsTheData(t *testing.T) {
	if got, want := resolvePGImage("", ""), PostgresImageFor(PGMajor); got != want {
		t.Errorf("a fresh install runs %s, want %s", got, want)
	}
	if got, want := resolvePGImage("", "16"), PostgresImageFor("16"); got != want {
		t.Errorf("an install on 16 runs %s, want %s", got, want)
	}
	if got := resolvePGImage(" mirror/pg:18 ", "16"); got != "mirror/pg:18" {
		t.Errorf("an explicit override must win, got %s", got)
	}
}

func TestCheckDataMajor(t *testing.T) {
	img16, img18 := PostgresImageFor("16"), PostgresImageFor("18")
	for _, ok := range []struct{ data, image string }{
		{"", img18},           // no cluster yet: initdb will make one
		{"18", img18},         // the normal case
		{"16", img16},         // an older install on its own image
		{"16", "mirror/pg:x"}, // an override the check cannot see into
	} {
		if err := checkDataMajor("main", ok.data, ok.image); err != nil {
			t.Errorf("data %q on %s should start, got: %v", ok.data, ok.image, err)
		}
	}

	err := checkDataMajor("qa", "16", img18)
	if err == nil {
		t.Fatal("PostgreSQL 16 data on the 18 image must be refused before docker run")
	}
	msg := err.Error()
	for _, want := range []string{`"qa"`, "PostgreSQL 16 data", "PostgreSQL 18", img16, "PG_IMAGE"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal should mention %q so the user knows what to do; got:\n%s", want, msg)
		}
	}

	// Data from a major this fox has no image for: the way out is a dump, not an env var.
	msg = checkDataMajor("main", "15", img18).Error()
	for _, want := range []string{"PostgreSQL 15", "pg_dump", "uninstall"} {
		if !strings.Contains(msg, want) {
			t.Errorf("an unsupported major's refusal should mention %q; got:\n%s", want, msg)
		}
	}
}

func TestSupportedPGMajors(t *testing.T) {
	if !slices.Contains(SupportedPGMajors, PGMajor) {
		t.Errorf("PGMajor %s is not in SupportedPGMajors %v", PGMajor, SupportedPGMajors)
	}
	seen := map[string]bool{}
	for _, m := range SupportedPGMajors {
		if parsePGVersion(m) == "" || seen[m] {
			t.Errorf("SupportedPGMajors has a bad or repeated entry %q", m)
		}
		seen[m] = true
	}
	if !strings.HasSuffix(PostgresImageFor(PGMajor), "/postgres-walg:"+PGMajor) {
		t.Errorf("PostgresImageFor(%s) = %s", PGMajor, PostgresImageFor(PGMajor))
	}
}

// A local build of an older install's image must be that major, not whatever
// the Dockerfile defaults to.
func TestBuildImageArgsPassTheMajor(t *testing.T) {
	got := strings.Join(buildImageArgs(PostgresImageFor("16"), "/ctx"), " ")
	if !strings.Contains(got, "--build-arg PG_MAJOR=16") || !strings.HasSuffix(got, " /ctx") {
		t.Errorf("building the 16 image: %s", got)
	}
	if got := strings.Join(buildImageArgs("mirror/pg", "/ctx"), " "); strings.Contains(got, "PG_MAJOR") {
		t.Errorf("an image with no major in its tag should build with the Dockerfile default: %s", got)
	}
}

// A local build can always happen: an explicit context first, then a checkout
// of the repository, then the copy built into fox. There is no "no context".
func TestChooseImageContext(t *testing.T) {
	if dir, where := chooseImageContext("/ctx", "docker/postgres"); dir != "/ctx" || !strings.Contains(where, envImageContext) {
		t.Errorf("an explicit context wins: %q %q", dir, where)
	}
	if dir, _ := chooseImageContext("", "../docker/postgres"); dir != "../docker/postgres" {
		t.Errorf("a checkout comes next: %q", dir)
	}
	dir, where := chooseImageContext("", "")
	if dir != "" || !strings.Contains(where, "built into") {
		t.Errorf("with neither, the built-in copy is used: %q %q", dir, where)
	}
}
