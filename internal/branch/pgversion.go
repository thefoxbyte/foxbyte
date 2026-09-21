// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// A data directory belongs to one PostgreSQL major: initdb writes it into
// PG_VERSION, and a server of any other major refuses to start on it ("database
// files are incompatible with server"). Inside a container that message is lost
// in a log nobody reads, and the branch simply never comes up.
//
// So the image follows the data rather than the binary. An install created under
// PostgreSQL 16 keeps running 16 after `fox update` brings a binary that ships
// 18 — `fox update` promises to leave data alone, and moving a cluster between
// majors is a migration, not an update. Only a fresh install starts on PGMajor.

// parsePGVersion reads the contents of a PG_VERSION file: the major, alone on
// its line ("16", or "9.6" for the old two-part scheme).
func parsePGVersion(contents string) string {
	v := strings.TrimSpace(contents)
	if !pgMajorRe.MatchString(v) {
		return ""
	}
	return v
}

var pgMajorRe = regexp.MustCompile(`^\d+(\.\d+)?$`)

// dataMajor is the major a branch's data directory was created with, or "" when
// there is no cluster there yet (a first start, which initdb will create).
func dataMajor(branch string) string {
	out, err := capture("cat", filepath.Join(mountpoint(branch), "pgdata", "PG_VERSION"))
	if err != nil {
		return ""
	}
	return parsePGVersion(out)
}

// resolvePGImage picks the engine image: an explicit override, else the image
// for the major this install's data was created with, else the major a fresh
// install gets. Pure, so the order is tested without a pool.
func resolvePGImage(override, installMajor string) string {
	if o := strings.TrimSpace(override); o != "" {
		return o
	}
	if installMajor != "" {
		return PostgresImageFor(installMajor)
	}
	return PostgresImageFor(PGMajor)
}

// pgImage is the engine image to run against this install (FOX_PG_IMAGE
// overrides, e.g. for a registry mirror). Every branch is a clone of main and
// the standby a copy of it, so main's data decides for all of them.
func pgImage() string {
	return resolvePGImage(brand.Getenv("PG_IMAGE"), dataMajor("main"))
}

// imageMajor reads the PostgreSQL major from an engine image's tag
// ("…/postgres-walg:16" -> "16"); "" when the tag does not start with one, as
// with an override the check cannot see into.
func imageMajor(ref string) string {
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i:], "/") { // a registry port, not a tag
		return ""
	}
	tag := ref[i+1:]
	if j := strings.IndexAny(tag, "-_"); j >= 0 {
		tag = tag[:j]
	}
	return parsePGVersion(tag)
}

// checkDataMajor refuses to start image on data created by another major, and
// says what to do instead of leaving Postgres to fail inside the container.
func checkDataMajor(branch, data, image string) error {
	img := imageMajor(image)
	if data == "" || img == "" || data == img {
		return nil
	}
	return fmt.Errorf("branch %q holds PostgreSQL %s data, but the image it was about to start (%s) is PostgreSQL %s.\n"+
		"Postgres cannot run one major's data directory on another; it would refuse with "+
		"\"database files are incompatible with server\".\n%s",
		branch, data, image, img, majorWayOut(data))
}

// majorWayOut is the advice for data this fox has no image for, or data an
// override points at the wrong major for.
func majorWayOut(data string) string {
	if !slices.Contains(SupportedPGMajors, data) {
		return fmt.Sprintf("This %s runs PostgreSQL %s. To keep this data, export it with a %s built for "+
			"PostgreSQL %s (pg_dump), then import it into a fresh install; or remove the install with `%s uninstall`.",
			brand.CLI, strings.Join(SupportedPGMajors, " and "), brand.CLI, data, brand.CLI)
	}
	return fmt.Sprintf("Run it on its own major instead: unset %s, or set it to %s.",
		brand.EnvName("PG_IMAGE"), PostgresImageFor(data))
}
