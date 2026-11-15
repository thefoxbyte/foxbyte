// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// SumsAsset is the checksum file every release publishes
// (scripts/release-checksums.sh writes it, in release.yml's job). It lists every
// file an update needs; the Windows distro image has a file of its own, which
// only install.ps1 reads.
const SumsAsset = "SHA256SUMS"

// Checksums maps a file name to its lowercase hex SHA-256.
type Checksums map[string]string

var sumLine = regexp.MustCompile(`^([0-9a-fA-F]{64})\s+\*?(\S.*?)\s*$`)

// The release's version, inside the signed SHA256SUMS (finding SUP-4). The tag
// a release is published under is not signed: anyone able to publish a release
// could put an old, signed release up under a newer tag, and it would install,
// then block the real updates as "not newer". release-checksums.sh writes the
// tag into the signed file as one more checksum line:
//
//	0000000000000000000000000000000000000000000000000000000000000000  VERSION=v2.3.0
//
// It is written as a checksum line, not a comment, because that is what every
// verifier already released reads without complaint: fox's own parser (before
// this) took it as the checksum of a file named "VERSION=v2.3.0" that nothing
// ever asks for, install.sh and install.ps1 look files up by name and so never
// see it, and `sha256sum -c --ignore-missing` skips it as a file that is not
// there. A "#" comment would have been reported by `sha256sum -c` as a
// malformed line.
const (
	versionLinePrefix = "VERSION="
	versionLineSum    = "0000000000000000000000000000000000000000000000000000000000000000"
)

// VersionLine is the line release-checksums.sh adds for tag.
func VersionLine(tag string) string { return versionLineSum + "  " + versionLinePrefix + tag }

// ParseChecksums reads "<sha256>  <name>" lines (also the "*<name>" binary form
// and CRLF line endings). A name listed twice with different hashes is an error.
// The version line is not a file and is left out; ParseSignedSums returns it.
func ParseChecksums(r io.Reader) (Checksums, error) {
	sums, _, err := ParseSignedSums(r)
	return sums, err
}

// ParseSignedSums is ParseChecksums that also returns the version the file
// names, or "" for a release made before the version line existed. Two
// different version lines are an error: the file could then be read either way.
func ParseSignedSums(r io.Reader) (Checksums, string, error) {
	out := Checksums{}
	version := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := sumLine.FindStringSubmatch(line)
		if m == nil {
			return nil, "", fmt.Errorf("SHA256SUMS: unreadable line %q", line)
		}
		name, sum := m[2], strings.ToLower(m[1])
		if sum == versionLineSum && strings.HasPrefix(name, versionLinePrefix) {
			v := strings.TrimPrefix(name, versionLinePrefix)
			if version != "" && version != v {
				return nil, "", fmt.Errorf("SHA256SUMS names two versions, %s and %s", version, v)
			}
			version = v
			continue
		}
		if prev, ok := out[name]; ok && prev != sum {
			return nil, "", fmt.Errorf("SHA256SUMS: %s is listed with two different checksums", name)
		}
		out[name] = sum
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	return out, version, nil
}

// HashFile returns a file's SHA-256 as lowercase hex.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Verify checks path against the checksum listed for name.
func (c Checksums) Verify(name, path string) error {
	want, ok := c[name]
	if !ok {
		return fmt.Errorf("%s is not listed in SHA256SUMS", name)
	}
	got, err := HashFile(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s: checksum mismatch (SHA256SUMS has %.12s…, the file is %.12s…)", name, want, got)
	}
	return nil
}
