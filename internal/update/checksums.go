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

// ParseChecksums reads "<sha256>  <name>" lines (also the "*<name>" binary form
// and CRLF line endings). A name listed twice with different hashes is an error.
func ParseChecksums(r io.Reader) (Checksums, error) {
	out := Checksums{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := sumLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("SHA256SUMS: unreadable line %q", line)
		}
		name, sum := m[2], strings.ToLower(m[1])
		if prev, ok := out[name]; ok && prev != sum {
			return nil, fmt.Errorf("SHA256SUMS: %s is listed with two different checksums", name)
		}
		out[name] = sum
	}
	return out, sc.Err()
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
