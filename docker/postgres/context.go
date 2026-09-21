// SPDX-License-Identifier: AGPL-3.0-or-later

// Package postgres carries the engine image's build context inside the fox
// binary, so an image that cannot be pulled can always be built instead.
//
// The published image is an optimisation, not a dependency: a registry that is
// unreachable, a package that is private, or a release whose image job has not
// finished all used to end a first install with `unauthorized` and a request to
// set a variable the Mac cannot pass into its VM. The context is two small files,
// read from this directory at build time, so it cannot drift from the release
// it ships in.
package postgres

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed Dockerfile restore-entrypoint.sh
var files embed.FS

// WriteContext writes the build context into dir, which must exist.
func WriteContext(dir string) error {
	return fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(p, ".sh") {
			mode = 0o755
		}
		return os.WriteFile(filepath.Join(dir, p), b, mode)
	})
}
