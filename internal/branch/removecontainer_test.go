// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every container is removed with its anonymous volumes. A `docker rm` without
// -v left one behind each time, and a backup verify left a whole restored copy
// of main: removeContainer is the one way, and nothing here goes around it.
func TestContainersAreRemovedWithTheirVolumes(t *testing.T) {
	bare := regexp.MustCompile(`"docker",\s*"rm"`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if bare.MatchString(line) && !strings.Contains(line, `"-v"`) {
				t.Errorf("%s:%d removes a container without its volumes: %s (use removeContainer)", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
