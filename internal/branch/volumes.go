// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import "strings"

// UnusedAnonymousVolumes counts the anonymous Docker volumes no container uses:
// the ones `docker volume prune` (without -a) would remove. Before
// removeContainer passed -v, every branch removed, every stop and start, and
// every backup verify left one, so an install from before then carries them.
// Named volumes, the object store's among them, are not counted.
func UnusedAnonymousVolumes() (int, error) {
	out, err := capture("docker", "volume", "ls", "-q",
		"--filter", "dangling=true", "--filter", "label=com.docker.volume.anonymous")
	if err != nil {
		return 0, err
	}
	return len(strings.Fields(out)), nil
}
