// SPDX-License-Identifier: AGPL-3.0-or-later

// Package update finds newer FoxByte releases on GitHub, verifies downloads
// against the release's SHA256SUMS, and installs them: the notice `fox start`
// prints and the `fox update` command. Everything here is platform-independent;
// running commands inside the Lima VM or WSL distro lives in internal/host.
package update

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a release version: major.minor.patch with an optional pre-release
// suffix (0.9.0-rc1, 0.1.0-dev).
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

// ParseVersion reads "v0.8.1", "0.8.1", "v0.8" (patch 0) or "0.1.0-dev".
func ParseVersion(s string) (Version, error) {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(strings.TrimPrefix(t, "v"), "V")
	var v Version
	if i := strings.IndexByte(t, '-'); i >= 0 {
		v.Pre = t[i+1:]
		t = t[:i]
		if v.Pre == "" {
			return Version{}, fmt.Errorf("invalid version %q", s)
		}
	}
	parts := strings.Split(t, ".")
	if t == "" || len(parts) > 3 {
		return Version{}, fmt.Errorf("invalid version %q", s)
	}
	nums := []*int{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return Version{}, fmt.Errorf("invalid version %q", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, fmt.Errorf("invalid version %q", s)
		}
		*nums[i] = n
	}
	return v, nil
}

// Compare returns -1, 0 or 1. A pre-release sorts before its release.
func (v Version) Compare(o Version) int {
	for _, d := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	case v.Pre < o.Pre:
		return -1
	}
	return 1
}

// IsDev reports a development build (`make build` stamps 0.1.0-dev).
func (v Version) IsDev() bool {
	return v.Pre == "dev" || strings.HasSuffix(v.Pre, "-dev") || strings.HasSuffix(v.Pre, ".dev")
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}
