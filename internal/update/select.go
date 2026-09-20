// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
)

// Target is the platform being updated: the host OS and CPU, and the CPU of the
// Linux VM or distro the engine runs in (macOS; Windows is always amd64).
type Target struct {
	GOOS, HostArch, GuestArch string
}

// ImageContextAsset is the Postgres image build context Windows installs ship.
const ImageContextAsset = "foxbyte-docker-context.tar.gz"

// EngineAsset is the Linux engine binary: it runs in the VM (macOS), the WSL
// distro (Windows, always x86_64), or directly on a Linux host.
func EngineAsset(t Target) string {
	switch t.GOOS {
	case "windows":
		return "fox-linux-amd64"
	case "darwin":
		if t.GuestArch != "" {
			return "fox-linux-" + t.GuestArch
		}
	}
	return "fox-linux-" + t.HostArch
}

// HostAsset is the `fox` binary for the computer itself on macOS and Windows,
// or "" on Linux, where the engine binary is the host binary.
func HostAsset(t Target) string {
	switch t.GOOS {
	case "darwin":
		return "fox-darwin-" + t.HostArch
	case "windows":
		return "fox-windows-amd64.exe"
	}
	return ""
}

// RequiredAssets lists the release files an update of this platform needs. A
// release missing any of them (for example while it is still being published)
// is never offered.
func RequiredAssets(t Target) []string {
	var out []string
	if h := HostAsset(t); h != "" {
		out = append(out, h)
	}
	out = append(out, EngineAsset(t))
	if t.GOOS == "windows" {
		out = append(out, ImageContextAsset)
	}
	return out
}

// missingAssets returns the required files (and SHA256SUMS) a release lacks.
func missingAssets(r Release, required []string) []string {
	var missing []string
	for _, name := range append([]string{SumsAsset}, required...) {
		if _, ok := r.Asset(name); !ok {
			missing = append(missing, name)
		}
	}
	return missing
}

// Candidates returns the releases an update may install, newest first: newer
// than current, not a draft or prerelease, and with every file the target
// needs. A pinned tag ("v0.9.0") selects just that release; it may be a
// prerelease but must still be newer and complete.
func Candidates(rels []Release, current Version, t Target, pin string) ([]Release, error) {
	required := RequiredAssets(t)
	if pin != "" {
		want, err := ParseVersion(pin)
		if err != nil {
			return nil, err
		}
		for _, r := range rels {
			v, err := ParseVersion(r.Tag)
			if err != nil || v.Compare(want) != 0 || r.Draft {
				continue
			}
			if v.Compare(current) <= 0 {
				return nil, fmt.Errorf("%s is not newer than the installed %s — to go back to an older version, reinstall it with the installer (FOX_VERSION=%s)", r.Tag, current, r.Tag)
			}
			if m := missingAssets(r, required); len(m) > 0 {
				return nil, fmt.Errorf("release %s is missing %s", r.Tag, strings.Join(m, ", "))
			}
			return []Release{r}, nil
		}
		return nil, fmt.Errorf("no published release %s", pin)
	}

	type cand struct {
		r Release
		v Version
	}
	var cs []cand
	for _, r := range rels {
		if r.Draft || r.Prerelease {
			continue
		}
		v, err := ParseVersion(r.Tag)
		if err != nil || v.Compare(current) <= 0 {
			continue
		}
		if len(missingAssets(r, required)) > 0 {
			continue
		}
		cs = append(cs, cand{r, v})
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].v.Compare(cs[j].v) > 0 })
	out := make([]Release, len(cs))
	for i, c := range cs {
		out[i] = c.r
	}
	return out, nil
}

// Release finds a release to install from, with its checksums — what `fox setup`
// needs, where "newer than what is installed" doesn't apply: setup installs the
// engine of a chosen release, whatever this machine currently runs.
//
// tag is a release tag, or "" / "latest" for the newest published release that
// has every file this target needs. The returned Offer carries the release's
// SHA256SUMS, so Download verifies what it fetches.
func (c *Client) Release(ctx context.Context, tag string, t Target) (*Offer, error) {
	rels, err := c.ListReleases(ctx)
	if err != nil {
		return nil, err
	}
	required := RequiredAssets(t)
	pinned := tag != "" && !strings.EqualFold(tag, "latest")

	var usable []Release
	for _, r := range rels {
		if r.Draft {
			continue
		}
		if pinned {
			v, err := ParseVersion(r.Tag)
			want, werr := ParseVersion(tag)
			if err != nil || werr != nil || v.Compare(want) != 0 {
				continue
			}
		} else if r.Prerelease {
			continue // only promoted releases are installed by default
		}
		if m := missingAssets(r, required); len(m) > 0 {
			if pinned {
				return nil, fmt.Errorf("release %s is missing %s", r.Tag, strings.Join(m, ", "))
			}
			continue
		}
		usable = append(usable, r)
		if pinned {
			break
		}
	}
	if len(usable) == 0 {
		if pinned {
			return nil, fmt.Errorf("no published release %s with the files this platform needs", tag)
		}
		return nil, fmt.Errorf("no published release has the files this platform needs")
	}
	if !pinned {
		sort.SliceStable(usable, func(i, j int) bool {
			a, _ := ParseVersion(usable[i].Tag)
			b, _ := ParseVersion(usable[j].Tag)
			return a.Compare(b) > 0
		})
	}

	r := usable[0]
	sa, _ := r.Asset(SumsAsset)
	body, err := c.fetchSmall(ctx, sa.URL, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("%s: fetching %s: %w", r.Tag, SumsAsset, err)
	}
	sums, err := ParseChecksums(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Tag, err)
	}
	for _, name := range required {
		if _, ok := sums[name]; !ok {
			return nil, fmt.Errorf("release %s: %s doesn't list %s", r.Tag, SumsAsset, name)
		}
	}
	v, _ := ParseVersion(r.Tag)
	return &Offer{Release: r, Version: v, Sums: sums, Required: required}, nil
}

// Available is the check `fox start` makes: the newest release worth telling the
// user about, or nil when this install is up to date.
//
// It uses the releases list alone — one request — and does NOT download
// SHA256SUMS. GitHub throttles repeated downloads of the same release asset
// hard (measured on 15 Sep 2026: the same SHA256SUMS took 0.5 s once, then 7–75 s
// on later requests from the same machine), so fetching it on every start made
// the notice miss its budget and stay silent. The offer it returns therefore has
// no Sums; `fox update` calls Resolve, which downloads SHA256SUMS and verifies
// every file before anything is installed.
func (c *Client) Available(ctx context.Context, current Version, t Target) (*Offer, error) {
	rels, err := c.ListReleases(ctx)
	if err != nil {
		return nil, err
	}
	cands, err := Candidates(rels, current, t, "")
	if err != nil || len(cands) == 0 {
		return nil, err
	}
	v, err := ParseVersion(cands[0].Tag)
	if err != nil {
		return nil, err
	}
	return &Offer{Release: cands[0], Version: v, Required: RequiredAssets(t)}, nil
}

// Offer is a release ready to install. Sums is filled in by Resolve (the update
// path) and empty for the start-time notice (see Available).
type Offer struct {
	Release  Release
	Version  Version
	Sums     Checksums
	Required []string
}

// Resolve finds the release to install: the newest candidate whose SHA256SUMS
// lists every file the target needs. It returns (nil, nil) when this install is
// already up to date.
func (c *Client) Resolve(ctx context.Context, current Version, t Target, pin string) (*Offer, error) {
	rels, err := c.ListReleases(ctx)
	if err != nil {
		return nil, err
	}
	cands, err := Candidates(rels, current, t, pin)
	if err != nil {
		return nil, err
	}
	required := RequiredAssets(t)
	var lastErr error
	for _, r := range cands {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		sa, _ := r.Asset(SumsAsset)
		body, err := c.fetchSmall(ctx, sa.URL, 1<<20)
		if err != nil {
			lastErr = err
			continue
		}
		sums, err := ParseChecksums(bytes.NewReader(body))
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", r.Tag, err)
			continue
		}
		var unlisted []string
		for _, name := range required {
			if _, ok := sums[name]; !ok {
				unlisted = append(unlisted, name)
			}
		}
		if len(unlisted) > 0 {
			lastErr = fmt.Errorf("release %s: SHA256SUMS doesn't list %s", r.Tag, strings.Join(unlisted, ", "))
			continue
		}
		v, _ := ParseVersion(r.Tag)
		return &Offer{Release: r, Version: v, Sums: sums, Required: required}, nil
	}
	if pin != "" && lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}
