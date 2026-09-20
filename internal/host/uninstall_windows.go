// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/foxbyte/foxbyte/internal/brand"
)

// uninstallSteps on Windows: the engine lives in a WSL distro.
//
// Unregistering the distro removes the databases, the object store and the
// engine in one move. A distro we did not create (an override) is left alone
// and emptied instead. Distros from retired product names are removed too: they
// are ours, and each one holds a full copy of a stack.
func uninstallSteps(o UninstallOptions) []removal {
	var out []removal
	for _, name := range distroNames() {
		d := name
		if !distroExists(d) {
			continue
		}
		if o.KeepData {
			out = append(out, removal{
				what:    fmt.Sprintf("the engine inside the WSL distro %q (its data is kept)", d),
				present: func() bool { return distroExists(d) },
				run: func() error {
					return wslRun(d, "sudo rm -f "+strings.Join(guestBinaryPaths(), " "))
				},
			})
			continue
		}
		out = append(out, removal{
			what:    fmt.Sprintf("the WSL distro %q, and everything in it", d),
			data:    true,
			present: func() bool { return distroExists(d) },
			run:     func() error { return unregisterDistro(d) },
		})
	}
	for _, dir := range appDataDirs() {
		p := dir
		out = append(out, removal{
			what:    "the installed files in " + p,
			present: func() bool { _, err := os.Stat(p); return err == nil },
			run:     func() error { return os.RemoveAll(p) },
		})
	}
	return append(out, hostSteps(o)...)
}

// distroNames is the distro this version uses, plus those of retired names.
func distroNames() []string {
	names := []string{resolveWSLDistro(brand.Getenv("WSL_DISTRO"))}
	for _, p := range brand.Previous {
		names = append(names, p.Slug) // legacy: a distro from a retired name
	}
	return names
}

// appDataDirs are the per-user install directories, for this name and retired
// ones.
func appDataDirs() []string {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		return nil
	}
	var out []string
	for _, slug := range append([]string{brand.Slug}, previousSlugs()...) {
		out = append(out,
			filepath.Join(local, slug),
			filepath.Join(local, "Programs", slug),
		)
	}
	return out
}

func previousSlugs() []string {
	var out []string
	for _, p := range brand.Previous {
		out = append(out, p.Slug) // legacy: installs from a retired name
	}
	return out
}

func guestBinaryPaths() []string {
	var out []string
	for _, n := range binaryNames() {
		out = append(out, "/usr/local/bin/"+n)
	}
	return out
}

func unregisterDistro(name string) error {
	if out, err := wsl("--unregister", name).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func wslRun(distro, script string) error {
	cmd := exec.Command("wsl", "-d", distro, "--", "sh", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
