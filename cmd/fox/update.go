// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/foxbyte/foxbyte/internal/daemon"
	"github.com/foxbyte/foxbyte/internal/host"
	"github.com/foxbyte/foxbyte/internal/update"
)

const updateUsage = `usage: fox update [--check] [--yes] [--version vX.Y.Z]

Installs the newest FoxByte release: the new engine, restarted servers, and
Blackbox upgrades on running branches. Databases, branches, backups and
settings are not touched.

  --check            Only report whether a newer release is available
  --yes, -y          Update without asking for confirmation
  --version vX.Y.Z   Install this release instead of the newest one
`

func updateCmd(args []string) {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Print(updateUsage)
			return
		}
	}
	opts, err := parseUpdateArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprint(os.Stderr, updateUsage)
		os.Exit(2)
	}
	must(host.Update(opts))
}

func parseUpdateArgs(args []string) (host.UpdateOptions, error) {
	var o host.UpdateOptions
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--check":
			o.Check = true
		case a == "--yes" || a == "-y":
			o.Yes = true
		case a == "--version":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return o, fmt.Errorf("--version needs a release, e.g. --version v0.9.0")
			}
			o.Version = args[i+1]
			i++
		case strings.HasPrefix(a, "--version="):
			o.Version = strings.TrimPrefix(a, "--version=")
		default:
			return o, fmt.Errorf("unknown argument %q", a)
		}
	}
	if o.Version != "" {
		if _, err := update.ParseVersion(o.Version); err != nil {
			return o, err
		}
	}
	return o, nil
}

// updateGuestCmd runs the engine-side steps of `fox update` where the engine
// lives. The host runs it with the NEW engine binary, so the installed engine
// doesn't need to know these commands. Not meant to be typed.
func updateGuestCmd(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: fox _update-guest stop-services | install-engine --src <file> --dest <path> [--prev <path>]")
		os.Exit(2)
	}
	switch args[0] {
	case "stop-services":
		for name := range services {
			daemon.Stop(name)
		}
		fmt.Println("  servers stopped")
	case "install-engine":
		src, dest, prev := optValue(args[1:], "--src"), optValue(args[1:], "--dest"), optValue(args[1:], "--prev")
		if src == "" || dest == "" {
			fmt.Println("usage: fox _update-guest install-engine --src <file> --dest <path> [--prev <path>]")
			os.Exit(2)
		}
		if prev == "" {
			prev = filepath.Join(foxbyteDir(), "updates", "prev", "fox")
		}
		must(update.InstallBinary(src, dest, prev))
		fmt.Printf("  installed %s (previous engine kept at %s)\n", dest, prev)
	default:
		fmt.Printf("unknown _update-guest step: %s\n", args[0])
		os.Exit(2)
	}
}
