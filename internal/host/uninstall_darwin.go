// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/foxbyte/foxbyte/internal/branch"
	"github.com/foxbyte/foxbyte/internal/brand"
)

// uninstallSteps on macOS: the engine lives in a Lima VM.
//
// A VM we created is deleted outright, which takes everything inside with it.
// A VM we merely adopted -- a plain "default" VM, or one named for a retired
// product -- is left alone and emptied instead: it may hold things that are
// nothing to do with us.
func uninstallSteps(o UninstallOptions) []removal {
	var out []removal
	name := instance()
	ours := name == brand.VMInstance

	switch {
	case !instanceExists(name):
		// Nothing in a VM to remove.
	case ours && !o.KeepData:
		out = append(out, removal{
			what:    fmt.Sprintf("the engine VM %q, and everything in it", name),
			data:    true,
			present: func() bool { return instanceExists(name) },
			run:     func() error { return limaDelete(name) },
		})
	default:
		out = append(out, guestSteps(name, o)...)
	}
	return append(out, hostSteps(o)...)
}

// guestSteps empties a VM we did not create (or keeps its data, with
// --keep-data), leaving the VM itself in place.
func guestSteps(name string, o UninstallOptions) []removal {
	guest := func(what, script string, data bool) removal {
		return removal{
			what: what,
			data: data,
			present: func() bool {
				return instanceExists(name)
			},
			run: func() error { return guestRun(name, script) },
		}
	}
	steps := []removal{
		guest("the engine's containers and network in VM "+name,
			`sudo docker rm -f $(sudo docker ps -aq --filter label=`+branch.ManagedLabel+`) 2>/dev/null || true; `+
				`sudo docker rm -f `+branch.ObjStore+` $(sudo docker ps -a --format '{{.Names}}' | grep '^`+branch.ContainerPrefix+`' ) 2>/dev/null || true; `+
				`sudo docker network rm `+branch.Network+` 2>/dev/null || true`, false),
	}
	if !o.KeepData {
		steps = append(steps,
			guest("the databases and their storage pool in VM "+name,
				`sudo zpool destroy -f `+branch.Pool+` 2>/dev/null || true; `+
					`sudo rm -f /var/lib/`+branch.Pool+`-zpool.img /var/lib/`+branch.Pool+`-btrfs.img`, true),
			guest("archived WAL and base backups in VM "+name,
				`sudo docker volume rm -f `+branch.ObjStoreVolume+` 2>/dev/null || true`, true),
			guest("the engine's state in VM "+name,
				`rm -rf ~/`+brand.StateDirName+stateDirGlob(), true),
		)
	}
	steps = append(steps, guest("the engine binary in VM "+name,
		`sudo rm -f `+strings.Join(guestBinaryPaths(), " "), false))
	return steps
}

// stateDirGlob also removes state directories left by retired names.
func stateDirGlob() string {
	var b strings.Builder
	for _, p := range brand.Previous {
		if p.StateDir != "" {
			fmt.Fprintf(&b, " ~/%s", p.StateDir) // legacy: state from a retired name
		}
	}
	return b.String()
}

func guestBinaryPaths() []string {
	var out []string
	for _, n := range binaryNames() {
		out = append(out, "/usr/local/bin/"+n)
	}
	return out
}

// guestRun runs a shell line inside the VM.
func guestRun(name, script string) error {
	cmd := exec.Command("limactl", "shell", name, "--", "sh", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func limaDelete(name string) error {
	_ = exec.Command("limactl", "stop", "-f", name).Run()
	if out, err := exec.Command("limactl", "delete", "--force", name).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
