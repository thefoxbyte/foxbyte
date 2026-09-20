// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !darwin && !windows

package host

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/foxbyte/foxbyte/internal/branch"
	"github.com/foxbyte/foxbyte/internal/brand"
)

// uninstallSteps on Linux: the engine runs on this machine, so there is no VM
// to delete — the containers, the pool and the storage service are removed
// where they are.
func uninstallSteps(o UninstallOptions) []removal {
	// present is a check, not a guess: "already gone" has to be true, or a
	// second run reports work it did not do.
	sh := func(what, present, script string, data bool) removal {
		return removal{
			what:    what,
			data:    data,
			present: func() bool { return shellSucceeds(present) },
			run:     func() error { return shellRun(script) },
		}
	}
	out := []removal{
		stopStep(stopStack),
		sh("the engine's containers and network",
			`[ -n "$(sudo docker ps -aq --filter label=`+branch.ManagedLabel+`)$(sudo docker ps -a --format '{{.Names}}' | grep -e '^`+branch.ContainerPrefix+`' -e '^`+branch.ObjStore+`$')" ] || `+
				`sudo docker network inspect `+branch.Network+` >/dev/null 2>&1`,
			// -v takes each container's anonymous volumes with it, which would
			// otherwise pile up unreferenced.
			`sudo docker rm -f -v $(sudo docker ps -aq --filter label=`+branch.ManagedLabel+`) 2>/dev/null || true; `+
				`sudo docker rm -f -v `+branch.ObjStore+` $(sudo docker ps -a --format '{{.Names}}' | grep '^`+branch.ContainerPrefix+`') 2>/dev/null || true; `+
				`sudo docker network rm `+branch.Network+` 2>/dev/null || true`, false),
		sh("the storage service",
			`test -f /etc/systemd/system/`+branch.Pool+`-storage.service`,
			`sudo systemctl disable --now `+branch.Pool+`-storage.service 2>/dev/null || true; `+
				`sudo rm -f /etc/systemd/system/`+branch.Pool+`-storage.service /usr/local/lib/dbengine/storage-up.sh; `+
				`sudo systemctl daemon-reload 2>/dev/null || true`, false),
	}
	if !o.KeepData {
		out = append(out,
			sh("the databases and their storage pool",
				`sudo zpool list -H -o name `+branch.Pool+` >/dev/null 2>&1 || test -f /var/lib/`+branch.Pool+`-zpool.img`,
				`sudo zpool destroy -f `+branch.Pool+` 2>/dev/null || true; `+
					`sudo rm -f /var/lib/`+branch.Pool+`-zpool.img /var/lib/`+branch.Pool+`-btrfs.img`, true),
			sh("archived WAL and base backups",
				`[ -n "$(sudo docker volume ls -q --filter name=^`+branch.ObjStoreVolume+`$)" ]`,
				`sudo docker volume rm -f `+branch.ObjStoreVolume+` 2>/dev/null || true`, true),
		)
	}
	return append(out, hostSteps(o)...)
}

// stopStack stops the background servers and every container, by running this
// same binary's `stop` -- the one place that knows what they are.
func stopStack() error {
	if self, err := os.Executable(); err == nil {
		_ = exec.Command(self, "stop").Run() // a stack already down is fine
	}
	// `stop` finds the servers through the pidfiles in the state directory. If
	// those are gone -- an interrupted removal, a state directory deleted by
	// hand -- the servers are still running, still holding the ports and an
	// account database that no longer exists. Take them by their command line.
	for _, name := range binaryNames() {
		for _, svc := range []string{"controlplane", "gateway", "serve"} {
			_ = exec.Command("pkill", "-f", "^[^ ]*"+name+" "+svc).Run()
		}
	}
	return nil
}

// shellSucceeds reports whether a check command exits zero.
func shellSucceeds(script string) bool {
	return exec.Command("sh", "-c", script).Run() == nil
}

func shellRun(script string) error {
	if out, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// stateDirGlob is unused on Linux (hostSteps removes the state directory
// directly), but keeps the platform files symmetrical.
var _ = brand.StateDirName
