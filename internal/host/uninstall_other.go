// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !darwin && !windows

package host

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/foxbyte/foxbyte/internal/branch"
	"github.com/foxbyte/foxbyte/internal/brand"
)

// uninstallSteps on Linux: the engine runs on this machine, so there is no VM
// to delete — the containers, the pool and the storage service are removed
// where they are.
func uninstallSteps(o UninstallOptions) []removal {
	sh := func(what, script string, data bool) removal {
		return removal{
			what:    what,
			data:    data,
			present: func() bool { return true },
			run:     func() error { return shellRun(script) },
		}
	}
	out := []removal{
		sh("the engine's containers and network",
			`sudo docker rm -f $(sudo docker ps -aq --filter label=`+branch.ManagedLabel+`) 2>/dev/null || true; `+
				`sudo docker rm -f `+branch.ObjStore+` $(sudo docker ps -a --format '{{.Names}}' | grep '^`+branch.ContainerPrefix+`') 2>/dev/null || true; `+
				`sudo docker network rm `+branch.Network+` 2>/dev/null || true`, false),
		sh("the storage service",
			`sudo systemctl disable --now `+branch.Pool+`-storage.service 2>/dev/null || true; `+
				`sudo rm -f /etc/systemd/system/`+branch.Pool+`-storage.service /usr/local/lib/dbengine/storage-up.sh; `+
				`sudo systemctl daemon-reload 2>/dev/null || true`, false),
	}
	if !o.KeepData {
		out = append(out,
			sh("the databases and their storage pool",
				`sudo zpool destroy -f `+branch.Pool+` 2>/dev/null || true; `+
					`sudo rm -f /var/lib/`+branch.Pool+`-zpool.img /var/lib/`+branch.Pool+`-btrfs.img`, true),
			sh("archived WAL and base backups",
				`sudo docker volume rm -f `+branch.ObjStoreVolume+` 2>/dev/null || true`, true),
		)
	}
	return append(out, hostSteps(o)...)
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
