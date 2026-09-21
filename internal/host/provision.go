// SPDX-License-Identifier: AGPL-3.0-or-later

package host

// provisionScript installs Docker and ZFS in the macOS VM. It is safe to run
// again, and it must be: `fox setup` re-runs it whenever provisionedCheck
// fails, which is exactly the state an install cut short leaves behind.
//
// Two kinds of wreckage, both found by killing a real install halfway:
//   - dpkg left "interrupted": every apt-get refuses to start until
//     `dpkg --configure -a` has run, so that goes first;
//   - a package killed while unpacking is "half-installed, reinstall
//     required": apt calls it already the newest version and will not touch
//     it, though its files — docker.service among them — are missing. Anything
//     dpkg marks that way is reinstalled.
//
// The environment is passed with `env`, not `sudo -E`: the sudo in current
// Ubuntu refuses -E. --no-install-recommends is not used: the installs this
// replaces never had it, and changing what a VM gets is a separate decision.
const provisionScript = "set -e; A='env DEBIAN_FRONTEND=noninteractive'; " +
	"sudo $A dpkg --configure -a; " +
	"sudo $A apt-get update -y; " +
	"broken=$(dpkg-query -W -f='${Status} ${Package}\\n' 2>/dev/null | awk '/reinstreq|half-installed|half-configured/ {print $NF}'); " +
	"[ -z \"$broken\" ] || sudo $A apt-get install -y --reinstall $broken; " +
	"sudo $A apt-get install -y zfsutils-linux docker.io; " +
	"sudo systemctl enable --now docker"

// provisionedCheck succeeds when the VM has the ZFS tools and a running Docker.
const provisionedCheck = "command -v zpool >/dev/null && command -v docker >/dev/null && " +
	"sudo systemctl is-active --quiet docker"
