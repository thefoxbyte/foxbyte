// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"strings"
	"testing"
)

// The provisioning script is re-run to repair a VM whose first run was cut
// short, so it must first recover dpkg from an interrupted run, and must keep
// installing what the engine needs.
func TestProvisionScriptRepairsAnInterruptedRun(t *testing.T) {
	configure := strings.Index(provisionScript, "dpkg --configure -a")
	update := strings.Index(provisionScript, "apt-get update")
	if configure < 0 || update < 0 || configure > update {
		t.Errorf("dpkg --configure -a must run before apt-get, or apt refuses to start after an interrupted run: %q", provisionScript)
	}
	if strings.Contains(provisionScript, "sudo -E") {
		t.Error("current Ubuntu's sudo refuses -E; pass the environment with env")
	}
	// A package killed while unpacking is "reinstreq": apt will not repair it
	// unless asked to reinstall it.
	if !strings.Contains(provisionScript, "reinstreq") || !strings.Contains(provisionScript, "--reinstall") {
		t.Errorf("packages dpkg marks for reinstall must be reinstalled: %q", provisionScript)
	}
	for _, want := range []string{"set -e", "zfsutils-linux", "docker.io", "systemctl enable --now docker"} {
		if !strings.Contains(provisionScript, want) {
			t.Errorf("the provisioning script lost %q", want)
		}
	}
}

// "Provisioned" means usable: Docker installed is not enough if it is not
// running, which is what a run cut short between install and enable leaves.
func TestProvisionedCheckWantsARunningDocker(t *testing.T) {
	for _, want := range []string{"zpool", "docker", "is-active"} {
		if !strings.Contains(provisionedCheck, want) {
			t.Errorf("provisionedCheck should look for %q: %q", want, provisionedCheck)
		}
	}
}
