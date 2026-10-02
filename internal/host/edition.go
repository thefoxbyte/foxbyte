// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// EngineAsset is the release asset holding the Linux engine binary this build
// needs: fox-linux-<arch>, or fox-enterprise-linux-<arch> for the paid edition.
//
// On macOS and Windows there are two binaries — the launcher on the host and the
// engine inside the VM — and every engine command is forwarded to the second
// one. If they were different editions the launcher would offer commands the
// engine does not have, or the reverse, and the failure would look like a bug
// rather than a mismatched install. So the launcher names the asset after
// itself.
func EngineAsset(arch string) string {
	name := brand.CLI
	if edition.Enterprise {
		name += "-enterprise"
	}
	return name + "-linux-" + arch
}
