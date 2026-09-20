// SPDX-License-Identifier: AGPL-3.0-or-later

// Pure, OS-independent helpers for the Windows/WSL2 launcher. They live in an
// untagged file (not host_windows.go) so they unit-test on any platform — the
// side-effecting wsl.exe orchestration that calls them is in host_windows.go.
package host

import (
	"bytes"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"strings"
	"unicode/utf16"
)

// defaultWSLDistro is the dedicated distro `fox setup` creates on Windows.
var defaultWSLDistro = brand.VMInstance

// guestImageContext is where setup stages the docker/postgres build context
// inside the distro. The engine's ensureImage() reads it from
// FOX_IMAGE_CONTEXT, so an installed user (who has no repo checkout, and
// therefore nothing for findImageContext to discover) can still build the image.
const guestImageContext = "/usr/local/share/dbengine/docker/postgres"

// resolveWSLDistro picks the distro name from an override (e.g. an env var),
// falling back to the dedicated default.
func resolveWSLDistro(override string) string {
	if s := strings.TrimSpace(override); s != "" {
		return s
	}
	return defaultWSLDistro
}

// guestPATH is Debian's default root PATH. The engine resolves its storage
// tools and docker with exec.LookPath, and ZFS installs under /usr/local -- but the
// environment `wsl.exe -- env` inherits depends on how the distro was created,
// so the forwarded command is given an explicit PATH rather than a hopeful one.
const guestPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// guestEnv is the environment every forwarded command runs with inside the
// distro: the in-guest marker (so the guest fox never forwards again), a PATH
// that finds the storage tools, the staged docker build context, and the
// copy-on-write driver.
//
// Windows uses btrfs. ZFS is out-of-tree, so its module has to match the running
// WSL kernel exactly and every kernel needs its own prebuilt bundle — and
// Microsoft ships new WSL kernels often enough that users end up on one nobody
// has built for, unable to install at all. btrfs is in the stock kernel, so it
// works on every WSL kernel with nothing to prebuild. macOS and Linux keep ZFS,
// where the module is a solved problem and the behaviour is proven.
func guestEnv() []string {
	return []string{
		envInGuest + "=1",
		"PATH=" + guestPATH,
		"FOX_IMAGE_CONTEXT=" + guestImageContext,
		"FOX_STORAGE=btrfs",
	}
}

// wslArgs builds the `wsl.exe` argument list that runs the guest engine binary
// inside a distro under the given environment.
//
//	wsl.exe -d <distro> -- env <env…> <guest> <args…>
func wslArgs(distro, guest string, env, args []string) []string {
	out := []string{"-d", distro, "--", "env"}
	out = append(out, env...)
	out = append(out, guest)
	return append(out, args...)
}

type wslDistro struct{ Name, State string }

// decodeWSLOutput decodes wsl.exe output, which is UTF-16LE (with a BOM) on real
// Windows but may be plain UTF-8 in tests or odd shells.
func decodeWSLOutput(b []byte) string {
	if bytes.IndexByte(b, 0) < 0 { // no NUL bytes → already UTF-8
		return string(b)
	}
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE { // strip UTF-16LE BOM
		b = b[2:]
	}
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return string(utf16.Decode(u16))
}

// decodeWSLList parses `wsl.exe -l -v` output into distros, tolerating the
// UTF-16LE encoding, the `*` default marker, and the header row.
func decodeWSLList(raw []byte) []wslDistro {
	var out []wslDistro
	for _, ln := range strings.Split(decodeWSLOutput(raw), "\n") {
		ln = strings.TrimRight(ln, "\r")
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ln), "*")))
		if len(fields) < 2 || strings.EqualFold(fields[0], "NAME") {
			continue
		}
		out = append(out, wslDistro{Name: fields[0], State: fields[1]})
	}
	return out
}

// winPathToMnt converts a Windows path to its WSL /mnt/<drive> form.
//
//	C:\Users\x\fox-linux-amd64  ->  /mnt/c/Users/x/fox-linux-amd64
func winPathToMnt(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) >= 2 && p[1] == ':' {
		return "/mnt/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}

// parseKernelRelease extracts the kernel release from `uname -r` output,
// tolerating the UTF-16LE wrapping and trailing newlines that wsl.exe adds.
func parseKernelRelease(raw []byte) string {
	return strings.TrimSpace(decodeWSLOutput(raw))
}

// distroImageName is the prebuilt distro: Ubuntu with Docker, btrfs tools,
// the engine and the container images already in place. Importing it replaces
// an apt install, a docker build and three registry pulls on the user's machine.
const distroImageName = "foxbyte-distro.tar.gz"
