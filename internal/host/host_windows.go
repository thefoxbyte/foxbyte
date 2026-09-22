//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"encoding/base64"
	"fmt"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/version"
)

// hostSetup is the Windows bootstrap: ensure a ZFS-capable WSL2 distro and bring
// the stack up.
func hostSetup() error { return setupWindows() }

// currentDistro resolves the WSL2 distro name: an explicit override, else the
// dedicated distro, brand.VMInstance ("fox").
func currentDistro() string { return resolveWSLDistro(brand.Getenv("WSL_DISTRO")) }

func wslInstalled() bool {
	_, err := exec.LookPath("wsl.exe")
	return err == nil
}

func distroExists(name string) bool {
	out, err := exec.Command("wsl.exe", "--list", "--quiet").Output()
	if err != nil {
		return false
	}
	for _, l := range strings.Fields(decodeWSLOutput(out)) {
		if strings.EqualFold(l, name) {
			return true
		}
	}
	return false
}

func distroRunning(name string) bool {
	out, err := exec.Command("wsl.exe", "--list", "--verbose").Output()
	if err != nil {
		return false
	}
	for _, d := range decodeWSLList(out) {
		if strings.EqualFold(d.Name, name) {
			return strings.EqualFold(d.State, "Running")
		}
	}
	return false
}

// guestBin resolves the engine binary path inside the distro.
func guestBin(name string) string {
	if v := strings.TrimSpace(brand.Getenv("GUEST_BIN")); v != "" {
		return v
	}
	out, err := exec.Command("wsl.exe", "-d", name, "--",
		"sh", "-c", "command -v fox || echo /tmp/fox").Output()
	if err == nil {
		if p := strings.TrimSpace(decodeWSLOutput(out)); p != "" {
			return p
		}
	}
	return "/tmp/fox"
}

func forward(args []string) error { return forwardStdin(args, os.Stdin) }

func forwardStdin(args []string, stdin io.Reader) error {
	if !wslInstalled() {
		return fmt.Errorf("WSL is required on Windows. Install it with `wsl --install` (admin, then reboot), then run `fox setup`")
	}
	name := currentDistro()
	if !distroExists(name) {
		return fmt.Errorf("no FoxByte WSL distro yet — run `fox setup` once to create it")
	}
	// `wsl.exe -d <name> -- …` starts a stopped distro on demand but returns as
	// soon as the command can run — well before systemd has brought Docker up.
	// WSL stops idle distros, so without this wait the first command after an
	// idle timeout or a reboot fails with "cannot reach the Docker daemon".
	// The macOS path has the same guard; there `limactl start` blocks for us.
	if !distroRunning(name) {
		fmt.Printf("Starting the FoxByte distro (%s)…\n", name)
		if err := waitForSystemd(name); err != nil {
			return err
		}
		// Only on a cold start: the pool unit runs at boot, and if it could not
		// bring the pool up the engine must not proceed to create a new one.
		if err := checkStorageUnit(name); err != nil {
			return err
		}
	}
	guest := guestBin(name)
	cmd := exec.Command("wsl.exe", wslArgs(name, guest, guestEnv(), args)...)
	cmd.Stdin = stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// forwardQuiet forwards a command with its output logged rather than printed.
//
// Only setup uses it. The engine's own `fox start` is worth watching when a user
// types it, but during an install the image build and registry pulls are several
// hundred lines that bury the progress the user actually wants to see.
func forwardQuiet(args []string) error {
	name := currentDistro()
	guest := guestBin(name)
	out, err := exec.Command("wsl.exe", wslArgs(name, guest, guestEnv(), args)...).CombinedOutput()
	text := decodeWSLOutput(out)
	logf("$ fox %s\n%s\n", strings.Join(args, " "), text)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, lastLines(text, 20))
	}
	return nil
}

// wsl runs an interactive wsl.exe command wired to the console.
func wsl(args ...string) *exec.Cmd {
	cmd := exec.Command("wsl.exe", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd
}

// wslQuiet runs a wsl.exe management command with its output logged rather than
// printed. wsl.exe narrates routine success ("The operation completed
// successfully.") in UTF-16, which is noise during setup and renders badly.
func wslQuiet(args ...string) error {
	out, err := exec.Command("wsl.exe", args...).CombinedOutput()
	text := decodeWSLOutput(out)
	logf("$ wsl %s\n%s\n", strings.Join(args, " "), text)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, lastLines(text, 10))
	}
	return nil
}

// guestPath prefixes setup scripts that use the ZFS userland. It installs under
// /usr/local, which is on Debian's default root PATH and sudo secure_path — but
// the environment `wsl.exe -- sh -c` inherits is not guaranteed to be either, so
// the setup scripts state it rather than assume it.
const guestPath = "export PATH=/usr/local/sbin:/usr/local/bin:$PATH"

// setupLog is the transcript of everything setup runs in the guest. apt and
// docker are extremely chatty, and streaming them made a working install look
// alarming and a broken one impossible to read. The detail goes here instead,
// and is surfaced on failure.
func setupLogPath() string { return filepath.Join(installDir(), "install.log") }

// logf appends to the setup log. Logging is best-effort: failing to write a log
// must never fail an install.
func logf(format string, args ...any) {
	f, err := os.OpenFile(setupLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format, args...)
}

// step announces a stage before running it, so a stall is attributable to a
// named step rather than to silence.
func step(msg string) {
	fmt.Printf("  %s…\n", msg)
	logf("\n=== %s ===\n", msg)
}

// wslRoot runs a shell command inside the distro as root (setup steps need
// privilege without a sudo password prompt), capturing its output to the setup
// log rather than the console.
//
// On failure the captured tail is included in the error, so the detail appears
// exactly when it is wanted and nowhere else.
func wslRoot(name, script string) error {
	cmd := exec.Command("wsl.exe", "-d", name, "-u", "root", "--", "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	text := decodeWSLOutput(out)
	logf("$ %s\n%s\n", script, text)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, lastLines(text, 15))
	}
	return nil
}

// lastLines returns the final n non-empty lines, the part of a failed command's
// output that actually says what went wrong.
func lastLines(s string, n int) string {
	var keep []string
	for _, ln := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(ln) != "" {
			keep = append(keep, strings.TrimRight(ln, "\r"))
		}
	}
	if len(keep) > n {
		keep = keep[len(keep)-n:]
	}
	return strings.Join(keep, "\n")
}

// wslRootOut is wslRoot but captures stdout, for probes.
func wslRootOut(name, script string) ([]byte, error) {
	return exec.Command("wsl.exe", "-d", name, "-u", "root", "--", "sh", "-c", script).Output()
}

func setupWindows() error {
	if !wslInstalled() {
		return fmt.Errorf("WSL is not installed.\n" +
			"Install it (Administrator PowerShell):\n  wsl --install\n" +
			"reboot, then run `fox setup` again")
	}
	// A quick health probe; `--status` fails if the WSL platform isn't enabled.
	if err := exec.Command("wsl.exe", "--status").Run(); err != nil {
		return fmt.Errorf("WSL is present but not healthy (is virtualization enabled in the BIOS, " +
			"and the 'Virtual Machine Platform' feature on?). Run `wsl --install` / `wsl --update`, then retry")
	}

	fmt.Println("Setting up FoxByte…")
	logf("\n---- fox setup %s ----\n", version.Version)

	// Fetch the latest engine build so re-running setup installs the newest one
	// (provisionGuestWSL reinstalls the engine binary on every setup).
	refreshEngineBinary("amd64") // WSL2 is x86_64

	name := currentDistro()
	if distroExists(name) {
		step(fmt.Sprintf("Reusing the existing %q distro", name))
	} else if err := importDistro(name); err != nil {
		return err
	}
	// Both paths land here, so both wait: WSL starts a distro on demand and
	// systemd needs a moment after that, whether it was just imported or merely
	// stopped. Every systemctl call below depends on this.
	if err := waitForSystemd(name); err != nil {
		return err
	}
	// Provisioning runs on every setup, not only after a fresh import: a setup
	// interrupted partway leaves the distro existing but incomplete, and `fox
	// setup` is the command a user re-runs to repair that. Each step below
	// checks its own work first, so a healthy distro costs a few probes.
	if err := provisionGuestWSL(name); err != nil {
		return err
	}
	// Re-checked every time for the same reason, plus one of its own: a WSL
	// update can move the kernel out from under an already-provisioned distro.
	if err := verifyBtrfs(name); err != nil {
		return err
	}
	step("Starting FoxByte")
	err := forwardQuiet([]string{"start"})
	if err == nil {
		return finishSetup(name)
	}
	// One retry. This used to be the only defence against the first start racing
	// the Postgres container's initdb, because the engine's readiness probe used
	// the Unix socket and so returned true while the entrypoint's temporary
	// server was still running. waitReady now probes TCP, which that temporary
	// server does not listen on, so the race is fixed at its source and this is
	// no longer load-bearing.
	//
	// Kept because `start` is idempotent and a first-run start has plenty of
	// other ways to be slow on a cold machine, but a failure here is now a real
	// failure rather than an expected one.
	step("Retrying the start")
	if err := forwardQuiet([]string{"start"}); err != nil {
		return err
	}
	return finishSetup(name)
}

// finishSetup completes a successful setup and tells the user what they have.
//
// The engine's own start banner is captured during setup, so without this the
// install would end in silence.
func finishSetup(name string) error {
	if err := shareMountPropagation(name); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(green("FoxByte is running."))
	fmt.Println("  Open:     https://localhost:8080")
	fmt.Println("  Try:      fox status")
	// No key is printed because none is minted: a credential is made by the
	// person who will use it, from the API keys page or `fox apikey create`.
	fmt.Println("  Connect:  postgresql://dbadmin:<API_KEY>@localhost:6432/main?sslmode=require")
	fmt.Println("  Log:      " + setupLogPath())
	// The first-run lines, with the setup token the sign-up page asks for, are
	// part of the engine's start banner, which setup captured.
	_ = forward([]string{"_first-run"})
	return nil
}

// shareMountPropagation puts the pool's mounts under shared propagation, once
// the pool exists.
//
// dbpool-storage.service does this on every boot, but on the very first run the
// pool is created by `fox start` after that unit has already run. Without it the
// first session's mounts stay private, and any sandboxed systemd service that
// starts afterwards pins them — see the note on finish() in zpoolUpScript.
func shareMountPropagation(name string) error {
	// Best-effort: a failure here costs a stale mount, not correctness, and the
	// next boot fixes it.
	_ = wslRoot(name, "mount --make-rshared /foxbyte 2>/dev/null || true")
	return nil
}

// importDistro creates the dedicated distro from the bundled Ubuntu rootfs and
// enables systemd inside it.
func importDistro(name string) error {
	rootfs := bundledRootfs()
	if rootfs == "" {
		return fmt.Errorf("the Ubuntu rootfs was not found next to fox.exe — reinstall with install.ps1")
	}
	installDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "foxbyte", "wsl")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	if strings.HasSuffix(rootfs, ".zst") {
		step("Unpacking the FoxByte distro image")
	}
	// Unpacked next to the download, which is in the user's own writable
	// install folder; the tar is removed once imported and the .zst is kept, so
	// a re-run of setup does not download it again.
	file, done, err := importableDistro(rootfs, filepath.Dir(rootfs))
	if err != nil {
		return fmt.Errorf("unpacking the distro image (it needs about 2 GB free while it imports): %w", err)
	}
	defer done()
	step(fmt.Sprintf("Creating the %q WSL distro", name))
	if err := wslQuiet("--import", name, installDir, file); err != nil {
		return fmt.Errorf("importing the WSL distro: %w", err)
	}
	// systemd for `systemctl enable --now docker` and the ZFS import units;
	// root as the default user so the engine's `sudo` never prompts.
	//
	// appendWindowsPath=false keeps the Windows PATH out of this distro. It is a
	// dedicated engine distro that needs nothing from Windows, and leaving it on
	// means `docker` resolves to Docker Desktop's docker.exe on machines that
	// have it — which silently shadows the Linux Docker the engine must talk to.
	conf := `printf '[boot]\nsystemd=true\n\n[user]\ndefault=root\n\n[interop]\nappendWindowsPath=false\n' > /etc/wsl.conf`
	if err := wslRoot(name, conf); err != nil {
		return fmt.Errorf("configuring the distro: %w", err)
	}
	// The distro must restart to pick up /etc/wsl.conf. The caller waits for
	// systemd to come back, on this path and on the already-exists path alike.
	if err := wslQuiet("--terminate", name); err != nil {
		return fmt.Errorf("restarting the distro to apply systemd: %w", err)
	}
	return nil
}

// waitForSystemd blocks until the distro's systemd has finished booting. The
// distro is restarted right before this to pick up /etc/wsl.conf, and systemctl
// calls issued during that window fail with "system has not been booted".
func waitForSystemd(name string) error {
	// Announced only if it actually takes a moment: on a warm distro systemd is
	// already up and a progress line for a no-op is just noise.
	announced := false
	for i := 0; i < 60; i++ {
		out, _ := wslRootOut(name, "systemctl is-system-running 2>&1 || true")
		switch strings.TrimSpace(decodeWSLOutput(out)) {
		case "running", "degraded":
			return nil
		}
		if !announced {
			step("Waiting for the distro to finish booting")
			announced = true
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("systemd did not finish booting in the %q distro after 60s — "+
		"try `wsl --terminate %s` and re-run `fox setup`", name, name)
}

// provisionGuestWSL installs Docker + ZFS in the distro and installs the engine
// binary — mirroring provisionGuest on macOS. Every step is idempotent so this
// doubles as the repair path for an interrupted setup.
func provisionGuestWSL(name string) error {
	if err := installDocker(name); err != nil {
		return err
	}
	if err := ensureBtrfs(name); err != nil {
		return err
	}
	if err := ensureStorage(name); err != nil {
		return err
	}
	if err := loadPreloadedImages(name); err != nil {
		return err
	}
	if err := stageImageContext(name); err != nil {
		return err
	}
	return installGuestBinaryWSL(name)
}

// loadPreloadedImages imports the container images baked into the distro image.
//
// The prebuilt distro ships them as a docker save tarball rather than a
// populated layer store, because building that store would mean running a second
// dockerd inside a chroot on the builder. Loading here is local disk work and
// replaces a docker build plus three registry pulls — the slowest and least
// reliable part of a first start.
//
// A plain Ubuntu rootfs has no tarball, in which case this is a no-op and the
// engine builds and pulls as before.
func loadPreloadedImages(name string) error {
	const tar = "/usr/local/share/dbengine/images/foxbyte-images.tar"
	if wslRoot(name, fmt.Sprintf("test -f %q", tar)) != nil {
		return nil
	}
	// Already loaded (a re-run): the engine's own check is `docker image
	// inspect`, so match it rather than guessing from the tarball's presence —
	// and match the image the preload actually carries. This probed the
	// pre-Sept-16 legacy name, which a newer distro never has, so every re-run
	// loaded the whole tarball again.
	if wslRoot(name, "docker image inspect "+branch.PostgresImageFor(branch.PGMajor)+" >/dev/null 2>&1") == nil {
		return nil
	}
	step("Loading the preinstalled container images")
	// Distro images built before 16 Sep 2026 tag Postgres `foxbyte/postgres-walg:16`,
	// which the engine never looks for — re-tag it so the preload is actually used.
	retag := "; docker image inspect foxbyte/postgres-walg:16 >/dev/null 2>&1 && " +
		"docker tag foxbyte/postgres-walg:16 ghcr.io/thefoxbyte/postgres-walg:16 || true"
	if err := wslRoot(name, fmt.Sprintf("set -e; docker load -i %q", tar)+retag); err != nil {
		// Not fatal: the engine can still build and pull. Losing the fast path
		// is better than failing an install over it.
		logf("loading preinstalled images failed, falling back to build/pull: %v\n", err)
	}
	return nil
}

// storageUpScript mounts the btrfs filesystem the branches live on, at every
// distro boot.
//
// It replaces a much larger ZFS equivalent. That one had to attach the pool
// image to a loop device (the WSL kernel cannot back a pool with a plain file),
// pick the device by backing inode to avoid adopting a stale binding from an
// unregistered distro, import the pool without scanning /dev, and refuse to
// continue on a suspended pool -- because detaching a device under a live pool
// wedges the VM, and because the engine would otherwise reach `zpool create -f`
// and overwrite existing data.
//
// btrfs needs none of that: mkfs works on the file directly, and mounting is the
// whole job. The mount is also what makes the data durable across a WSL VM
// shutdown, which is when the previous design lost its kernel modules.
const storageUpScript = `#!/bin/sh
# Managed by fox setup. Mounts the FoxByte btrfs filesystem before the engine
# runs. Idempotent: a mounted filesystem is left alone.
set -e
IMG=/var/lib/dbpool-btrfs.img
MNT=/dbpool/branches
SIZE="${FOX_ZPOOL_SIZE:-30G}"

modprobe btrfs 2>/dev/null || true
mkdir -p "$MNT"

if mountpoint -q "$MNT"; then
	exit 0
fi

# First boot: the engine creates the filesystem itself on its first start, so a
# missing image is normal and not an error.
[ -f "$IMG" ] || exit 0

# No compression: branch subvolumes are nodatacow so btrfs cannot compress them
# anyway, and compressing a database write path costs CPU for little gain.
mount -o loop "$IMG" "$MNT"
`

const storageUnit = `[Unit]
Description=FoxByte storage (btrfs)
After=local-fs.target
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/lib/dbengine/storage-up.sh

[Install]
WantedBy=multi-user.target
`

// ensureStorage installs and enables the mount unit above.
func ensureStorage(name string) error {
	step("Preparing storage")
	script := "set -e; mkdir -p /usr/local/lib/dbengine; " +
		writeFileB64("/usr/local/lib/dbengine/storage-up.sh", storageUpScript) + "; " +
		"chmod 0755 /usr/local/lib/dbengine/storage-up.sh; " +
		writeFileB64("/etc/systemd/system/dbpool-storage.service", storageUnit) + "; " +
		"systemctl daemon-reload; systemctl enable --now dbpool-storage.service"
	if err := wslRoot(name, script); err != nil {
		return fmt.Errorf("preparing storage: %w", err)
	}
	// systemctl's exit code does not reliably reflect a failed --now start, and a
	// silently dead unit means the branches are not mounted — so confirm it.
	return checkStorageUnit(name)
}

// checkStorageUnit fails unless dbpool-storage.service is active.
//
// Running the engine without it would let Postgres write into the empty
// directory the filesystem should have been mounted over, so the data would look
// fine until the next boot mounted the real filesystem on top and hid it.
func checkStorageUnit(name string) error {
	out, _ := wslRootOut(name, "systemctl is-active dbpool-storage.service 2>&1 || true")
	if strings.TrimSpace(decodeWSLOutput(out)) == "active" {
		return nil
	}
	detail, _ := wslRootOut(name, "systemctl status dbpool-storage.service --no-pager -l 2>&1 | tail -n 12 || true")
	return fmt.Errorf("the FoxByte btrfs filesystem is not mounted in the %q distro.\n"+
		"Refusing to continue: the engine would write into the empty mount point, and the next boot would hide that data.\n\n%s",
		name, strings.TrimSpace(decodeWSLOutput(detail)))
}

// writeFileB64 renders a shell fragment that writes content to path. The content
// is base64'd so multi-line scripts with their own quoting survive the trip
// through wsl.exe and sh -c intact.
func writeFileB64(path, content string) string {
	return fmt.Sprintf("printf %%s %q | base64 -d > %q",
		base64.StdEncoding.EncodeToString([]byte(content)), path)
}

// installDocker installs and enables Docker, skipping the (slow) apt work when
// it is already there.
//
// The probe deliberately looks for /usr/bin/dockerd rather than `command -v
// docker`: WSL appends the Windows PATH into distros, so on a machine with
// Docker Desktop installed `docker` resolves to docker.exe and the distro looks
// provisioned when it has no Docker at all. dockerd is Linux-only and cannot be
// supplied by interop.
func installDocker(name string) error {
	if wslRoot(name, "test -x /usr/bin/dockerd") == nil {
		// Already present — either a previous setup installed it, or it came
		// baked into the prebuilt distro image. Still ensure it is running: WSL
		// starts distros with nothing up.
		return wslRoot(name, "systemctl enable --now docker")
	}
	step("Installing Docker in the WSL distro")
	// Acquire::Retries because a single flaky mirror connection should not end a
	// setup run — Ubuntu's mirrors resolve to both IPv6 and IPv4, and a stalled
	// IPv4 path otherwise leaves docker.io with "no installation candidate".
	const retries = "-o Acquire::Retries=3"
	script := "set -e; export DEBIAN_FRONTEND=noninteractive; " +
		"apt-get update -y " + retries + "; " +
		"apt-get install -y " + retries + " docker.io; " +
		"systemctl enable --now docker"
	if err := wslRoot(name, script); err != nil {
		return fmt.Errorf("installing Docker in the distro: %w\n"+
			"If this was a network timeout, re-run `fox setup` — it resumes where it stopped", err)
	}
	return nil
}

// guestKernelRelease reports `uname -r` inside the distro. Every WSL2 distro
// shares one kernel, so this is really the WSL kernel version.
func guestKernelRelease(name string) (string, error) {
	out, err := wslRootOut(name, "uname -r")
	if err != nil {
		return "", fmt.Errorf("reading the WSL kernel version: %w", err)
	}
	rel := parseKernelRelease(out)
	if rel == "" {
		return "", fmt.Errorf("could not read the WSL kernel version")
	}
	return rel, nil
}

// ensureBtrfs makes the copy-on-write substrate usable.
//
// btrfs is in the stock WSL kernel, so there is nothing to build, download or
// match: modprobe and the userland tools are the whole requirement. That is the
// entire reason Windows uses btrfs rather than ZFS -- ZFS modules are
// out-of-tree and must match the running kernel exactly, so every WSL kernel
// needed its own prebuilt bundle, and a user on an uncovered kernel could not
// install at all.
func ensureBtrfs(name string) error {
	if wslRoot(name, "modprobe btrfs && command -v mkfs.btrfs >/dev/null") == nil {
		return nil
	}
	step("Installing btrfs tools")
	script := "set -e; export DEBIAN_FRONTEND=noninteractive; " +
		"modprobe btrfs; " +
		"command -v mkfs.btrfs >/dev/null || { apt-get update -y; apt-get install -y btrfs-progs; }"
	if err := wslRoot(name, script); err != nil {
		return fmt.Errorf("installing btrfs tools: %w", err)
	}
	return nil
}

// verifyBtrfs is the gate before the engine runs: without a working btrfs there
// is no copy-on-write, and every later failure would be a confusing symptom of
// this one cause.
func verifyBtrfs(name string) error {
	if err := wslRoot(name, "modprobe btrfs && mkfs.btrfs --version >/dev/null"); err != nil {
		return fmt.Errorf("btrfs is not usable in the %q distro: %w\n"+
			"btrfs ships in the WSL kernel, so this is unexpected — see %s",
			name, err, setupLogPath())
	}
	return nil
}
func stageImageContext(name string) error {
	// The prebuilt distro image already carries the context (and the built
	// image), so there is nothing to stage.
	if wslRoot(name, fmt.Sprintf("test -f %q/Dockerfile", guestImageContext)) == nil {
		return nil
	}
	src := bundledDir("docker-context")
	if src == "" {
		logf("no bundled docker build context; fox start will look relative to the working directory\n")
		return nil
	}
	step("Staging the Postgres image build context")
	script := fmt.Sprintf("set -e; mkdir -p %q; cp -r %q/. %q/; chmod +x %q/restore-entrypoint.sh",
		guestImageContext, winPathToMnt(src), guestImageContext, guestImageContext)
	if err := wslRoot(name, script); err != nil {
		return fmt.Errorf("staging the image build context: %w", err)
	}
	return nil
}

// installGuestBinaryWSL copies the bundled linux engine binary into the distro.
func installGuestBinaryWSL(name string) error {
	bin := strings.TrimSpace(brand.Getenv("GUEST_BINARY"))
	if bin == "" {
		bin = bundledLinuxBinary("amd64") // WSL2 is x86_64
	}
	if bin == "" {
		fmt.Println("Note: no bundled Linux fox binary found — the guest will use /tmp/fox " +
			"if you built it from source (FOX_GUEST_BINARY overrides this).")
		return nil
	}
	step("Installing the fox engine into the WSL distro")
	src := winPathToMnt(bin)
	return wslRoot(name, fmt.Sprintf("install -m 0755 %q /usr/local/bin/fox", src))
}

// installDir is the directory holding fox.exe — where the installer stages
// assets and where setup caches anything it downloads.
func installDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "foxbyte")
}

// assetDirs lists the places the installer (or a dev build) puts support files,
// relative to fox.exe.
func assetDirs() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	dir := filepath.Dir(exe)
	return []string{
		dir,
		filepath.Join(dir, "..", "share", "foxbyte"),
		filepath.Join(dir, "..", "dist"),
		filepath.Join(dir, "dist"),
	}
}

// bundledAsset finds a support file (ZFS bundle, rootfs) shipped next to fox.exe
// by the installer, or in ./dist for a dev build.
func bundledAsset(basename string) string {
	for _, d := range assetDirs() {
		c := filepath.Join(d, basename)
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// bundledDir is bundledAsset for a directory (the docker build context).
func bundledDir(basename string) string {
	for _, d := range assetDirs() {
		c := filepath.Join(d, basename)
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return ""
}

// bundledRootfs finds the Ubuntu rootfs tarball, which install.ps1 fetches and
// which `wsl --import` accepts gzipped or plain.
// The prebuilt image comes first: it already contains Docker, the ZFS userland,
// the engine and the container images, so importing it skips an apt install, a
// docker build and three registry pulls. A plain Ubuntu rootfs still works, and
// setup does that extra work itself.
func bundledRootfs() string {
	for _, n := range append(append([]string{}, distroImageNames...), "foxbyte-rootfs.tar.gz", "foxbyte-rootfs.tar") {
		if p := bundledAsset(n); p != "" {
			return p
		}
	}
	return ""
}

// prebuiltDistro reports whether the imported distro came from our image, in
// which case setup can skip what the image already did.
func prebuiltDistro(name string) bool {
	return wslRoot(name, "test -x /usr/bin/dockerd && test -x /usr/local/sbin/zpool") == nil
}

// A WSL distro's files are reachable from Windows at \\wsl.localhost\<distro>\,
// so a file crosses with an ordinary copy, byte for byte. The distro must be
// running for the share to answer; forwarding a command starts it.
func guestUNC(guestPath string) string {
	return `\\wsl.localhost\` + currentDistro() + strings.ReplaceAll(guestPath, "/", `\`)
}

func copyFromGuest(guestPath, hostPath string) error {
	return copyFile(guestUNC(guestPath), hostPath)
}

func copyToGuest(hostPath, guestPath string) error {
	if err := wslRoot(currentDistro(), "true"); err != nil { // make sure it is up
		return err
	}
	return copyFile(hostPath, guestUNC(guestPath))
}

func removeInGuest(guestPath string) { _ = os.Remove(guestUNC(guestPath)) }
