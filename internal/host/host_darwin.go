//go:build darwin

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// hostSetup is the macOS bootstrap: create/start the Lima VM and bring the stack up.
func hostSetup() error { return setupDarwin() }

func instance() string {
	if v := strings.TrimSpace(brand.Getenv("LIMA_INSTANCE")); v != "" {
		return v
	}
	// Prefer the dedicated instance. Otherwise take one that already exists: a
	// VM from a previous name of the product, or a plain "default" VM on a
	// machine set up by hand. Without this, a rename would leave the engine
	// looking at an empty new VM while the data sat in the old one.
	names := []string{brand.VMInstance}
	for _, p := range brand.Previous {
		names = append(names, p.Slug, p.CLI) // legacy: VMs named for a retired product
	}
	names = append(names, "default")
	for _, name := range names {
		if instanceExists(name) {
			return name
		}
	}
	return brand.VMInstance
}

func limactl(args ...string) *exec.Cmd {
	cmd := exec.Command("limactl", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd
}

func instanceExists(name string) bool {
	out, err := exec.Command("limactl", "list", "--format", "{{.Name}}").Output()
	if err != nil {
		return false
	}
	for _, l := range strings.Fields(string(out)) {
		if l == name {
			return true
		}
	}
	return false
}

func instanceRunning(name string) bool {
	out, err := exec.Command("limactl", "list", name, "--format", "{{.Status}}").Output()
	return err == nil && strings.TrimSpace(string(out)) == "Running"
}

// guestBin resolves the fox binary path inside the VM: an explicit override, or
// `fox` on the guest PATH, else the dev build at /tmp/fox.
func guestBin(name string) string {
	if v := strings.TrimSpace(brand.Getenv("GUEST_BIN")); v != "" {
		return v
	}
	out, err := exec.Command("limactl", "shell", name, "--",
		"sh", "-c", "command -v fox || echo /tmp/fox").Output()
	if err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			return p
		}
	}
	return "/tmp/fox"
}

func forward(args []string) error { return forwardStdin(args, os.Stdin) }

func forwardStdin(args []string, stdin io.Reader) error {
	if _, err := exec.LookPath("limactl"); err != nil {
		return fmt.Errorf("Lima is required on macOS. Install it with `brew install lima`, then run `fox setup`")
	}
	name := instance()
	if !instanceExists(name) {
		return fmt.Errorf("no FoxByte VM yet — run `fox setup` once to create it")
	}
	if !instanceRunning(name) {
		fmt.Printf("Starting the FoxByte VM (%s)…\n", name)
		if err := limactl("start", name).Run(); err != nil {
			return fmt.Errorf("starting the VM: %w", err)
		}
	}
	guest := guestBin(name)
	full := append([]string{"shell", name, "--", "env", envInGuest + "=1", guest}, args...)
	cmd := exec.Command("limactl", full...)
	cmd.Stdin = stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func setupDarwin() error {
	if _, err := exec.LookPath("limactl"); err != nil {
		return fmt.Errorf("Lima is required on macOS.\n" +
			"Install it with:\n  brew install lima\n" +
			"then run `fox setup` again")
	}
	// Fetch the latest engine build up front, so even an existing VM is updated
	// (not just a freshly created one).
	refreshEngineBinary(runtime.GOARCH)

	name := instance()
	if instanceExists(name) {
		if !instanceRunning(name) {
			fmt.Printf("Starting existing VM %q…\n", name)
			if err := limactl("start", name).Run(); err != nil {
				return err
			}
		}
		fmt.Printf("VM %q is ready.\n", name)
	} else {
		fmt.Printf("Creating the FoxByte VM %q (first run downloads Ubuntu; a few minutes)…\n", name)
		if err := limactl("start", "--name", name, "--tty=false", "template://ubuntu").Run(); err != nil {
			return fmt.Errorf("creating the VM: %w", err)
		}
		if err := provisionGuest(name); err != nil {
			return err
		}
	}
	// Always (re)install the engine binary, so re-running `fox setup` picks up a
	// newer build instead of keeping the one already inside the VM.
	if err := installGuestBinary(name); err != nil {
		return err
	}
	fmt.Println("Bringing the stack up…")
	return forward([]string{"start"})
}

// provisionGuest installs Docker + ZFS inside a freshly created VM. The engine
// binary is installed separately (installGuestBinary), on every setup. The engine
// itself auto-creates the ZFS pool and builds the image on first `up`.
func provisionGuest(name string) error {
	fmt.Println("Installing Docker and ZFS in the VM…")
	script := "set -e; sudo apt-get update -y; " +
		"sudo apt-get install -y zfsutils-linux docker.io; " +
		"sudo systemctl enable --now docker"
	if err := limactl("shell", name, "--", "sh", "-c", script).Run(); err != nil {
		return fmt.Errorf("installing guest dependencies: %w", err)
	}
	return nil
}

// installGuestBinary copies the bundled Linux fox binary into the VM and puts it
// on PATH, so `fox` inside the guest is the real engine. Skipped (with a note) if
// no bundled binary is found — e.g. a source checkout that builds its own.
// guestStaging is where the engine binary lands in the VM before it is installed
// on PATH.
var guestStaging = "/tmp/" + brand.CLI + ".new"

func installGuestBinary(name string) error {
	bin := strings.TrimSpace(brand.Getenv("GUEST_BINARY"))
	if bin == "" {
		bin = bundledLinuxBinary(guestArch(name))
	}
	if bin == "" {
		fmt.Println("Note: no bundled Linux fox binary found — the guest will use /tmp/fox " +
			"if you built it from source (FOX_GUEST_BINARY overrides this).")
		return nil
	}
	fmt.Println("Installing the fox engine into the VM…")
	if err := limactl("copy", bin, name+":"+guestStaging).Run(); err != nil {
		return fmt.Errorf("copying the engine binary into the VM: %w", err)
	}
	return limactl("shell", name, "--",
		"sudo", "install", "-m", "0755", guestStaging, "/usr/local/bin/"+brand.CLI).Run()
}

// guestArch reports the Go arch string for the VM ("arm64"/"amd64").
func guestArch(name string) string {
	out, err := exec.Command("limactl", "shell", name, "--", "uname", "-m").Output()
	if err == nil && strings.TrimSpace(string(out)) == "x86_64" {
		return "amd64"
	}
	return "arm64" // Lima defaults to the host arch; Apple Silicon is arm64
}

// Files cross between the Mac and the VM with `limactl copy`, which is scp:
// byte for byte. A stream through `limactl shell` could be given a terminal and
// have its line endings rewritten, which would ruin an archive silently.
func copyFromGuest(guestPath, hostPath string) error {
	return limactl("copy", instance()+":"+guestPath, hostPath).Run()
}

func copyToGuest(hostPath, guestPath string) error {
	return limactl("copy", hostPath, instance()+":"+guestPath).Run()
}

func removeInGuest(guestPath string) {
	_ = exec.Command("limactl", "shell", instance(), "--", "rm", "-f", guestPath).Run()
}
