//go:build darwin

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"github.com/foxbyte/foxbyte/internal/brand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/foxbyte/foxbyte/internal/update"
)

// limaEngine updates the engine inside the Lima VM.
type limaEngine struct{ name string }

func newEngineHost() engineHost { return &limaEngine{} }

func (l *limaEngine) vm() string {
	if l.name == "" {
		l.name = instance()
	}
	return l.name
}

func (l *limaEngine) where() string { return "the VM" }

func (l *limaEngine) prepare() error {
	if _, err := exec.LookPath("limactl"); err != nil {
		return fmt.Errorf("Lima is required on macOS. Install it with `brew install lima`, then run `fox setup`")
	}
	name := l.vm()
	if !instanceExists(name) {
		return fmt.Errorf("no FoxByte VM yet — run `fox setup` once to create it")
	}
	if !instanceRunning(name) {
		fmt.Printf("Starting the FoxByte VM (%s)…\n", name)
		if err := limactl("start", name).Run(); err != nil {
			return fmt.Errorf("starting the VM: %w", err)
		}
	}
	return nil
}

// guestArch is the VM's CPU when it runs, else the Mac's (Lima's default).
func (l *limaEngine) guestArch() string {
	if _, err := exec.LookPath("limactl"); err == nil && instanceRunning(l.vm()) {
		return guestArch(l.vm())
	}
	return runtime.GOARCH
}

func (l *limaEngine) stage(local string) (string, error) {
	const dest = "/tmp/fox-update"
	if err := exec.Command("limactl", "copy", local, l.vm()+":"+dest+".new").Run(); err != nil {
		return "", err
	}
	script := "chmod 0755 " + dest + ".new && mv -f " + dest + ".new " + dest
	if err := exec.Command("limactl", "shell", l.vm(), "--", "sh", "-c", script).Run(); err != nil {
		return "", err
	}
	return dest, nil
}

func (l *limaEngine) installed() (string, error) {
	if strings.TrimSpace(brand.Getenv("GUEST_BIN")) != "" {
		return "", fmt.Errorf("FOX_GUEST_BIN is set (a development setup) — unset it to update the installed engine")
	}
	p := guestBin(l.vm())
	if p == "/tmp/fox" {
		return "", fmt.Errorf("the VM has no installed engine, only a development build at /tmp/fox — run `fox setup` first")
	}
	return p, nil
}

func (l *limaEngine) command(bin string, args []string) *exec.Cmd {
	full := append([]string{"shell", l.vm(), "--", "env", envInGuest + "=1", update.EnvNoCheck + "=1", bin}, args...)
	return exec.Command("limactl", full...)
}

func (l *limaEngine) run(bin string, args ...string) error {
	cmd := l.command(bin, args)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func (l *limaEngine) output(bin string, args ...string) (string, error) {
	cmd := l.command(bin, args)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return string(out), err
}

func platformUpdateHooks(eh engineHost) updateHooks {
	l := eh.(*limaEngine)
	return updateHooks{
		target: func() update.Target {
			return update.Target{GOOS: "darwin", HostArch: runtime.GOARCH, GuestArch: l.guestArch()}
		},
		preflight:    preflightHostBinary,
		replaceHost:  replaceHostBinary,
		checkServers: checkControlPlane,
	}
}

// preflightHostBinary checks fox on the Mac can be replaced, before anything
// changes: not a Homebrew install, and sudo is asked for now if needed.
func preflightHostBinary() error {
	exe, err := hostExecutable()
	if err != nil {
		return err
	}
	if strings.Contains(exe, "/Cellar/") || strings.Contains(exe, "/homebrew/") {
		return fmt.Errorf("fox at %s is managed by Homebrew — update it with Homebrew instead", exe)
	}
	if update.DirWritable(filepath.Dir(exe)) {
		return nil
	}
	fmt.Printf("  replacing %s needs administrator rights — you may be asked for your password\n", exe)
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo is needed to replace %s: %w", exe, err)
	}
	return nil
}

func replaceHostBinary(files map[string]string, t update.Target) error {
	exe, err := hostExecutable()
	if err != nil {
		return err
	}
	prev := filepath.Join(cacheDir(), "updates", "prev", "fox")
	if err := update.InstallBinary(files[update.HostAsset(t)], exe, prev); err != nil {
		return err
	}
	refreshEngineCache(files, t)
	fmt.Printf("  installed %s (previous copy kept at %s)\n", exe, prev)
	return nil
}
