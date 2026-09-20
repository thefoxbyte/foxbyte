//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"github.com/foxbyte/foxbyte/internal/brand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/foxbyte/foxbyte/internal/update"
)

// wslEngine updates the engine inside the WSL distro.
type wslEngine struct{ name string }

func newEngineHost() engineHost { return &wslEngine{} }

func (w *wslEngine) distro() string {
	if w.name == "" {
		w.name = currentDistro()
	}
	return w.name
}

func (w *wslEngine) where() string { return "the WSL distro" }

func (w *wslEngine) prepare() error {
	if !wslInstalled() {
		return fmt.Errorf("WSL is required on Windows. Install it with `wsl --install` (admin, then reboot), then run `fox setup`")
	}
	name := w.distro()
	if !distroExists(name) {
		return fmt.Errorf("no FoxByte WSL distro yet — run `fox setup` once to create it")
	}
	if !distroRunning(name) {
		fmt.Printf("Starting the FoxByte distro (%s)…\n", name)
		if err := waitForSystemd(name); err != nil {
			return err
		}
		if err := checkStorageUnit(name); err != nil {
			return err
		}
	}
	return nil
}

func (w *wslEngine) stage(local string) (string, error) {
	const dest = "/tmp/fox-update"
	script := fmt.Sprintf("set -e; cp %q %q.new; chmod 0755 %q.new; mv -f %q.new %q",
		winPathToMnt(local), dest, dest, dest, dest)
	if err := wslRoot(w.distro(), script); err != nil {
		return "", err
	}
	return dest, nil
}

func (w *wslEngine) installed() (string, error) {
	if strings.TrimSpace(brand.Getenv("GUEST_BIN")) != "" {
		return "", fmt.Errorf("FOX_GUEST_BIN is set (a development setup) — unset it to update the installed engine")
	}
	p := guestBin(w.distro())
	if p == "/tmp/fox" {
		return "", fmt.Errorf("the WSL distro has no installed engine, only a development build at /tmp/fox — run `fox setup` first")
	}
	return p, nil
}

func (w *wslEngine) command(bin string, args []string) *exec.Cmd {
	env := append(guestEnv(), update.EnvNoCheck+"=1")
	return exec.Command("wsl.exe", wslArgs(w.distro(), bin, env, args)...)
}

func (w *wslEngine) run(bin string, args ...string) error {
	cmd := w.command(bin, args)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func (w *wslEngine) output(bin string, args ...string) (string, error) {
	cmd := w.command(bin, args)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return decodeWSLOutput(out), err
}

func platformUpdateHooks(eh engineHost) updateHooks {
	w := eh.(*wslEngine)
	return updateHooks{
		target: func() update.Target {
			return update.Target{GOOS: "windows", HostArch: "amd64", GuestArch: "amd64"}
		},
		preflight: func() error {
			if exe, err := hostExecutable(); err == nil {
				_ = os.Remove(exe + ".old") // left by the previous update
			}
			return nil
		},
		afterEngine: func(files map[string]string) error {
			return refreshImageContext(w.distro(), files[update.ImageContextAsset])
		},
		replaceHost:  replaceHostBinary,
		checkServers: checkControlPlane,
	}
}

// refreshImageContext replaces the Postgres image build context in the distro
// and next to bb.exe with the release's, keeping the previous copies as
// .prev. Only future image builds use it: running containers and the built
// image are left alone.
func refreshImageContext(name, archive string) error {
	if archive == "" {
		return nil
	}
	script := fmt.Sprintf(`set -e; d=%q; src=%q; rm -rf "$d.new"; mkdir -p "$d.new"; tar -xzf "$src" -C "$d.new"; `+
		`chmod +x "$d.new/restore-entrypoint.sh" 2>/dev/null || true; rm -rf "$d.prev"; `+
		`if [ -d "$d" ]; then mv "$d" "$d.prev"; fi; mv "$d.new" "$d"`,
		guestImageContext, winPathToMnt(archive))
	if err := wslRoot(name, script); err != nil {
		return fmt.Errorf("refreshing the image build context in the distro: %w", err)
	}
	if err := update.ReplaceDirFromTarGz(archive, filepath.Join(installDir(), "docker-context")); err != nil {
		return fmt.Errorf("refreshing the image build context next to bb.exe: %w", err)
	}
	return nil
}

func replaceHostBinary(files map[string]string, t update.Target) error {
	exe, err := hostExecutable()
	if err != nil {
		return err
	}
	prev := filepath.Join(cacheDir(), "updates", "prev", "bb.exe")
	if err := update.SwapExecutable(files[update.HostAsset(t)], exe, prev); err != nil {
		return err
	}
	refreshEngineCache(files, t)
	// The installer stages the engine next to bb.exe too; setup looks there
	// after the cache.
	engine := filepath.Join(installDir(), update.EngineAsset(t))
	if regularFile(engine) {
		_ = update.CopyFile(files[update.EngineAsset(t)], engine, 0o755)
	}
	fmt.Printf("  installed %s (previous copy kept at %s)\n", exe, prev)
	return nil
}
