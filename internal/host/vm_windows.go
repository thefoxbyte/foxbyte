//go:build windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import "fmt"

func vmStatus() error {
	if !wslInstalled() {
		fmt.Println("WSL isn't installed, so there is no FoxByte VM yet — run the installer or `fox setup`.")
		return nil
	}
	name := currentDistro()
	if !distroExists(name) {
		fmt.Printf("No FoxByte VM yet (WSL distro %q) — run `fox setup` to create it.\n", name)
		return nil
	}
	state := "Stopped"
	if distroRunning(name) {
		state = "Running"
	}
	fmt.Printf("FoxByte VM: %s (WSL2 distro)\n  status  %s\n", name, state)
	if state != "Running" {
		fmt.Println("Start it, and the stack inside it, with: fox start")
	}
	return nil
}

func vmShell() error {
	if !wslInstalled() {
		return fmt.Errorf("WSL is required on Windows — run the installer or `fox setup`")
	}
	name := currentDistro()
	if !distroExists(name) {
		return fmt.Errorf("no FoxByte VM yet — run `fox setup` once to create it")
	}
	return wsl("-d", name).Run()
}
