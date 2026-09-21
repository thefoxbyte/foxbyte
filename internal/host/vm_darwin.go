//go:build darwin

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func vmStatus() error {
	if _, err := exec.LookPath("limactl"); err != nil {
		fmt.Println("Lima isn't installed, so there is no FoxByte VM yet. Install it with `brew install lima`, then run `fox setup`.")
		return nil
	}
	name := instance()
	if !instanceExists(name) {
		fmt.Printf("No FoxByte VM yet (Lima instance %q) — run `fox setup` to create it.\n", name)
		return nil
	}
	out, err := exec.Command("limactl", "list", name, "--format", "{{.Status}}|{{.CPUs}}|{{.Memory}}|{{.Disk}}|{{.Dir}}").Output()
	if err != nil {
		return fmt.Errorf("reading the VM's state from Lima: %w", err)
	}
	f := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(f) < 5 {
		return fmt.Errorf("unexpected output from limactl list: %q", out)
	}
	mem, _ := strconv.ParseInt(f[2], 10, 64)
	disk, _ := strconv.ParseInt(f[3], 10, 64)
	fmt.Printf("FoxByte VM: %s (Lima)\n", name)
	fmt.Printf("  status  %s\n  cpus    %s\n  memory  %s\n  disk    %s\n  files   %s\n", f[0], f[1], gib(mem), gib(disk), f[4])
	if f[0] != "Running" {
		fmt.Println("Start it, and the stack inside it, with: fox start")
	}
	return nil
}

func vmShell() error {
	if _, err := exec.LookPath("limactl"); err != nil {
		return fmt.Errorf("Lima is required on macOS — install it with `brew install lima`, then run `fox setup`")
	}
	name := instance()
	if !instanceExists(name) {
		return fmt.Errorf("no FoxByte VM yet — run `fox setup` once to create it")
	}
	if !instanceRunning(name) {
		return fmt.Errorf("the FoxByte VM (%s) is stopped — start it with `fox start`", name)
	}
	cmd := exec.Command("limactl", "shell", name)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
