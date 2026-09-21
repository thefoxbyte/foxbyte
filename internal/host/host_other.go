//go:build !darwin && !windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"io"
	"runtime"
)

// On Linux the engine runs in-process, so `fox setup` has nothing to do. Any
// other OS is unsupported.
func hostSetup() error {
	if runtime.GOOS == "linux" {
		fmt.Println("Linux host — no VM needed. Run `fox start`.")
		return nil
	}
	return fmt.Errorf("unsupported host OS %q", runtime.GOOS)
}

// forward/forwardStdin are never reached on Linux (host.Maybe runs the engine
// in-process); they exist so the shared dispatch links on every platform.
func forward(args []string) error { return forwardStdin(args, nil) }

func forwardStdin(args []string, stdin io.Reader) error {
	return fmt.Errorf("unsupported host OS %q — cannot forward to a VM", runtime.GOOS)
}

// Never reached on Linux, where there is no VM to cross into; they exist so
// the shared commands link on every platform.
func copyFromGuest(guestPath, hostPath string) error { return copyFile(guestPath, hostPath) }
func copyToGuest(hostPath, guestPath string) error   { return copyFile(hostPath, guestPath) }
func removeInGuest(guestPath string)                 {}
