//go:build !darwin && !windows

// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"fmt"
	"runtime"
)

func vmStatus() error {
	if runtime.GOOS == "linux" {
		fmt.Println("Linux host — FoxByte runs directly on this machine; there is no VM.")
		return nil
	}
	return fmt.Errorf("unsupported host OS %q", runtime.GOOS)
}

func vmShell() error {
	if runtime.GOOS == "linux" {
		return fmt.Errorf("Linux host — there is no VM to open a shell in; FoxByte runs directly on this machine")
	}
	return fmt.Errorf("unsupported host OS %q", runtime.GOOS)
}
