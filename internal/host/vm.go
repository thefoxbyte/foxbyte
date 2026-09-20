// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import "fmt"

// vmUsage is the `fox vm` help line.
const vmUsage = "usage: fox vm [status|shell]"

// VM runs `fox vm`: a look at, or a shell inside, the VM that macOS (Lima) and
// Windows (WSL2) keep the engine in. It runs on the host itself and is never
// forwarded, since it is about the VM rather than something inside it.
func VM(args []string) error {
	sub, err := vmSubcommand(args)
	if err != nil {
		return err
	}
	switch sub {
	case "help":
		fmt.Println(vmUsage)
		fmt.Println("  status  (default) where the engine VM is, whether it's running, and its size")
		fmt.Println("  shell   open a shell inside the engine VM")
		return nil
	case "shell":
		return vmShell()
	default:
		return vmStatus()
	}
}

// vmSubcommand picks the `fox vm` subcommand; no argument means status.
func vmSubcommand(args []string) (string, error) {
	if len(args) == 0 {
		return "status", nil
	}
	switch args[0] {
	case "status", "shell":
		if len(args) > 1 {
			return "", fmt.Errorf("fox vm %s takes no arguments — %s", args[0], vmUsage)
		}
		return args[0], nil
	case "help", "-h", "--help":
		return "help", nil
	}
	return "", fmt.Errorf("unknown vm command %q — %s", args[0], vmUsage)
}

// gib renders a byte count as GiB for status output.
func gib(bytes int64) string {
	return fmt.Sprintf("%.0f GiB", float64(bytes)/(1<<30))
}
