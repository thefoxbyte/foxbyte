// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/foxbyte/foxbyte/internal/brand"
)

// Uninstalling.
//
// Removal used to be a list of commands to run by hand -- containers, volumes,
// the pool, the state directory, the VM, the binary -- and missing one left
// something behind that still held ports, disk, or a stale copy of the engine.
// Worse, an install under a retired product name left a binary on PATH that
// spoke to its own state directory and could start a second stack.
//
// `fox uninstall` lists what it will remove, asks, and then removes it. It is
// safe to run twice: every removal checks first and says "already gone".

const uninstallUsage = "usage: fox uninstall [--keep-data] [--yes]"

// UninstallOptions are the command's flags, plus the streams to talk on (a test
// supplies its own).
type UninstallOptions struct {
	KeepData bool      // keep the databases, backups and account store
	Yes      bool      // do not ask
	Out      io.Writer // where the inventory and progress go
	In       io.Reader // where the confirmation is read from
}

// removal is one thing to remove. present reports whether it is there at all, so a
// second run can say so rather than reporting errors.
type removal struct {
	what    string // one line, for the inventory
	data    bool   // holds data: skipped by --keep-data
	present func() bool
	run     func() error
}

// Uninstall runs `fox uninstall`.
func Uninstall(args []string) error {
	o := UninstallOptions{Out: os.Stdout, In: os.Stdin}
	for _, a := range args {
		switch a {
		case "--keep-data":
			o.KeepData = true
		case "--yes", "-y":
			o.Yes = true
		case "help", "-h", "--help":
			fmt.Println(uninstallUsage)
			fmt.Println("  --keep-data  remove the engine but keep databases, backups and accounts")
			fmt.Println("  --yes        do not ask for confirmation")
			return nil
		default:
			return fmt.Errorf("unknown option %q — %s", a, uninstallUsage)
		}
	}
	return uninstall(o)
}

func uninstall(o UninstallOptions) error {
	steps := uninstallSteps(o)
	var todo []removal
	for _, s := range steps {
		if o.KeepData && s.data {
			continue
		}
		if s.present != nil && !s.present() {
			continue
		}
		todo = append(todo, s)
	}
	if len(todo) == 0 {
		fmt.Fprintf(o.Out, "Nothing to remove — %s is not installed here.\n", brand.Product)
		return nil
	}

	fmt.Fprintf(o.Out, "This will remove:\n")
	for _, s := range todo {
		mark := "  "
		if s.data {
			mark = "! "
		}
		fmt.Fprintf(o.Out, "  %s%s\n", mark, s.what)
	}
	if o.KeepData {
		fmt.Fprintf(o.Out, "\nDatabases, backups and accounts are kept (--keep-data).\n")
	} else {
		fmt.Fprintf(o.Out, "\nLines marked ! destroy data, and cannot be undone.\n")
	}

	if !o.Yes {
		fmt.Fprintf(o.Out, "\nType %s to confirm: ", brand.CLI)
		line, _ := bufio.NewReader(o.In).ReadString('\n')
		if strings.TrimSpace(line) != brand.CLI {
			fmt.Fprintln(o.Out, "Nothing was removed.")
			return nil
		}
	}

	var failed int
	for _, s := range todo {
		fmt.Fprintf(o.Out, "removing %s… ", s.what)
		if err := s.run(); err != nil {
			failed++
			fmt.Fprintf(o.Out, "failed: %v\n", err)
			continue
		}
		fmt.Fprintln(o.Out, "done")
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d steps failed — rerun, or remove those by hand", failed, len(todo))
	}
	fmt.Fprintf(o.Out, "\n%s is removed.\n", brand.Product)
	if o.KeepData {
		fmt.Fprintf(o.Out, "Its data is still here; installing %s again will find it.\n", brand.Product)
	}
	return nil
}

// stopStep stops the background servers and containers before anything is
// removed. Without it the state directory goes out from under running servers:
// they keep the ports, hold a deleted account database, and every key minted
// afterwards is rejected.
func stopStep(run func() error) removal {
	return removal{
		what:    "the running servers and containers",
		present: func() bool { return true },
		run:     run,
	}
}

// hostSteps are the same on every platform: this binary, binaries left by
// retired names, and the state directory.
func hostSteps(o UninstallOptions) []removal {
	var out []removal
	for _, name := range binaryNames() {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if self, err := os.Executable(); err == nil {
			if selfResolved, err := filepath.EvalSymlinks(self); err == nil {
				if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved == selfResolved {
					// Removing the running binary is fine on Unix, and is the
					// point of the command, so it is kept in the list.
					_ = resolved
				}
			}
		}
		p := path
		out = append(out, removal{
			what:    "the " + name + " command (" + p + ")",
			present: func() bool { _, err := os.Stat(p); return err == nil },
			run:     func() error { return removePath(p) },
		})
	}
	dir := brand.StateDir()
	out = append(out, removal{
		what:    "accounts, API keys, secrets and Blackbox anchors (" + dir + ")",
		data:    true,
		present: func() bool { _, err := os.Stat(dir); return err == nil },
		run:     func() error { return os.RemoveAll(dir) },
	})
	return out
}

// binaryNames is this command and the commands of retired product names, so an
// install from before a rename is removed too rather than left on PATH.
func binaryNames() []string {
	names := []string{brand.CLI}
	for _, p := range brand.Previous {
		names = append(names, p.CLI) // legacy: a binary left by a retired name
	}
	return names
}

// removePath deletes a file, with sudo if the directory is not writable (the
// binary usually lives in /usr/local/bin).
func removePath(p string) error {
	if err := os.Remove(p); err == nil || os.IsNotExist(err) {
		return nil
	}
	if out, err := exec.Command("sudo", "rm", "-f", p).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
