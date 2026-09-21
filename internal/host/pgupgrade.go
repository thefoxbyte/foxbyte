// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// `fox backup export`, `fox backup restore` and `fox pg upgrade` are the three
// commands with a half on each side of the VM. The databases are inside it, but
// an export is only a backup if it ends up somewhere the VM's failure cannot
// take with it: on the user's own disk. So on macOS and Windows the engine
// writes the export inside the VM, and the host copies it out and verifies it
// against its own checksums before calling it done.
//
// The upgrade is one sequence either way — show the plan, ask, export, apply —
// run by RunUpgrade with steps that forward into the VM from a host, or call
// the engine directly on Linux and inside the VM.

// ErrUpToDate stops an upgrade that has nothing to do; it is not a failure.
var ErrUpToDate = errors.New("already on the newest PostgreSQL this fox ships")

// errNotConfirmed is what declining the confirmation returns.
var errNotConfirmed = errors.New("not confirmed — nothing was changed")

// planExitUpToDate is the exit status the engine's plan step uses to say there
// is nothing to do, so the host can tell that apart from a refusal.
const planExitUpToDate = 3

// UpgradeSteps are the three things an upgrade does, wherever they run.
type UpgradeSteps struct {
	Plan   func() error // prints the plan; ErrUpToDate or a refusal stop here
	Export func(out string) error
	Apply  func() error
}

// UpgradeOptions are the user's choices.
type UpgradeOptions struct {
	DryRun     bool
	Yes        bool   // do not ask
	HaveBackup bool   // --i-have-a-backup: skip the export
	ExportTo   string // where the pre-upgrade export goes (default: DefaultExportPath)
}

// RunUpgrade shows the plan, asks, exports, and applies — in that order, and
// never the last without the others unless the user said so explicitly.
func RunUpgrade(s UpgradeSteps, o UpgradeOptions, in io.Reader, out io.Writer) error {
	if err := s.Plan(); err != nil {
		if errors.Is(err, ErrUpToDate) {
			return nil
		}
		return err
	}
	if o.DryRun {
		fmt.Fprintln(out, "\nDry run: nothing was changed.")
		return nil
	}
	if !o.Yes && !confirmTyped(in, out) {
		return errNotConfirmed
	}
	if o.HaveBackup {
		fmt.Fprintln(out, "Not taking an export (--i-have-a-backup).")
	} else {
		path := o.ExportTo
		if path == "" {
			path = DefaultExportPath()
		}
		fmt.Fprintf(out, "Taking an export of every carried branch first: %s\n", path)
		if err := s.Export(path); err != nil {
			return fmt.Errorf("the export failed, so nothing was upgraded: %w", err)
		}
	}
	return s.Apply()
}

// confirmTyped asks the way `fox uninstall` does: type the command's name.
func confirmTyped(in io.Reader, out io.Writer) bool {
	fmt.Fprintf(out, "\nType %s to confirm: ", brand.CLI)
	line, _ := bufio.NewReader(in).ReadString('\n')
	return strings.TrimSpace(line) == brand.CLI
}

// DefaultExportPath is where an export goes when no --out is given: the state
// directory, which `fox uninstall --keep-data` keeps.
func DefaultExportPath() string {
	return filepath.Join(brand.StatePath("exports"),
		fmt.Sprintf("%s-export-%s.tar", brand.Slug, time.Now().Format("20060102-150405")))
}

// ExportArgs are `fox backup export`'s flags.
type ExportArgs struct {
	Out      string
	Branches []string
}

// ParseExportArgs reads [--out <path>] [--branch <name>]...
func ParseExportArgs(args []string) (ExportArgs, error) {
	var a ExportArgs
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out", "--branch":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return a, fmt.Errorf("%s needs a value", args[i])
			}
			if args[i] == "--out" {
				a.Out = args[i+1]
			} else {
				a.Branches = append(a.Branches, args[i+1])
			}
			i++
		default:
			return a, fmt.Errorf("unknown option %q\nusage: %s backup export [--out <file>] [--branch <name>]...", args[i], brand.CLI)
		}
	}
	return a, nil
}

// RestoreArgs are `fox backup restore`'s arguments.
type RestoreArgs struct {
	File, Branch, As string
}

// ParseRestoreArgs reads <file> [--branch <name>] --as <new branch>.
func ParseRestoreArgs(args []string) (RestoreArgs, error) {
	a := RestoreArgs{Branch: "main"}
	usage := fmt.Errorf("usage: %s backup restore <export.tar> [--branch <name>] --as <new branch>", brand.CLI)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--branch", "--as":
			if i+1 >= len(args) {
				return a, usage
			}
			if args[i] == "--branch" {
				a.Branch = args[i+1]
			} else {
				a.As = args[i+1]
			}
			i++
		default:
			if a.File != "" || strings.HasPrefix(args[i], "--") {
				return a, usage
			}
			a.File = args[i]
		}
	}
	if a.File == "" || a.As == "" {
		return a, usage
	}
	return a, nil
}

// PgUpgradeArgs are `fox pg upgrade`'s flags.
type PgUpgradeArgs struct {
	UpgradeOptions
	Rollback, Finalize bool
}

// ParsePgUpgradeArgs reads the upgrade's flags.
func ParsePgUpgradeArgs(args []string) (PgUpgradeArgs, error) {
	var a PgUpgradeArgs
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			a.DryRun = true
		case "--yes", "-y":
			a.Yes = true
		case "--i-have-a-backup":
			a.HaveBackup = true
		case "--rollback":
			a.Rollback = true
		case "--finalize":
			a.Finalize = true
		case "--export":
			if i+1 >= len(args) {
				return a, fmt.Errorf("--export needs a path")
			}
			a.ExportTo = args[i+1]
			i++
		default:
			return a, fmt.Errorf("unknown option %q\nusage: %s pg upgrade [--dry-run] [--yes] [--export <file> | --i-have-a-backup] | --rollback | --finalize", args[i], brand.CLI)
		}
	}
	if a.Rollback && a.Finalize {
		return a, fmt.Errorf("--rollback and --finalize are opposites; choose one")
	}
	if a.HaveBackup && a.ExportTo != "" {
		return a, fmt.Errorf("--export and --i-have-a-backup contradict each other")
	}
	return a, nil
}

// guestTemp is where the engine writes a file that is about to cross to the
// host, or where one lands on its way in.
func guestTemp(name string) string { return "/var/tmp/" + filepath.Base(name) }

// hostExport runs an export inside the VM, copies it to the host, verifies it
// there, and removes the VM's copy.
func hostExport(args []string) error {
	a, err := ParseExportArgs(args)
	if err != nil {
		return err
	}
	out := a.Out
	if out == "" {
		out = DefaultExportPath()
	}
	if out, err = filepath.Abs(out); err != nil {
		return err
	}
	guest := guestTemp(out)
	fwd := []string{"_export-guest", "--out", guest}
	for _, b := range a.Branches {
		fwd = append(fwd, "--branch", b)
	}
	if err := forward(fwd); err != nil {
		return err
	}
	defer removeInGuest(guest)
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	if err := copyFromGuest(guest, out); err != nil {
		return fmt.Errorf("copying the export out of the VM: %w", err)
	}
	m, err := branch.ReadExport(out, "")
	if err != nil {
		_ = os.Remove(out)
		return fmt.Errorf("the copy of the export does not verify, so it was deleted: %w", err)
	}
	fmt.Printf("Export written to %s — %s, verified.\n", out, countBranches(len(m.Branches)))
	return nil
}

func countBranches(n int) string {
	if n == 1 {
		return "1 branch"
	}
	return fmt.Sprintf("%d branches", n)
}

// hostRestore verifies an export on the host, copies it into the VM, restores
// from it there, and removes the VM's copy.
func hostRestore(args []string) error {
	a, err := ParseRestoreArgs(args)
	if err != nil {
		return err
	}
	if _, err := branch.ReadExport(a.File, ""); err != nil {
		return err
	}
	guest := guestTemp("restore-" + filepath.Base(a.File))
	if err := copyToGuest(a.File, guest); err != nil {
		return fmt.Errorf("copying the export into the VM: %w", err)
	}
	defer removeInGuest(guest)
	return forward([]string{"backup", "restore", guest, "--branch", a.Branch, "--as", a.As})
}

// hostPgUpgrade runs `fox pg upgrade` from a host: the plan and the work run in
// the VM, the questions and the export's destination are on the host.
func hostPgUpgrade(args []string) error {
	a, err := ParsePgUpgradeArgs(args)
	if err != nil {
		return err
	}
	switch {
	case a.Rollback:
		return confirmThen(a.UpgradeOptions, func() error { return forward([]string{"_pg-rollback-plan"}) },
			func() error { return forward([]string{"_pg-rollback"}) })
	case a.Finalize:
		return confirmThen(a.UpgradeOptions, func() error { return forward([]string{"_pg-finalize-plan"}) },
			func() error { return forward([]string{"_pg-finalize"}) })
	}
	return RunUpgrade(UpgradeSteps{
		Plan: func() error {
			err := forward([]string{"_pg-upgrade-plan"})
			if exitCode(err) == planExitUpToDate {
				return ErrUpToDate
			}
			if err != nil {
				return errors.New("refusing to upgrade (see above) — nothing was changed")
			}
			return nil
		},
		Export: func(out string) error { return hostExport([]string{"--out", out}) },
		Apply:  func() error { return forward([]string{"_pg-upgrade-apply"}) },
	}, a.UpgradeOptions, os.Stdin, os.Stdout)
}

// confirmThen shows what an action will do, asks unless --yes, then does it.
func confirmThen(o UpgradeOptions, show, act func() error) error {
	if err := show(); err != nil {
		return err
	}
	if o.DryRun {
		fmt.Println("\nDry run: nothing was changed.")
		return nil
	}
	if !o.Yes && !confirmTyped(os.Stdin, os.Stdout) {
		return errNotConfirmed
	}
	return act()
}

// ConfirmThen is confirmThen for the engine's own use on Linux and in the VM.
func ConfirmThen(o UpgradeOptions, show, act func() error) error { return confirmThen(o, show, act) }

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 0
}

// PlanExitUpToDate is the exit status for "nothing to do", for the engine side.
const PlanExitUpToDate = planExitUpToDate

// copyFile copies a file byte for byte, creating dst (mode 0600).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
