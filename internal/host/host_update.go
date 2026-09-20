// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/foxbyte/foxbyte/internal/update"
	"github.com/foxbyte/foxbyte/internal/version"
)

// UpdateOptions are the flags of `fox update`.
type UpdateOptions struct {
	Check   bool   // only report whether a newer release exists
	Yes     bool   // don't ask for confirmation
	Version string // install this release instead of the newest
}

// engineHost is where the engine runs: the Lima VM (macOS), the WSL distro
// (Windows) or this machine (Linux). host_update_<os>.go provide it.
type engineHost interface {
	where() string                                     // "the VM", for messages
	prepare() error                                    // make sure it's running
	stage(local string) (string, error)                // copy a downloaded engine in; returns its path there
	installed() (string, error)                        // path of the installed engine there
	run(bin string, args ...string) error              // run a binary there, output shown
	output(bin string, args ...string) (string, error) // run a binary there, stdout captured
}

// updateHooks are the per-platform steps around the engine update.
type updateHooks struct {
	target       func() update.Target
	preflight    func() error                                         // before anything changes (e.g. sudo)
	afterEngine  func(files map[string]string) error                  // after the engine is installed (Windows image context)
	replaceHost  func(files map[string]string, t update.Target) error // nil on Linux, where the engine is the host binary
	checkServers func() error
}

type updater struct {
	opts        UpdateOptions
	current     string
	client      *update.Client
	eh          engineHost
	hooks       updateHooks
	in          io.Reader
	out         io.Writer
	home        string // ~/.fox on this computer
	interactive bool
}

// Update runs `fox update`: it installs the newest release — the engine where it
// runs, restarted servers, Blackbox upgrades on running branches, and `fox` on
// this computer. Databases, branches, backups and settings are never touched.
func Update(opts UpdateOptions) error {
	eh := newEngineHost()
	u := &updater{
		opts:        opts,
		current:     version.Version,
		client:      update.NewClient(os.Getenv, updateCheckCache()),
		eh:          eh,
		hooks:       platformUpdateHooks(eh),
		in:          os.Stdin,
		out:         os.Stdout,
		home:        cacheDir(),
		interactive: update.IsTerminal(os.Stdin),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	return u.run(ctx)
}

func updateCheckCache() string { return filepath.Join(cacheDir(), "update-check.json") }

// StartUpdateNotice starts looking for a newer release in the background and
// returns a function that prints the one-line notice if one was found. `fox
// start` calls the function after its own output. It never delays start by more
// than the check timeout, and prints nothing when offline or on a development
// build; FOX_NO_UPDATE_CHECK=1 turns it off.
func StartUpdateNotice() func() {
	if !update.ShouldCheck(os.Getenv, version.Version) {
		return func() {}
	}
	t := update.Target{GOOS: runtime.GOOS, HostArch: runtime.GOARCH, GuestArch: runtime.GOARCH}
	if runtime.GOOS == "windows" {
		t.GuestArch = "amd64"
	}
	wait := update.BackgroundCheck(update.NewClient(os.Getenv, updateCheckCache()), version.Version, t, update.CheckTimeout(os.Getenv))
	return func() {
		if s := wait(); s != "" {
			fmt.Println()
			fmt.Println(s)
		}
	}
}

func (u *updater) printf(format string, args ...any) { fmt.Fprintf(u.out, format, args...) }

func reportedVersion(out string) (update.Version, error) {
	f := strings.Fields(out)
	if len(f) == 0 {
		return update.Version{}, fmt.Errorf("no version printed")
	}
	return update.ParseVersion(f[len(f)-1])
}

func (u *updater) run(ctx context.Context) error {
	cur, err := update.ParseVersion(u.current)
	if err != nil || cur.IsDev() {
		return fmt.Errorf("this is a development build (%s) — `fox update` updates installed releases; install one with the installer first", u.current)
	}
	t := u.hooks.target()
	u.printf("Checking for a newer FoxByte release…\n")
	o, err := u.client.Resolve(ctx, cur, t, u.opts.Version)
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}
	if o == nil {
		u.printf("FoxByte %s is up to date.\n", u.current)
		return nil
	}
	u.printf("FoxByte %s is available (you have %s).\n", o.Release.Tag, u.current)
	if o.Release.HTMLURL != "" {
		u.printf("  What's new: %s\n", o.Release.HTMLURL)
	}
	if u.opts.Check {
		u.printf("Run `fox update` to install it.\n")
		return nil
	}
	if !u.opts.Yes {
		if !u.interactive {
			return fmt.Errorf("not a terminal — run `fox update --yes` to update without the confirmation prompt")
		}
		u.printf("\nUpdate to %s now? The servers restart for a few seconds; your data is not touched. [y/N] ", o.Release.Tag)
		line, rerr := bufio.NewReader(u.in).ReadString('\n')
		a := strings.ToLower(strings.TrimSpace(line))
		if rerr != nil && a == "" {
			// No answer at all: stdin is closed (e.g. </dev/null, which looks like a terminal).
			return fmt.Errorf("no answer — run `fox update --yes` to update without the confirmation prompt")
		}
		if a != "y" && a != "yes" {
			u.printf("Not updated.\n")
			return nil
		}
	}

	if err := u.eh.prepare(); err != nil {
		return err
	}
	// On macOS the VM's CPU is only known for sure once it runs.
	if t2 := u.hooks.target(); t2 != t {
		t = t2
		if o, err = u.client.Resolve(ctx, cur, t, o.Release.Tag); err != nil {
			return fmt.Errorf("checking for updates: %w", err)
		} else if o == nil {
			return fmt.Errorf("the release has no build for this computer's VM (%s)", update.EngineAsset(t))
		}
	}
	installed, err := u.eh.installed()
	if err != nil {
		return err
	}

	total := 5
	if u.hooks.replaceHost != nil {
		total = 6
	}
	n := 0
	step := func(msg string) {
		n++
		u.printf("\n[%d/%d] %s\n", n, total, msg)
	}

	// 1. Download everything first: nothing changes unless all of it verifies.
	step(fmt.Sprintf("Downloading %s (checked against SHA256SUMS)", o.Release.Tag))
	dir := filepath.Join(u.home, "updates", o.Release.Tag)
	files := map[string]string{}
	for _, name := range o.Required {
		a, _ := o.Release.Asset(name)
		path, err := u.client.Download(ctx, a, o.Sums[name], dir)
		if err != nil {
			return fmt.Errorf("%w\nNothing was changed", err)
		}
		files[name] = path
		u.printf("  %s ✓\n", name)
	}

	// 2. The new engine must run where it will be installed (right CPU, not corrupt).
	step("Checking the new engine in " + u.eh.where())
	staged, err := u.eh.stage(files[update.EngineAsset(t)])
	if err != nil {
		return fmt.Errorf("copying the new engine into %s: %w\nNothing was changed", u.eh.where(), err)
	}
	out, err := u.eh.output(staged, "version")
	got, verr := reportedVersion(out)
	if err != nil || verr != nil || got.Compare(o.Version) != 0 {
		return fmt.Errorf("the new engine doesn't run in %s (it printed %q, err %v)\nNothing was changed", u.eh.where(), strings.TrimSpace(out), err)
	}
	u.printf("  engine %s runs ✓\n", got)
	if u.hooks.preflight != nil {
		if err := u.hooks.preflight(); err != nil {
			return fmt.Errorf("%w\nNothing was changed", err)
		}
	}

	// 3. The servers must stop: `start` leaves running ones alone. Postgres,
	// MinIO and branches keep running.
	step("Stopping the servers (databases keep running)")
	if err := u.eh.run(staged, "_update-guest", "stop-services"); err != nil {
		_ = u.eh.run(installed, "start")
		return fmt.Errorf("stopping the servers: %w\nNothing was changed", err)
	}

	// 4. Install the engine; on failure bring the servers back on the old one.
	step("Installing the new engine")
	if err := u.eh.run(staged, "_update-guest", "install-engine", "--src", staged, "--dest", installed); err != nil {
		u.printf("  installing failed — restarting the servers on %s\n", u.current)
		_ = u.eh.run(installed, "start")
		return fmt.Errorf("installing the new engine: %w\nFoxByte is still on %s", err, u.current)
	}
	if u.hooks.afterEngine != nil {
		if err := u.hooks.afterEngine(files); err != nil {
			u.printf("  note: %v\n", err)
		}
	}

	// 5. Restart on the new engine. `up` leaves running containers alone and
	// re-applies main's Blackbox; running branches get the new Blackbox too.
	step("Restarting on the new engine and upgrading Blackbox on running branches")
	if err := u.eh.run(installed, "up"); err != nil {
		return fmt.Errorf("the new engine is installed but `fox up` failed: %w\nFix the problem above, then run `fox start`", err)
	}
	ledgerOK := u.eh.run(installed, "ledger", "upgrade", "--all") == nil
	if !ledgerOK {
		u.printf("  note: some branches weren't upgraded — run `fox blackbox upgrade --all` later\n")
	}
	if err := u.eh.run(installed, "start"); err != nil {
		return fmt.Errorf("the new engine is installed but `fox start` failed: %w\nFix the problem above, then run `fox start`", err)
	}

	// 6. `fox` on this computer.
	if u.hooks.replaceHost != nil {
		step("Updating fox on this computer")
		if err := u.hooks.replaceHost(files, t); err != nil {
			return fmt.Errorf("the engine is on %s, but fox on this computer wasn't replaced: %w\nReinstall with the installer to finish (FOX_VERSION=%s)", o.Release.Tag, err, o.Release.Tag)
		}
	}

	if out, err := u.eh.output(installed, "version"); err != nil {
		u.printf("\nnote: couldn't read the engine version: %v\n", err)
	} else if v, err := reportedVersion(out); err != nil || v.Compare(o.Version) != 0 {
		u.printf("\nnote: the engine reports %q, expected %s\n", strings.TrimSpace(out), o.Version)
	}
	if u.hooks.checkServers != nil {
		if err := u.hooks.checkServers(); err != nil {
			u.printf("\nnote: the control plane isn't answering yet (%v) — check `fox status`\n", err)
		}
	}
	u.printf("\nDone — FoxByte is now %s. Your data was not touched.\n", o.Release.Tag)
	if o.Release.HTMLURL != "" {
		u.printf("  What's new: %s\n", o.Release.HTMLURL)
	}
	u.printf("  To go back, reinstall %s with the installer (FOX_VERSION=v%s); the previous binaries are kept in ~/.fox/updates/prev\n", u.current, u.current)
	return nil
}

// hostExecutable is the running fox, with symlinks resolved.
func hostExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return exe, nil
}

// refreshEngineCache replaces the engine `fox setup` would install from the
// cache with the new one, so a later setup doesn't bring the old engine back.
func refreshEngineCache(files map[string]string, t update.Target) {
	name := update.EngineAsset(t)
	dest := filepath.Join(cacheDir(), name)
	if err := os.MkdirAll(cacheDir(), 0o755); err == nil {
		_ = update.CopyFile(files[name], dest, 0o755)
	}
}

// checkControlPlane waits up to ~10s for the control plane to answer.
func checkControlPlane() error {
	c := &http.Client{
		Timeout: 2 * time.Second,
		// The local control plane uses a self-signed certificate; this only
		// checks that it answers.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	var last error
	for i := 0; i < 20; i++ {
		resp, err := c.Get("https://localhost:8080/api/status")
		if err == nil {
			resp.Body.Close()
			return nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	return last
}
