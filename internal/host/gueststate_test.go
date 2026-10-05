// SPDX-License-Identifier: AGPL-3.0-or-later

package host

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/brand"
)

func TestStateNameIsChecked(t *testing.T) {
	for _, ok := range []string{"license.json", "a", "a-b_c.2"} {
		if err := checkStateName(ok); err != nil {
			t.Errorf("checkStateName(%q) = %v, want nil", ok, err)
		}
	}
	// Each of these would mean something to a shell, or somewhere other than
	// the state directory.
	for _, bad := range []string{"", ".", "..", "../license.json", "a/b", "a b", "a;rm -rf /", "$HOME", "a\"b", "a`b`"} {
		if err := checkStateName(bad); err == nil {
			t.Errorf("checkStateName(%q) = nil, want an error", bad)
		}
	}
}

// runGuestScript runs a generated snippet the way the guest shell would, with a
// home directory of its own. The scripts are the part of this that cannot be
// checked by compiling, so they are run rather than string-matched.
func runGuestScript(t *testing.T, home, script string, stdin []byte) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX shell to run the guest script with")
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s\n--- script ---\n%s", err, out, script)
	}
}

func TestGuestStateWriteLandsTheFilePrivately(t *testing.T) {
	home := t.TempDir()
	runGuestScript(t, home, guestStateWriteScript("license.json"), []byte(`{"id":"FB-1"}`))

	dir := filepath.Join(home, brand.StateDirName)
	path := filepath.Join(dir, "license.json")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading what the script wrote: %v", err)
	}
	if string(got) != `{"id":"FB-1"}` {
		t.Errorf("content = %q", got)
	}
	// 0600 in a 0700 directory, the same as the host side writes it. A licence
	// names a customer, and the guest is not necessarily a single-user machine.
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v (err %v), want 0600", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v (err %v), want 0700", fi.Mode().Perm(), err)
	}
	// Nothing half-written is left behind.
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Errorf("the temporary file survived the rename")
	}
}

// The regression this guards: creating ~/.fox in a guest that still has a
// retired state directory would strand that install's accounts, keys and
// anchors, because brand.resolveStateDir only moves the old directory while the
// new one does not exist. Handing the engine a licence must not cost it its
// data.
func TestGuestStateWriteDoesNotStrandARetiredDirectory(t *testing.T) {
	if len(brand.Previous) == 0 {
		t.Skip("no retired names to strand")
	}
	old := ""
	for _, p := range brand.Previous {
		if p.StateDir != "" {
			old = p.StateDir
			break
		}
	}
	if old == "" {
		t.Skip("no retired state directory to strand")
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, old), 0o700); err != nil {
		t.Fatal(err)
	}
	runGuestScript(t, home, guestStateWriteScript("license.json"), []byte("x"))

	if _, err := os.Stat(filepath.Join(home, old, "license.json")); err != nil {
		t.Errorf("the licence did not land in the retired directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, brand.StateDirName)); !os.IsNotExist(err) {
		t.Errorf("%s was created alongside %s, which is what strands it", brand.StateDirName, old)
	}
}

func TestGuestStateRemove(t *testing.T) {
	home := t.TempDir()
	runGuestScript(t, home, guestStateWriteScript("license.json"), []byte("x"))
	runGuestScript(t, home, guestStateRemoveScript("license.json"), nil)
	if _, err := os.Stat(filepath.Join(home, brand.StateDirName, "license.json")); !os.IsNotExist(err) {
		t.Errorf("the licence survived the remove")
	}
	// Removing what was never there is how `fox license remove` behaves on this
	// side too: it says "removed", it does not fail.
	runGuestScript(t, home, guestStateRemoveScript("license.json"), nil)
}

// The scripts resolve $HOME in the guest rather than carrying a path from the
// host. On Lima the engine's state is in the guest user's home — /root/.fox
// does not exist — so a path computed here would be the wrong one.
func TestGuestStateScriptsResolveTheGuestHome(t *testing.T) {
	for _, s := range []string{guestStateWriteScript("license.json"), guestStateRemoveScript("license.json")} {
		if !strings.Contains(s, `"$HOME/`+brand.StateDirName+`"`) {
			t.Errorf("script does not resolve $HOME in the guest:\n%s", s)
		}
		if strings.Contains(s, os.Getenv("HOME")) && os.Getenv("HOME") != "" {
			t.Errorf("script carries this machine's home into the guest:\n%s", s)
		}
	}
}
