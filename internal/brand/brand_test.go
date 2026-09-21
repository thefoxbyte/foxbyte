// SPDX-License-Identifier: AGPL-3.0-or-later

package brand

import (
	"os"
	"path/filepath"
	"testing"
)

// A variable set under a retired prefix must still be read. Someone's shell
// profile, CI job or MCP client config should not stop working because the
// product was renamed.
func TestGetenvFallsBackToRetiredPrefixes(t *testing.T) {
	if len(Previous) == 0 {
		t.Skip("no retired names")
	}
	old := Previous[0].EnvPrefix

	t.Setenv(EnvPrefix+"API_KEY", "current")
	t.Setenv(old+"API_KEY", "retired")
	if got := Getenv("API_KEY"); got != "current" {
		t.Errorf("the current prefix should win: got %q", got)
	}

	os.Unsetenv(EnvPrefix + "API_KEY")
	if got := Getenv("API_KEY"); got != "retired" {
		t.Errorf("a retired prefix should still be read: got %q", got)
	}
	if got := GetenvFull(EnvPrefix + "API_KEY"); got != "retired" {
		t.Errorf("GetenvFull should fall back too: got %q", got)
	}
	if got := Getenv("NOT_SET_ANYWHERE"); got != "" {
		t.Errorf("an unset variable should be empty: got %q", got)
	}
	// A name that is not ours is read as given, with no fallback invented.
	t.Setenv("PATH_TO_NOWHERE", "x")
	if got := GetenvFull("PATH_TO_NOWHERE"); got != "x" {
		t.Errorf("a foreign variable should be read as-is: got %q", got)
	}
}

// After a rename the engine must keep its accounts, keys, secrets and anchors:
// the state directory moves with the brand rather than being abandoned. Losing
// it would leave the object store's credentials out of step with its data.
func TestStateDirMovesFromARetiredName(t *testing.T) {
	if len(Previous) == 0 {
		t.Skip("no retired names")
	}
	retired := Previous[0].StateDir

	t.Run("moves a retired directory", func(t *testing.T) {
		home := t.TempDir()
		old := filepath.Join(home, retired)
		if err := os.MkdirAll(old, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(old, "secrets.json"), []byte(`{"pg_password":"p"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		got := resolveStateDir(home)
		if want := filepath.Join(home, StateDirName); got != want {
			t.Fatalf("state dir = %q, want %q", got, want)
		}
		if _, err := os.Stat(filepath.Join(got, "secrets.json")); err != nil {
			t.Errorf("the secrets did not come across: %v", err)
		}
		if _, err := os.Stat(old); !os.IsNotExist(err) {
			t.Errorf("the retired directory should be gone, got %v", err)
		}
	})

	t.Run("leaves the current directory alone", func(t *testing.T) {
		home := t.TempDir()
		cur := filepath.Join(home, StateDirName)
		if err := os.MkdirAll(cur, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cur, "secrets.json"), []byte("current"), 0o600); err != nil {
			t.Fatal(err)
		}
		// A retired directory alongside it must not overwrite anything.
		if err := os.MkdirAll(filepath.Join(home, retired), 0o700); err != nil {
			t.Fatal(err)
		}
		if got := resolveStateDir(home); got != cur {
			t.Fatalf("state dir = %q, want %q", got, cur)
		}
		b, err := os.ReadFile(filepath.Join(cur, "secrets.json"))
		if err != nil || string(b) != "current" {
			t.Errorf("the current secrets were disturbed: %q, %v", b, err)
		}
	})

	t.Run("nothing to move", func(t *testing.T) {
		home := t.TempDir()
		if got, want := resolveStateDir(home), filepath.Join(home, StateDirName); got != want {
			t.Errorf("state dir = %q, want %q", got, want)
		}
	})
}

// The generated constants must be usable as a product identity.
func TestConstantsAreSane(t *testing.T) {
	if Product == "" || CLI == "" || Slug == "" {
		t.Fatal("the product is not named")
	}
	if Title() == "" || RepoURL() == "https://github.com/" {
		t.Error("Title and RepoURL should be built from the brand")
	}
	if EnvName("API_KEY") != EnvPrefix+"API_KEY" {
		t.Errorf("EnvName = %q", EnvName("API_KEY"))
	}
}
