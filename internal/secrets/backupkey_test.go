// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "fox-secrets-test-")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home)
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

// The backup key is made once and then only read: a second process asking for
// it, or a later start, must get the same key, or new backups would be
// encrypted with a key the old ones do not open.
func TestBackupKey(t *testing.T) {
	if _, err := BackupKey(); !errors.Is(err, ErrNoBackupKey) {
		t.Fatalf("before any key: %v", err)
	}
	k, err := EnsureBackupKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckBackupKey(k); err != nil {
		t.Fatalf("generated key %v", err)
	}
	if again, _ := EnsureBackupKey(); again != k {
		t.Fatal("EnsureBackupKey made a second key")
	}
	if fi, err := os.Stat(BackupKeyPath()); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v, want 0600", fi.Mode().Perm())
	}
	if id := BackupKeyID(k); len(id) != 16 || strings.Contains(k, id) {
		t.Errorf("key id %q", id)
	}

	// Import: the same key is a no-op, a different one is refused unless
	// replacing is asked for, and a malformed one is refused outright.
	if err := ImportBackupKey(k+"\n", false); err != nil {
		t.Errorf("importing the same key: %v", err)
	}
	other := strings.Repeat("ab", 32)
	if err := ImportBackupKey(other, false); err == nil {
		t.Error("a different key replaced the one here without --replace")
	}
	if err := ImportBackupKey("short", true); err == nil {
		t.Error("a malformed key was accepted")
	}
	if err := ImportBackupKey(other, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := BackupKey(); got != other {
		t.Error("the replaced key did not take")
	}
}
