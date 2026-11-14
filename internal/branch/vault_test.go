// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

func TestVaultAddrs(t *testing.T) {
	db, svc, err := vaultAddrs("172.29.213.0/29")
	if err != nil || db != "172.29.213.2" || svc != "172.29.213.3" {
		t.Fatalf("got %s %s %v", db, svc, err)
	}
	// Written loosely, the network's own address is still found.
	if db, svc, _ = vaultAddrs("10.9.8.7/24"); db != "10.9.8.2" || svc != "10.9.8.3" {
		t.Fatalf("got %s %s", db, svc)
	}
	for _, bad := range []string{"", "fd00::/64", "10.0.0.0/30", "10.0.0.1"} {
		if _, _, err := vaultAddrs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The database admits the service's role from the service's address, and
// rejects everything else: the machine reaches an internal network through
// its bridge (design, section 20).
func TestVaultHBAPinsTheService(t *testing.T) {
	h := vaultHBA("172.29.213.3")
	lines := []string{}
	for _, l := range strings.Split(h, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	want := []string{"local all all trust", "host vault vault_svc 172.29.213.3/32 scram-sha-256", "host all all all reject"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", lines)
	}
}

// The init script reads the service's password from the environment: no
// secret is written into a file a container reads, or onto a command line.
func TestVaultDBInitHasNoSecret(t *testing.T) {
	if !strings.Contains(vaultDBInit, "'$FOX_VAULT_SVC_PASSWORD'") || strings.Contains(vaultDBInit, "PASSWORD=") {
		t.Fatal(vaultDBInit)
	}
}

func TestVaultSummary(t *testing.T) {
	if s := vaultSummary(vaultReply{Results: []string{"done", "refused", "done"}}); s != "done 2, refused 1" {
		t.Fatal(s)
	}
	if s := vaultSummary(vaultReply{Error: "no kind \"pan\""}); s != `refused: no kind "pan"` {
		t.Fatal(s)
	}
}

func fakeVault(t *testing.T, logAt func(seq int64) (string, bool, error)) {
	t.Helper()
	old := vaulter
	t.Cleanup(func() { vaulter = old })
	vaulter = &Vaulter{
		Call: func(socket, secret, actor, path string, body []byte) ([]byte, string, int, error) {
			return []byte(`{"refs":["AR00000000000000000000000001"],"results":["done"]}`), "7:" + strings.Repeat("a", 64), 200, nil
		},
		Status: func(socket, secret string) ([]byte, error) { return []byte(`{}`), nil },
		LogAt:  func(socket, secret string, seq int64) (string, bool, error) { return logAt(seq) },
		Kinds:  func() []VaultKind { return nil },
	}
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(vaultPath("secret"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath("secret", "secret"), []byte("s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func store(t *testing.T) *auth.Store {
	t.Helper()
	s, err := auth.Open(auth.Config{DBPath: filepath.Join(t.TempDir(), "a.db"), WebOrigin: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// The head the security log keeps is checked against the vault's log: the
// same entry holds; an entry no longer there, or changed, does not.
func TestVaultAnchor(t *testing.T) {
	h7 := "7:" + strings.Repeat("a", 64)
	st := store(t)
	fakeVault(t, func(seq int64) (string, bool, error) { return h7, true, nil })
	if a := vaultCheckAnchor(st); !a.Holds || !strings.Contains(a.Note, "no call") {
		t.Fatalf("with nothing recorded: %+v", a)
	}
	st.Audit(auth.EvVaultCall, "op", "aadhaar", "", "find, 1 value: done 1; head "+h7)
	if a := vaultCheckAnchor(st); !a.Holds || a.Recorded != h7 {
		t.Fatalf("the same head: %+v", a)
	}
	fakeVault(t, func(seq int64) (string, bool, error) { return "", false, nil })
	if a := vaultCheckAnchor(st); a.Holds || !strings.Contains(a.Note, "cut off its end") {
		t.Fatalf("an entry gone: %+v", a)
	}
	// A vault set up again starts a log of its own: the old vault's head is
	// not held against it.
	st.Audit(auth.EvVaultSetup, "op", "", "", "set up")
	if a := vaultCheckAnchor(st); !a.Holds || !strings.Contains(a.Note, "no call") {
		t.Fatalf("after a new setup: %+v", a)
	}
	st.Audit(auth.EvVaultCall, "op", "aadhaar", "", "find, 1 value: done 1; head "+h7)
	fakeVault(t, func(seq int64) (string, bool, error) { return "7:" + strings.Repeat("b", 64), true, nil })
	if a := vaultCheckAnchor(st); a.Holds || !strings.Contains(a.Note, "not what the security log saw") {
		t.Fatalf("an entry changed: %+v", a)
	}
}
