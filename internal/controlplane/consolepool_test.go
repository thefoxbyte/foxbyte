// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

func loginCfg(t *testing.T, addr, user, password string) *pgx.ConnConfig {
	t.Helper()
	cfg, err := pgx.ParseConfig("postgres://" + addr + "/appdb")
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = user, password
	return cfg
}

func resetPools(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		for _, b := range []string{"dev", "prod"} {
			closeConsolePools(b)
		}
	})
}

// One user's pooled session is never another's: a pool is one login on one
// branch, and every connection it makes logs in as that login.
func TestConsolePoolIsolatesLogins(t *testing.T) {
	resetPools(t)
	alice, err := poolFor("dev", loginCfg(t, "10.0.0.1:5432", "alice@example.com", "a"), 4)
	if err != nil {
		t.Fatal(err)
	}
	bob, _ := poolFor("dev", loginCfg(t, "10.0.0.1:5432", "bob@example.com", "b"), 4)
	shared, _ := poolFor("dev", loginCfg(t, "10.0.0.1:5432", "db_client", "c"), 4)
	again, _ := poolFor("dev", loginCfg(t, "10.0.0.1:5432", "alice@example.com", "a"), 4)
	otherBranch, _ := poolFor("prod", loginCfg(t, "10.0.0.1:5432", "alice@example.com", "a"), 4)
	newPassword, _ := poolFor("dev", loginCfg(t, "10.0.0.1:5432", "alice@example.com", "rotated"), 4)
	moved, _ := poolFor("dev", loginCfg(t, "10.0.0.9:5432", "alice@example.com", "a"), 4)

	if alice != again {
		t.Error("the same login on the same branch should reuse its pool")
	}
	for name, p := range map[string]any{"bob": bob, "the shared role": shared, "another branch": otherBranch,
		"a changed password": newPassword, "a new address": moved} {
		if p == any(alice) {
			t.Errorf("alice's pool was handed out for %s", name)
		}
	}
	if u := alice.Config().ConnConfig.User; u != "alice@example.com" {
		t.Errorf("alice's pool logs in as %q", u)
	}
	if u := bob.Config().ConnConfig.User; u != "bob@example.com" {
		t.Errorf("bob's pool logs in as %q", u)
	}
	if pw := newPassword.Config().ConnConfig.Password; pw != "rotated" {
		t.Errorf("a pool logs in with the password it was made with, got %q", pw)
	}
}

// The pool keeps its own copy of the login: changing the config a request
// built afterwards cannot change who the pool's connections are.
func TestConsolePoolCopiesTheLogin(t *testing.T) {
	resetPools(t)
	cfg := loginCfg(t, "10.0.0.1:5432", "alice@example.com", "a")
	p, err := poolFor("dev", cfg, 4)
	if err != nil {
		t.Fatal(err)
	}
	cfg.User = "mallory@example.com"
	if u := p.Config().ConnConfig.User; u != "alice@example.com" {
		t.Fatalf("the pool now logs in as %q", u)
	}
	if p.Config().AfterRelease == nil {
		t.Fatal("a pooled session must be reset before it is reused")
	}
}

// Suspending or deleting a branch closes its pools, and only its pools.
func TestCloseConsolePoolsForOneBranch(t *testing.T) {
	resetPools(t)
	dev, _ := poolFor("dev", loginCfg(t, "10.0.0.1:5432", "alice@example.com", "a"), 4)
	prod, _ := poolFor("prod", loginCfg(t, "10.0.0.2:5432", "alice@example.com", "a"), 4)
	closeConsolePools("dev")
	if again, _ := poolFor("dev", loginCfg(t, "10.0.0.1:5432", "alice@example.com", "a"), 4); again == dev {
		t.Error("dev's pool survived its branch being closed")
	}
	if again, _ := poolFor("prod", loginCfg(t, "10.0.0.2:5432", "alice@example.com", "a"), 4); again != prod {
		t.Error("closing dev closed prod's pool too")
	}
}

func TestConsolePoolSettings(t *testing.T) {
	t.Setenv("FOX_CONSOLE_POOL_SIZE", "")
	if consolePoolSize() != 4 {
		t.Error("default pool size")
	}
	for _, off := range []string{"0", "off"} {
		t.Setenv("FOX_CONSOLE_POOL_SIZE", off)
		if consolePoolSize() != 0 {
			t.Errorf("%q should turn pooling off", off)
		}
	}
	t.Setenv("FOX_CONSOLE_STATEMENT_TIMEOUT", "")
	if consoleStatementTimeout() != DefaultConsoleStatementTimeout {
		t.Error("default statement timeout")
	}
}
