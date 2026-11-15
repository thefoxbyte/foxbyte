// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// A new install, whose store has no accounts when this code first runs,
// starts with main read-only for anybody not granted write, and stays so as
// accounts arrive.
func TestMainWriteNewInstallStartsGranted(t *testing.T) {
	s := testStore(t)
	if m, err := s.MainWriteMode(); err != nil || m != MainWriteGranted {
		t.Fatalf("mode = %q, %v; want granted", m, err)
	}
	if _, err := s.CreateUser("ada@example.com", "password1"); err != nil {
		t.Fatal(err)
	}
	// Opened again, as every process does: the recorded mode is kept.
	path := s.cfg.DBPath
	s2, err := Open(Config{DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if m, _ := s2.MainWriteMode(); m != MainWriteGranted {
		t.Errorf("after the first account, mode = %q; want granted", m)
	}
}

// An install that already had accounts is recorded as "all" when it upgrades,
// so nobody loses write until an admin switches; and the record stays put.
func TestMainWriteUpgradeIsRecordedAsAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	// The store as an older release left it: accounts, no main-write tables.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users(email, pw_hash, created) VALUES('old@example.com', '', 1)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(Config{DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := s.MainWriteMode(); m != MainWriteAll {
		t.Errorf("upgraded install: mode = %q; want all", m)
	}
	// Deleting every account does not turn it into a new install.
	u, _ := s.UserByEmail("old@example.com")
	if err := s.DeleteAccount(u.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(Config{DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if m, _ := s.MainWriteMode(); m != MainWriteAll {
		t.Errorf("reopened with no accounts: mode = %q; want all, as recorded", m)
	}
}

func TestMainWriteModeSetAndRefused(t *testing.T) {
	s := testStore(t)
	if err := s.SetMainWriteMode(MainWriteAll); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.MainWriteMode(); m != MainWriteAll {
		t.Errorf("mode = %q", m)
	}
	if err := s.SetMainWriteMode("everyone"); err == nil {
		t.Error("an unknown mode was accepted")
	}
	if m, _ := s.MainWriteMode(); m != MainWriteAll {
		t.Errorf("a refused mode changed it: %q", m)
	}
}

func TestMainWriteGrantAndRevoke(t *testing.T) {
	s := testStore(t)
	a, _ := s.CreateUser("ada@example.com", "password1")
	b, _ := s.CreateUser("Bob@Example.com", "password1")
	if err := s.GrantMainWrite(b.ID, "ada@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantMainWrite(b.ID, "someone-else"); err != nil { // twice: the first grant stays
		t.Fatal(err)
	}
	if err := s.GrantMainWrite(9999, "ada@example.com"); err == nil {
		t.Error("a grant to no account was accepted")
	}
	if ok, _ := s.HasMainWriteGrant(b.ID); !ok {
		t.Error("bob has no grant")
	}
	if ok, _ := s.HasMainWriteGrant(a.ID); ok {
		t.Error("ada has a grant nobody gave")
	}
	ws, err := s.MainWriters()
	if err != nil || len(ws) != 1 || ws[0].GrantedBy != "ada@example.com" {
		t.Fatalf("writers = %+v, %v", ws, err)
	}
	mode, emails, err := s.MainWriteState()
	if err != nil || mode != MainWriteGranted || strings.Join(emails, ",") != "bob@example.com" {
		t.Errorf("state = %q %v %v", mode, emails, err)
	}
	if had, _ := s.RevokeMainWrite(b.ID); !had {
		t.Error("revoke found no grant")
	}
	if had, _ := s.RevokeMainWrite(b.ID); had {
		t.Error("a second revoke found one")
	}
	if ok, _ := s.HasMainWriteGrant(b.ID); ok {
		t.Error("bob kept his grant")
	}
}

// A deleted account's grant goes with it: the address signed up again is
// somebody else, who has to be granted again.
func TestMainWriteGrantGoesWithTheAccount(t *testing.T) {
	s := testStore(t)
	b, _ := s.CreateUser("bob@example.com", "password1")
	_ = s.GrantMainWrite(b.ID, "admin")
	if err := s.DeleteAccount(b.ID); err != nil {
		t.Fatal(err)
	}
	b2, _ := s.CreateUser("bob@example.com", "password1")
	if ok, _ := s.HasMainWriteGrant(b2.ID); ok {
		t.Error("the new bob inherited the old one's grant")
	}
}

// The standby gets the mode and the grants, and a document from a node older
// than the tables leaves its own as they are.
func TestMainWriteTravelsToTheStandby(t *testing.T) {
	a, b := testStore(t), testStore(t)
	u, _ := a.CreateUser("bob@example.com", "password1")
	_ = a.SetMainWriteMode(MainWriteAll)
	_ = a.GrantMainWrite(u.ID, "admin")
	doc, _, err := a.SharedState()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ApplySharedState(doc); err != nil {
		t.Fatal(err)
	}
	if m, _ := b.MainWriteMode(); m != MainWriteAll {
		t.Errorf("standby mode = %q; want all", m)
	}
	if ok, _ := b.HasMainWriteGrant(u.ID); !ok {
		t.Error("the grant did not travel")
	}

	// An older sender carries neither table.
	old := strings.Replace(string(doc), `"install_settings"`, `"x_install_settings"`, 1)
	old = strings.Replace(old, `"main_writers"`, `"x_main_writers"`, 1)
	if _, err := b.ApplySharedState([]byte(old)); err != nil {
		t.Fatalf("an older document was refused: %v", err)
	}
	if m, _ := b.MainWriteMode(); m != MainWriteAll {
		t.Errorf("an older document changed the mode to %q", m)
	}
}
