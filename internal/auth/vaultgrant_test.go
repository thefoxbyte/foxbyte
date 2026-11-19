// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"testing"
	"time"
)

// A grant holds until revoked or expired; a new grant of the same permission
// on the same kind replaces the old one, which stays in the record.
func TestVaultGrants(t *testing.T) {
	s := testStore(t)
	g, err := s.GrantVault("KYC@x.com", "aadhaar", VaultDetokenise, 0, nil, "admin@x.com")
	if err != nil || g.Email != "kyc@x.com" || g.PerHour != VaultDefaultDetokenisePerHour || g.GrantedBy != "admin@x.com" {
		t.Fatalf("got %+v, %v", g, err)
	}
	u, _ := s.GrantVault("kyc@x.com", "aadhaar", VaultUse, 0, nil, "admin@x.com")
	if u.PerHour != VaultDefaultUsePerHour {
		t.Fatalf("use's default limit: %d", u.PerHour)
	}
	if _, err := s.HeldVaultGrant("kyc@x.com", "text", VaultDetokenise); err != ErrNoVaultGrant {
		t.Fatalf("a kind not granted: %v", err)
	}
	g2, err := s.GrantVault("kyc@x.com", "aadhaar", VaultDetokenise, 5, nil, "root")
	if err != nil {
		t.Fatal(err)
	}
	held, err := s.HeldVaultGrant("kyc@x.com", "aadhaar", VaultDetokenise)
	if err != nil || held.ID != g2.ID || held.PerHour != 5 {
		t.Fatalf("the newer grant holds: %+v, %v", held, err)
	}
	old, _ := s.VaultGrantByID(g.ID)
	if old.RevokedAt == nil || old.RevokedBy != "root" {
		t.Fatalf("the replaced grant is marked revoked, by whom: %+v", old)
	}
	if all, _ := s.VaultGrants(true); len(all) != 3 {
		t.Fatalf("every grant is kept: %d", len(all))
	}
	if now, _ := s.VaultGrants(false); len(now) != 2 {
		t.Fatalf("two hold: %d", len(now))
	}
	if _, err := s.RevokeVaultGrant(g2.ID, "admin@x.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeVaultGrant(g2.ID, "admin@x.com"); err != ErrNoVaultGrant {
		t.Fatalf("revoking twice: %v", err)
	}
	if _, err := s.HeldVaultGrant("kyc@x.com", "aadhaar", VaultDetokenise); err != ErrNoVaultGrant {
		t.Fatalf("a revoked grant still holds: %v", err)
	}
	if _, err := s.GrantVault("kyc@x.com", "aadhaar", "admin", 0, nil, "x"); err == nil {
		t.Fatal("a permission that is neither use nor detokenise was given")
	}
}

func TestVaultGrantExpires(t *testing.T) {
	s := testStore(t)
	past := time.Now().Add(-time.Minute)
	if _, err := s.GrantVault("a@x.com", "aadhaar", VaultUse, 0, &past, "x"); err == nil {
		t.Fatal("a grant that expired before it started was given")
	}
	soon := time.Now().Add(150 * time.Millisecond)
	g, err := s.GrantVault("a@x.com", "aadhaar", VaultUse, 0, &soon, "x")
	if err != nil || g.Expires == nil {
		t.Fatal(err)
	}
	if _, err := s.HeldVaultGrant("a@x.com", "aadhaar", VaultUse); err != nil {
		t.Fatal("before it expires, it holds")
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := s.HeldVaultGrant("a@x.com", "aadhaar", VaultUse); err != ErrNoVaultGrant {
		t.Fatalf("after it expires, it does not: %v", err)
	}
	if now, _ := s.VaultGrants(false); len(now) != 0 {
		t.Fatalf("an expired grant is listed as holding: %d", len(now))
	}
}

// Use is counted over the last hour, and the grant remembers when it was
// last used.
func TestVaultGrantUse(t *testing.T) {
	s := testStore(t)
	g, _ := s.GrantVault("a@x.com", "aadhaar", VaultDetokenise, 10, nil, "x")
	if g.LastUsed != nil || g.UsedLastHour != 0 {
		t.Fatalf("a new grant: %+v", g)
	}
	for _, n := range []int{3, 4} {
		if err := s.RecordVaultUse(g.ID, n); err != nil {
			t.Fatal(err)
		}
	}
	// A use from three hours ago no longer counts, and is dropped.
	if _, err := s.db.Exec(`INSERT INTO vault_grant_uses (grant_id, at, n) VALUES (?, ?, 50)`, g.ID, time.Now().Add(-3*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	held, _ := s.HeldVaultGrant("a@x.com", "aadhaar", VaultDetokenise)
	if held.UsedLastHour != 7 || held.LastUsed == nil {
		t.Fatalf("got %+v", held)
	}
	_ = s.RecordVaultUse(g.ID, 1)
	var rows int
	_ = s.db.QueryRow(`SELECT count(*) FROM vault_grant_uses`).Scan(&rows)
	if rows != 3 {
		t.Fatalf("uses older than two hours are dropped: %d rows", rows)
	}
}
