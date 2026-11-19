// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The vault's grants (point 13, step 13.2; docs/FOX_P13_Vault_Design.md,
// section 9): which account may put values of a kind in the vault and find
// their reference keys (use), and which may read values back (detokenise).
// Only admins grant them, and the machine's operator; being an admin grants
// neither. Each detokenise grant carries a limit an hour; each grant may carry
// an expiry. A grant is never deleted: revoking one marks it, so the access
// review can say who held what, and when.

const vaultGrantSchema = `
CREATE TABLE IF NOT EXISTS vault_grants (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  email       TEXT NOT NULL COLLATE NOCASE,
  kind        TEXT NOT NULL,
  permission  TEXT NOT NULL CHECK (permission IN ('use', 'detokenise')),
  per_hour    INTEGER NOT NULL CHECK (per_hour > 0),
  expires_at  INTEGER,
  granted_by  TEXT NOT NULL,
  granted_at  INTEGER NOT NULL,
  revoked_by  TEXT,
  revoked_at  INTEGER,
  last_used   INTEGER
);
CREATE INDEX IF NOT EXISTS vault_grants_who ON vault_grants (email, kind, permission);
CREATE TABLE IF NOT EXISTS vault_grant_uses (
  grant_id INTEGER NOT NULL REFERENCES vault_grants (id),
  at       INTEGER NOT NULL,
  n        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS vault_grant_uses_at ON vault_grant_uses (grant_id, at);
`

// The two permissions.
const (
	VaultUse        = "use"
	VaultDetokenise = "detokenise"
)

// Default limits an hour: reading values back is what a limit is for (100);
// putting values in and finding keys is what applications do in bulk.
const (
	VaultDefaultDetokenisePerHour = 100
	VaultDefaultUsePerHour        = 100000
)

// VaultGrant is one grant.
type VaultGrant struct {
	ID         int64      `json:"id"`
	Email      string     `json:"email"`
	Kind       string     `json:"kind"`
	Permission string     `json:"permission"`
	PerHour    int        `json:"per_hour"`
	Expires    *time.Time `json:"expires,omitempty"`
	GrantedBy  string     `json:"granted_by"`
	GrantedAt  time.Time  `json:"granted_at"`
	RevokedBy  string     `json:"revoked_by,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsed   *time.Time `json:"last_used,omitempty"`
	// UsedLastHour is how many values the grant read or put in over the last
	// hour, against PerHour.
	UsedLastHour int `json:"used_last_hour"`
}

// Active reports whether the grant holds now.
func (g VaultGrant) Active(now time.Time) bool {
	return g.RevokedAt == nil && (g.Expires == nil || now.Before(*g.Expires))
}

// ErrNoVaultGrant is a grant that does not exist, or no longer holds.
var ErrNoVaultGrant = errors.New("no such vault grant")

// ValidVaultPermission reports whether p is use or detokenise.
func ValidVaultPermission(p string) bool { return p == VaultUse || p == VaultDetokenise }

func msPtr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64).UTC()
	return &t
}

const vaultGrantCols = `id, email, kind, permission, per_hour, expires_at, granted_by, granted_at, revoked_by, revoked_at, last_used`

func scanVaultGrant(sc interface{ Scan(...any) error }) (VaultGrant, error) {
	var g VaultGrant
	var expires, revokedAt, lastUsed sql.NullInt64
	var revokedBy sql.NullString
	var granted int64
	if err := sc.Scan(&g.ID, &g.Email, &g.Kind, &g.Permission, &g.PerHour, &expires, &g.GrantedBy, &granted, &revokedBy, &revokedAt, &lastUsed); err != nil {
		return g, err
	}
	g.Expires, g.RevokedAt, g.LastUsed = msPtr(expires), msPtr(revokedAt), msPtr(lastUsed)
	g.RevokedBy = revokedBy.String
	g.GrantedAt = time.UnixMilli(granted).UTC()
	return g, nil
}

// GrantVault gives email a permission on a kind. A grant of the same
// permission on the same kind that still holds is replaced: revoked by the
// same actor, so the record shows the change. perHour 0 takes the default.
func (s *Store) GrantVault(email, kind, permission string, perHour int, expires *time.Time, by string) (VaultGrant, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || kind == "" || !ValidVaultPermission(permission) {
		return VaultGrant{}, fmt.Errorf("a grant names an account, a kind, and use or detokenise")
	}
	if perHour < 0 {
		return VaultGrant{}, fmt.Errorf("a limit an hour is a positive number")
	}
	if perHour == 0 {
		perHour = VaultDefaultUsePerHour
		if permission == VaultDetokenise {
			perHour = VaultDefaultDetokenisePerHour
		}
	}
	now := time.Now().UTC()
	if expires != nil && !expires.After(now) {
		return VaultGrant{}, fmt.Errorf("the grant would expire before it starts")
	}
	var id int64
	err := retryBusy(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`UPDATE vault_grants SET revoked_by = ?, revoked_at = ?
			WHERE email = ? AND kind = ? AND permission = ? AND revoked_at IS NULL`, by, now.UnixMilli(), email, kind, permission); err != nil {
			return err
		}
		var exp any
		if expires != nil {
			exp = expires.UTC().UnixMilli()
		}
		res, err := tx.Exec(`INSERT INTO vault_grants (email, kind, permission, per_hour, expires_at, granted_by, granted_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, email, kind, permission, perHour, exp, by, now.UnixMilli())
		if err != nil {
			return err
		}
		if id, err = res.LastInsertId(); err != nil {
			return err
		}
		return tx.Commit()
	})
	if err != nil {
		return VaultGrant{}, err
	}
	return s.VaultGrantByID(id)
}

// VaultGrantByID reads one grant, with its use over the last hour.
func (s *Store) VaultGrantByID(id int64) (VaultGrant, error) {
	g, err := scanVaultGrant(s.db.QueryRow(`SELECT `+vaultGrantCols+` FROM vault_grants WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return g, ErrNoVaultGrant
	}
	if err != nil {
		return g, err
	}
	g.UsedLastHour, err = s.vaultUsedSince(g.ID, time.Now().Add(-time.Hour))
	return g, err
}

// RevokeVaultGrant ends a grant that still holds.
func (s *Store) RevokeVaultGrant(id int64, by string) (VaultGrant, error) {
	var n int64
	err := retryBusy(func() error {
		res, err := s.db.Exec(`UPDATE vault_grants SET revoked_by = ?, revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
			by, time.Now().UTC().UnixMilli(), id)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return VaultGrant{}, err
	}
	if n == 0 {
		return VaultGrant{}, ErrNoVaultGrant
	}
	return s.VaultGrantByID(id)
}

// VaultGrants lists grants, newest first: those that still hold, or every one
// ever made with all.
func (s *Store) VaultGrants(all bool) ([]VaultGrant, error) {
	q := `SELECT ` + vaultGrantCols + ` FROM vault_grants`
	if !all {
		q += ` WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`
	}
	q += ` ORDER BY id DESC`
	var rows *sql.Rows
	var err error
	if all {
		rows, err = s.db.Query(q)
	} else {
		rows, err = s.db.Query(q, time.Now().UTC().UnixMilli())
	}
	if err != nil {
		return nil, err
	}
	var out []VaultGrant
	for rows.Next() {
		g, err := scanVaultGrant(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	since := time.Now().Add(-time.Hour)
	for i := range out {
		if out[i].UsedLastHour, err = s.vaultUsedSince(out[i].ID, since); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// VaultGrantsOf lists the grants that hold now for one account.
func (s *Store) VaultGrantsOf(email string) ([]VaultGrant, error) {
	all, err := s.VaultGrants(false)
	if err != nil {
		return nil, err
	}
	var out []VaultGrant
	for _, g := range all {
		if strings.EqualFold(g.Email, email) {
			out = append(out, g)
		}
	}
	return out, nil
}

// HeldVaultGrant is the grant that holds now for email's permission on kind.
func (s *Store) HeldVaultGrant(email, kind, permission string) (VaultGrant, error) {
	g, err := scanVaultGrant(s.db.QueryRow(`SELECT `+vaultGrantCols+` FROM vault_grants
		WHERE email = ? AND kind = ? AND permission = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY id DESC LIMIT 1`, strings.ToLower(strings.TrimSpace(email)), kind, permission, time.Now().UTC().UnixMilli()))
	if errors.Is(err, sql.ErrNoRows) {
		return g, ErrNoVaultGrant
	}
	if err != nil {
		return g, err
	}
	g.UsedLastHour, err = s.vaultUsedSince(g.ID, time.Now().Add(-time.Hour))
	return g, err
}

func (s *Store) vaultUsedSince(id int64, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT coalesce(sum(n), 0) FROM vault_grant_uses WHERE grant_id = ? AND at > ?`, id, since.UnixMilli()).Scan(&n)
	return n, err
}

// RecordVaultUse counts n values against a grant, and keeps when it was last
// used. Uses older than two hours are dropped as it goes: the limit is an
// hour's, and last_used keeps the rest.
func (s *Store) RecordVaultUse(id int64, n int) error {
	now := time.Now().UTC()
	return retryBusy(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`INSERT INTO vault_grant_uses (grant_id, at, n) VALUES (?, ?, ?)`, id, now.UnixMilli(), n); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE vault_grants SET last_used = ? WHERE id = ?`, now.UnixMilli(), id); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM vault_grant_uses WHERE at < ?`, now.Add(-2*time.Hour).UnixMilli()); err != nil {
			return err
		}
		return tx.Commit()
	})
}
