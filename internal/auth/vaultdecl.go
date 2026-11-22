// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// The customer's declarations about their vault (point 13, step 13.4b;
// docs/FOX_P13_Vault_Design.md, section 14): what the rules ask that FoxByte
// cannot check from the machine, such as the HSM's certificate or the network
// zone around it, stated by an admin or the operator and kept with who said
// it and when. The evidence shows each as declared, never as checked. Every
// statement is kept: a new one for the same item replaces it in the
// evidence, and a withdrawal (an empty value) leaves the item open again.

const vaultDeclSchema = `
CREATE TABLE IF NOT EXISTS vault_declarations (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  kind        TEXT NOT NULL,
  item        TEXT NOT NULL,
  value       TEXT NOT NULL,
  declared_by TEXT NOT NULL,
  declared_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS vault_declarations_item ON vault_declarations (kind, item, id);
`

// VaultDeclaration is one statement. Value "" is a withdrawal.
type VaultDeclaration struct {
	ID         int64     `json:"id"`
	Kind       string    `json:"kind"`
	Item       string    `json:"item"`
	Value      string    `json:"value"`
	DeclaredBy string    `json:"declared_by"`
	DeclaredAt time.Time `json:"declared_at"`
}

// MaxVaultDeclaration is the longest a statement may be.
const MaxVaultDeclaration = 2000

// ErrVaultDeclaration is a statement that cannot be kept.
var ErrVaultDeclaration = errors.New("not a declaration")

// DeclareVault keeps a statement about a kind's item; value "" withdraws it.
func (s *Store) DeclareVault(kind, item, value, by string) (VaultDeclaration, error) {
	d := VaultDeclaration{Kind: kind, Item: item, Value: strings.TrimSpace(value), DeclaredBy: by, DeclaredAt: time.Now().UTC().Truncate(time.Millisecond)}
	if kind == "" || item == "" || by == "" || len(d.Value) > MaxVaultDeclaration {
		return d, ErrVaultDeclaration
	}
	res, err := s.db.Exec(`INSERT INTO vault_declarations (kind, item, value, declared_by, declared_at) VALUES (?, ?, ?, ?, ?)`,
		d.Kind, d.Item, d.Value, d.DeclaredBy, d.DeclaredAt.UnixMilli())
	if err != nil {
		return d, err
	}
	d.ID, err = res.LastInsertId()
	return d, err
}

// VaultDeclarations are a kind's statements ("" for every kind): the current
// one for each item, withdrawals left out, or with all, every statement
// ever made, newest first.
func (s *Store) VaultDeclarations(kind string, all bool) ([]VaultDeclaration, error) {
	q := `SELECT id, kind, item, value, declared_by, declared_at FROM vault_declarations d
		WHERE (? = '' OR kind = ?)
		  AND id = (SELECT max(id) FROM vault_declarations x WHERE x.kind = d.kind AND x.item = d.item)
		  AND value <> ''
		ORDER BY kind, item`
	if all {
		q = `SELECT id, kind, item, value, declared_by, declared_at FROM vault_declarations
			WHERE (? = '' OR kind = ?) ORDER BY id DESC`
	}
	rows, err := s.db.Query(q, kind, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VaultDeclaration{}
	for rows.Next() {
		var d VaultDeclaration
		var at int64
		if err := rows.Scan(&d.ID, &d.Kind, &d.Item, &d.Value, &d.DeclaredBy, &at); err != nil {
			return nil, err
		}
		d.DeclaredAt = time.UnixMilli(at).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// VaultDeclarationOf is an item's current statement, nil when none holds.
func (s *Store) VaultDeclarationOf(kind, item string) (*VaultDeclaration, error) {
	var d VaultDeclaration
	var at int64
	err := s.db.QueryRow(`SELECT id, kind, item, value, declared_by, declared_at FROM vault_declarations
		WHERE kind = ? AND item = ? ORDER BY id DESC LIMIT 1`, kind, item).Scan(&d.ID, &d.Kind, &d.Item, &d.Value, &d.DeclaredBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if d.Value == "" {
		return nil, nil
	}
	d.DeclaredAt = time.UnixMilli(at).UTC()
	return &d, nil
}
