//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/enterprise/schema"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Keeping it current (point 4.7): what appears after a branch's first scan is
// unclassified until a person has looked at it.

func init() { branch.SetPIIInventory(accept) }

// accept records that a person looked at a new column or path and it holds
// nothing to classify. Its findings, if it has any, are decided one by one
// instead, with the evidence in front of whoever decides; deciding the last of
// them reviews the place too (followInventory).
func accept(name string, id int64, note, actor string) error {
	ctx, cancel := context.WithTimeout(context.Background(), reviewTimeout)
	defer cancel()
	if err := schema.EnsurePII(name); err != nil {
		return err
	}
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	var status, where, by string
	err = tx.QueryRow(ctx, `SELECT status, schema_name || '.' || table_name || '.' || column_name
			|| CASE WHEN json_path = '' THEN '' ELSE ' ' || json_path END, reviewed_by
		FROM bb.pii_columns WHERE id = $1 FOR UPDATE`, id).Scan(&status, &where, &by)
	if errors.Is(err, pgx.ErrNoRows) {
		return branch.ErrNoColumn
	}
	if err != nil {
		return err
	}
	var undecided int
	if err := tx.QueryRow(ctx, `SELECT count(*)::int FROM bb.pii_findings f JOIN bb.pii_columns c
			ON (f.schema_name, f.table_name, f.column_name, f.json_path) = (c.schema_name, c.table_name, c.column_name, c.json_path)
		WHERE c.id = $1 AND f.state = 'suggested'`, id).Scan(&undecided); err != nil {
		return err
	}
	switch {
	case status == branch.PIIKnown:
		return fmt.Errorf("%w: %s was there at the branch's first scan; its findings are reviewed as findings", branch.ErrInvalidRequest, where)
	case status == branch.PIIReviewed:
		return fmt.Errorf("%w: %s is already reviewed, by %s", branch.ErrInvalidRequest, where, by)
	case undecided > 0:
		return fmt.Errorf("%w: %d finding(s) at %s are undecided; decide each with: fox pii mark <id> confirm|reject", branch.ErrUndecided, undecided, where)
	}
	if note == "" {
		note = "nothing to classify"
	}
	if _, err := tx.Exec(ctx, `UPDATE bb.pii_columns SET status = 'reviewed', reviewed_by = $2, reviewed_at = now(), note = $3 WHERE id = $1`,
		id, actor, note); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bb.pii_column_reviews (column_id, status, actor, note) VALUES ($1, 'reviewed', $2, $3)`,
		id, actor, note); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
