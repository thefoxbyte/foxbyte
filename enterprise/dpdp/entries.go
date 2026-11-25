//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package dpdp

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/enterprise/schema"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func init() { branch.SetDPDPInventory(set, remove) }

const timeout = 30 * time.Second

// historyEntry is the entry as the history keeps it: the row, in the shape
// branch.DPDPEntry reads back.
const historyEntry = `jsonb_build_object(
	'schema', schema_name, 'table', table_name, 'column', column_name,
	'basis', basis, 'purpose', purpose, 'principals', to_jsonb(principals),
	'keep', jsonb_build_object('count', keep_count, 'unit', keep_unit, 'from', keep_from,
		'reason', keep_reason, 'citation', keep_citation),
	'note', note, 'onErasure', on_erasure, 'clearTo', clear_to, 'setBy', set_by, 'setAt', set_at)`

// set records an entry, replacing the one at its place, and the change in
// the history, in one transaction. The entry has been checked
// (branch.CheckDPDPEntry) and its place holds confirmed personal data.
func set(name string, e branch.DPDPEntry, actor string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// A branch made before the licence covered the inventory gains its
	// tables here, not only at its next start.
	if err := schema.EnsureDPDP(name); err != nil {
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
	k := e.Keep
	if _, err := tx.Exec(ctx, `WITH r AS (
			INSERT INTO bb.dpdp_entries AS d (schema_name, table_name, column_name, basis, purpose, principals,
				keep_count, keep_unit, keep_from, keep_reason, keep_citation, note, set_by, set_at, on_erasure, clear_to)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now(), $14, $15)
			ON CONFLICT (schema_name, table_name, column_name) DO UPDATE SET
				basis = EXCLUDED.basis, purpose = EXCLUDED.purpose, principals = EXCLUDED.principals,
				keep_count = EXCLUDED.keep_count, keep_unit = EXCLUDED.keep_unit, keep_from = EXCLUDED.keep_from,
				keep_reason = EXCLUDED.keep_reason, keep_citation = EXCLUDED.keep_citation, note = EXCLUDED.note,
				set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at,
				on_erasure = EXCLUDED.on_erasure, clear_to = EXCLUDED.clear_to
			RETURNING *)
		INSERT INTO bb.dpdp_history (schema_name, table_name, column_name, action, entry, actor)
		SELECT schema_name, table_name, column_name, 'set', `+historyEntry+`, $13 FROM r`,
		e.Schema, e.Table, e.Column, e.Basis, e.Purpose, e.Principals,
		k.Count, k.Unit, k.From, k.Reason, k.Citation, e.Note, actor, e.OnErasure, e.ClearTo); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// remove deletes the entry at a place and keeps it in the history.
func remove(name, schemaName, table, column, actor string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var have bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('bb.dpdp_entries') IS NOT NULL").Scan(&have); err != nil {
		return err
	}
	if !have {
		return branch.ErrNoDPDPEntry
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	var id int64
	err = tx.QueryRow(ctx, `WITH r AS (
			DELETE FROM bb.dpdp_entries WHERE schema_name = $1 AND table_name = $2 AND column_name = $3 RETURNING *)
		INSERT INTO bb.dpdp_history (schema_name, table_name, column_name, action, entry, actor)
		SELECT schema_name, table_name, column_name, 'removed', `+historyEntry+`, $4 FROM r
		RETURNING id`, schemaName, table, column, actor).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return branch.ErrNoDPDPEntry
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
