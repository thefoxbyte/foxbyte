// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Editing a table's rows in the console's data grid (point 12.2): the rows
// added, changed and deleted on screen, saved together.
//
//   - One transaction. Every change is applied or none is: a save that fails
//     at its fifth change leaves the table as it was.
//   - Only a table with a primary key. The key is what says which row a
//     change is for; without one there is no honest answer.
//   - The row as it was loaded. An update changes a row only if the columns
//     it changes still hold what the grid showed, and a delete only a row that
//     is still there: otherwise someone else got there first, and the save
//     stops rather than overwrite their change.
//   - As the person editing. The statements run as the signed-in user's own
//     role, so grants, row-level security, the guardrails and (with point 7)
//     masking apply exactly as they do to SQL typed in the console.
//   - Built here, not sent as SQL. The table, its columns and its key are
//     checked against the catalog, every name is quoted, and every value is
//     a parameter cast to its column's type: nothing the browser sends
//     becomes SQL text.

// RowChange is one change to one row. A value is a string as the grid edits
// it, or null for SQL NULL.
type RowChange struct {
	Op     string             `json:"op"`               // insert, update or delete
	Key    map[string]*string `json:"key,omitempty"`    // the row's primary key (update, delete)
	Values map[string]*string `json:"values,omitempty"` // the new values (insert, update)
	// Old holds what the grid showed for the columns an update changes; the
	// update applies only while the row still holds them.
	Old map[string]*string `json:"old,omitempty"`
}

// RowEdit is a save: the changes to one table.
type RowEdit struct {
	Schema  string      `json:"schema"`
	Table   string      `json:"table"`
	Changes []RowChange `json:"changes"`
}

// RowEditResult says what a save did.
type RowEditResult struct {
	Inserted int `json:"inserted"`
	Updated  int `json:"updated"`
	Deleted  int `json:"deleted"`
}

const maxRowChanges = 1000

// ErrRowGone means an update or a delete found its row changed or deleted
// since the grid loaded it.
var ErrRowGone = errors.New("the row was changed or deleted since it was loaded: reload and try again")

type editCol struct {
	typ       string
	generated bool
	identity  string // a: always, d: by default
}

// tableForEdit reads what a save needs to know about a table: its columns and
// its primary key, checked in the catalog.
func tableForEdit(ctx context.Context, tx pgx.Tx, schema, table string) (map[string]editCol, []string, error) {
	var oid uint32
	err := tx.QueryRow(ctx, `SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r','p')`, schema, table).Scan(&oid)
	if err != nil {
		return nil, nil, fmt.Errorf("no table %s.%s on this branch", schema, table)
	}
	rows, err := tx.Query(ctx, `SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attgenerated <> '', a.attidentity::text
		FROM pg_attribute a WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped`, oid)
	if err != nil {
		return nil, nil, err
	}
	cols := map[string]editCol{}
	for rows.Next() {
		var name string
		var c editCol
		if err := rows.Scan(&name, &c.typ, &c.generated, &c.identity); err != nil {
			rows.Close()
			return nil, nil, err
		}
		cols[name] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	krows, err := tx.Query(ctx, `SELECT a.attname FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
		WHERE i.indrelid = $1::oid AND i.indisprimary ORDER BY array_position(i.indkey::int2[], a.attnum)`, oid)
	if err != nil {
		return nil, nil, err
	}
	var key []string
	for krows.Next() {
		var k string
		if err := krows.Scan(&k); err != nil {
			krows.Close()
			return nil, nil, err
		}
		key = append(key, k)
	}
	krows.Close()
	if len(key) == 0 {
		return nil, nil, fmt.Errorf("%s.%s has no primary key, so a row cannot be told apart from another: edit it with SQL", schema, table)
	}
	return cols, key, krows.Err()
}

// rowStatements turns one change into its statement and parameters, checking
// every column against the table. Pure, so every rule is a unit test.
func rowStatement(qtable string, cols map[string]editCol, key []string, c RowChange) (string, []any, error) {
	var args []any
	param := func(col string, v *string) string {
		if v == nil {
			args = append(args, nil)
		} else {
			args = append(args, *v)
		}
		return fmt.Sprintf("CAST($%d::text AS %s)", len(args), cols[col].typ)
	}
	settable := func(m map[string]*string) ([]string, error) {
		names := make([]string, 0, len(m))
		for n := range m {
			col, ok := cols[n]
			switch {
			case !ok:
				return nil, fmt.Errorf("there is no column %q", n)
			case col.generated:
				return nil, fmt.Errorf("%q is generated from other columns and cannot be set", n)
			case col.identity == "a":
				return nil, fmt.Errorf("%q is an identity column (GENERATED ALWAYS) and cannot be set", n)
			}
			names = append(names, n)
		}
		sort.Strings(names) // the same change gives the same statement
		return names, nil
	}
	where := func() (string, error) {
		if len(c.Key) != len(key) {
			return "", fmt.Errorf("a row is named by its primary key (%s)", strings.Join(key, ", "))
		}
		var parts []string
		for _, k := range key {
			v, ok := c.Key[k]
			if !ok || v == nil {
				return "", fmt.Errorf("a row is named by its primary key (%s)", strings.Join(key, ", "))
			}
			parts = append(parts, quoteIdent(k)+" = "+param(k, v))
		}
		return strings.Join(parts, " AND "), nil
	}
	switch c.Op {
	case "insert":
		names, err := settable(c.Values)
		if err != nil {
			return "", nil, err
		}
		if len(names) == 0 {
			return "INSERT INTO " + qtable + " DEFAULT VALUES", nil, nil
		}
		var cs, vs []string
		for _, n := range names {
			cs = append(cs, quoteIdent(n))
			vs = append(vs, param(n, c.Values[n]))
		}
		return "INSERT INTO " + qtable + " (" + strings.Join(cs, ", ") + ") VALUES (" + strings.Join(vs, ", ") + ")", args, nil
	case "update":
		names, err := settable(c.Values)
		if err != nil {
			return "", nil, err
		}
		if len(names) == 0 {
			return "", nil, errors.New("an update changes at least one column")
		}
		var sets []string
		for _, n := range names {
			sets = append(sets, quoteIdent(n)+" = "+param(n, c.Values[n]))
		}
		w, err := where()
		if err != nil {
			return "", nil, err
		}
		// The row as it was loaded: each column being changed still holds
		// what the grid showed.
		for _, n := range names {
			if old, ok := c.Old[n]; ok {
				w += " AND " + quoteIdent(n) + " IS NOT DISTINCT FROM " + param(n, old)
			}
		}
		return "UPDATE " + qtable + " SET " + strings.Join(sets, ", ") + " WHERE " + w, args, nil
	case "delete":
		w, err := where()
		if err != nil {
			return "", nil, err
		}
		return "DELETE FROM " + qtable + " WHERE " + w, args, nil
	}
	return "", nil, fmt.Errorf("a change is insert, update or delete, not %q", c.Op)
}

// applyRowEdits saves a grid's changes in one transaction.
func applyRowEdits(ctx context.Context, conn *pgx.Conn, e RowEdit) (RowEditResult, error) {
	var res RowEditResult
	switch {
	case len(e.Changes) == 0:
		return res, errors.New("there is nothing to save")
	case len(e.Changes) > maxRowChanges:
		return res, fmt.Errorf("at most %d changes in one save", maxRowChanges)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)
	cols, key, err := tableForEdit(ctx, tx, e.Schema, e.Table)
	if err != nil {
		return res, err
	}
	qtable := quoteIdent(e.Schema) + "." + quoteIdent(e.Table)
	for i, c := range e.Changes {
		stmt, args, err := rowStatement(qtable, cols, key, c)
		if err != nil {
			return RowEditResult{}, fmt.Errorf("change %d (%s): %w", i+1, c.Op, err)
		}
		tag, err := tx.Exec(ctx, stmt, args...)
		if err != nil {
			return RowEditResult{}, fmt.Errorf("change %d (%s): %w", i+1, c.Op, err)
		}
		if c.Op != "insert" && tag.RowsAffected() != 1 {
			return RowEditResult{}, fmt.Errorf("change %d (%s): %w", i+1, c.Op, ErrRowGone)
		}
		switch c.Op {
		case "insert":
			res.Inserted++
		case "update":
			res.Updated++
		case "delete":
			res.Deleted++
		}
	}
	return res, tx.Commit(ctx)
}

// handleRowEdits is POST /api/branches/{name}/rows: a grid's changes to one
// table, saved together as the signed-in user.
func handleRowEdits(w http.ResponseWriter, r *http.Request) {
	var e RowEdit
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		writeErr(w, 400, fmt.Errorf("the body must be JSON: {\"schema\", \"table\", \"changes\": [...]}"))
		return
	}
	if e.Schema == "" {
		e.Schema = "public"
	}
	withUserSession(w, r, func(ctx context.Context, conn *pgx.Conn) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		res, err := applyRowEdits(ctx, conn, e)
		if err != nil {
			out := map[string]any{"error": err.Error()}
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Detail != "" {
				out["detail"] = pg.Detail
			}
			status := 400
			if errors.Is(err, ErrRowGone) {
				status = 409
			}
			writeJSON(w, status, out)
			return
		}
		writeJSON(w, 200, res)
	})
}
