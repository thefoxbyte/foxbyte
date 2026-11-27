//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package dpdp

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Searching a branch again for a request (F4, Gate 1 step 5; design,
// section 15). The request keeps no value, so its rows are found by the keys
// it kept, read-only: a row it deleted is counted if it is there again, and a
// row it cleared if a column it cleared holds a value again. A column
// cleared to its default is not compared: the default may be anything.

func erasureRecheck(name string, plan branch.ErasurePlan, done []branch.ErasureDone) ([]branch.RecheckTable, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SELECT set_config('statement_timeout', '1min', true)"); err != nil {
		return nil, err
	}
	cat := &catalog{ctx: ctx, tx: tx, rels: map[tkey]*relInfo{}}
	planned := map[tkey]branch.ErasureTable{}
	for _, t := range plan.Tables {
		planned[tkey{t.Schema, t.Table}] = t
	}
	out := []branch.RecheckTable{}
	for _, d := range done {
		if d.Action == branch.ErasureActSetNull || len(d.Keys) == 0 {
			continue
		}
		k := tkey{d.Schema, d.Table}
		t := branch.RecheckTable{Schema: d.Schema, Table: d.Table, Action: d.Action, Keys: len(d.Keys)}
		rel, err := cat.rel(k)
		if err != nil {
			t.Note = "not on the branch now, so nothing of it to find"
			out = append(out, t)
			continue
		}
		if len(rel.keyCols) == 0 {
			t.Note = "no primary key or replica identity now, so its rows cannot be found by key"
			out = append(out, t)
			continue
		}
		keys := make([]string, len(d.Keys))
		for i, x := range d.Keys {
			keys[i] = string(x)
		}
		switch d.Action {
		case branch.ErasureActDelete, branch.ErasureActCascade:
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+rel.rel+" x WHERE "+keyMatch(rel, "x"), keys).Scan(&t.Found); err != nil {
				return nil, fmt.Errorf("searching %s again: %w", k, readErr(err))
			}
		case branch.ErasureActClear:
			n, note, err := recheckCleared(ctx, tx, rel, keys, planned[k].Columns)
			if err != nil {
				return nil, fmt.Errorf("searching %s again: %w", k, readErr(err))
			}
			t.Found, t.Note = n, note
		default:
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// recheckCleared counts a table's cleared rows, found by key, in which a
// column the request cleared holds a value again.
func recheckCleared(ctx context.Context, tx pgx.Tx, rel *relInfo, keys []string, cols []branch.ErasureColumn) (int, string, error) {
	type check struct {
		col   string
		null  bool     // cleared to NULL
		want  *string  // cleared to this placeholder
		paths []string // JSON paths cleared
	}
	var checks []check
	byCol := map[string]int{}
	var notes []string
	for _, c := range cols {
		if _, ok := rel.cols[c.Column]; !ok {
			notes = append(notes, c.Column+" is not on the branch now")
			continue
		}
		i, ok := byCol[c.Column]
		if !ok {
			checks = append(checks, check{col: c.Column})
			i = len(checks) - 1
			byCol[c.Column] = i
		}
		switch {
		case c.Path != "":
			checks[i].paths = append(checks[i].paths, c.Path)
		case c.To == "NULL":
			checks[i].null = true
		case c.To == "DEFAULT":
			notes = append(notes, c.Column+" was cleared to its default, which is not compared")
		case strings.HasPrefix(c.To, `"`):
			if v, err := strconv.Unquote(c.To); err == nil {
				checks[i].want = &v
			}
		}
	}
	if len(checks) == 0 {
		return 0, strings.Join(notes, "; "), nil
	}
	reads := make([]string, len(checks))
	for i, c := range checks {
		reads[i] = "x." + branch.QuoteIdent(c.col) + "::text"
	}
	rows, err := tx.Query(ctx, "SELECT "+strings.Join(reads, ", ")+" FROM "+rel.rel+" x WHERE "+keyMatch(rel, "x"), keys)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	found := 0
	for rows.Next() {
		vals := make([]*string, len(checks))
		dest := make([]any, len(checks))
		for i := range vals {
			dest[i] = &vals[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return 0, "", err
		}
		for i, c := range checks {
			if holdsAgain(vals[i], c.null, c.want, c.paths) {
				found++
				break
			}
		}
	}
	return found, strings.Join(notes, "; "), rows.Err()
}

// holdsAgain judges one cleared column's value now.
func holdsAgain(v *string, null bool, want *string, paths []string) bool {
	if v == nil {
		return false
	}
	if len(paths) > 0 {
		cleared, err := clearJSONPaths(*v, paths)
		if err != nil {
			return true // not the document it was: count it, to be looked at
		}
		return !sameJSON(*v, cleared)
	}
	if null {
		return true
	}
	if want != nil {
		return *v != *want
	}
	return false
}

func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return a == b
	}
	return reflect.DeepEqual(x, y)
}
