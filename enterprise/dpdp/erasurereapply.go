//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package dpdp

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/enterprise/schema"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Applying a request again to a copy restored from before it (F4, Gate 1
// step 4; design, section 12). The request keeps no value, so nothing is
// searched: the rows it changed are found by the keys it kept and changed as
// its plan said, in one transaction; the Blackbox entries it redacted are
// redacted again by id, the originals beside the chain it deleted deleted
// again; the Aadhaar exposure report's places in those rows go too. Settle
// rewrites the tables after.

func erasureReapply(target string, a branch.ErasureReapply) (branch.ErasureResult, error) {
	res := branch.ErasureResult{Applied: time.Now().UTC(), By: a.Actor, Tables: []branch.ErasureDone{}, Rewrites: []branch.ErasureRewrite{},
		Notes: []string{"Found by the keys the request kept, as it keeps no value: a search for the values was not run on the copy."}}
	if err := schema.EnsureDPDP(target); err != nil {
		return res, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), eraseTimeout)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, target)
	if err != nil {
		return res, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SELECT set_config('statement_timeout', '5min', true), set_config('lock_timeout', '30s', true), "+
		"set_config('bb.actor', $1, true)", a.Actor); err != nil {
		return res, err
	}
	cat := &catalog{ctx: ctx, tx: tx, rels: map[tkey]*relInfo{}}
	planned := map[tkey]branch.ErasureTable{}
	for _, t := range a.Plan.Tables {
		planned[tkey{t.Schema, t.Table}] = t
	}
	// Clears first, then deletes the deepest first, as the apply did.
	done := append([]branch.ErasureDone(nil), a.Done...)
	rank := func(d branch.ErasureDone) int {
		if d.Action == branch.ErasureActClear {
			return -1
		}
		return -planned[tkey{d.Schema, d.Table}].Depth
	}
	sort.SliceStable(done, func(i, j int) bool { return rank(done[i]) < rank(done[j]) })

	var places int
	for _, d := range done {
		k := tkey{d.Schema, d.Table}
		if d.Action == branch.ErasureActSetNull {
			continue // the foreign key's own ON DELETE SET NULL, with the deletes
		}
		if d.Rows > 0 && len(d.Keys) == 0 {
			return res, fmt.Errorf("%s: the request changed %d row(s) there with no key to find them by, so they cannot be found again without the values", k, d.Rows)
		}
		if len(d.Keys) == 0 {
			continue
		}
		rel, err := cat.rel(k)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: not in the copy (%v), so nothing of it to erase", k, err))
			continue
		}
		if len(rel.keyCols) == 0 {
			return res, fmt.Errorf("%s has no primary key or replica identity in the copy, so the request's rows cannot be found in it", k)
		}
		keys := make([]string, len(d.Keys))
		for i, x := range d.Keys {
			keys[i] = string(x)
		}
		ids, found, err := rowsByKey(ctx, tx, rel, keys)
		if err != nil {
			return res, fmt.Errorf("finding the request's rows in %s: %w", k, readErr(err))
		}
		names, err := oidNames(ctx, tx, ids)
		if err != nil {
			return res, err
		}
		n := 0
		switch d.Action {
		case branch.ErasureActClear:
			dc, err := reapplySets(rel, planned[k].Columns)
			if err != nil {
				return res, fmt.Errorf("%s: %w", k, err)
			}
			if n, err = clearRows(ctx, tx, names, dc, ids); err != nil {
				return res, fmt.Errorf("clearing %s again (nothing was applied): %w", k, readErr(err))
			}
		case branch.ErasureActDelete, branch.ErasureActCascade:
			// A row a cascade was to take may be gone with its parent already.
			if n, err = execByRow(ctx, tx, names, ids, func(rel string) string { return "DELETE FROM " + rel + " WHERE ctid = ANY($1::text[]::tid[])" }); err != nil {
				return res, fmt.Errorf("deleting from %s again (nothing was applied): %w", k, readErr(err))
			}
		default:
			continue
		}
		m, err := deleteAadhaarPlacesByKey(ctx, tx, k, rel.keyCols, found, d.Action, planned[k].Columns)
		if err != nil {
			return res, fmt.Errorf("removing %s's Aadhaar report places (nothing was applied): %w", k, readErr(err))
		}
		places += m
		res.Rows += n
		res.Tables = append(res.Tables, branch.ErasureDone{Schema: d.Schema, Table: d.Table, Action: d.Action, Rows: n, KeyColumns: rel.keyCols, Keys: d.Keys})
	}
	res.AadhaarPlaces = places
	var bbRewrites []branch.ErasureRewrite
	if len(a.Redact) > 0 || len(a.Originals) > 0 {
		var red branch.ErasureTextDone
		var entry *int64
		if err := tx.QueryRow(ctx, "SELECT redacted, entry, originals FROM bb.erasure_redact_ids($1, $2, $3)",
			fmt.Sprintf("erasure request #%d, applied again after a restore", a.ID), a.Redact, a.Originals).Scan(&red.Redacted, &entry, &red.Originals); err != nil {
			return res, fmt.Errorf("redacting the copy's Blackbox (nothing was applied): %w", readErr(err))
		}
		if entry != nil {
			red.Entry = *entry
		}
		red.Flagged = []int64{}
		res.Blackbox = &red
		if bbRewrites, err = blackboxRewrites(ctx, tx, &red); err != nil {
			return res, fmt.Errorf("sizing the copy's Blackbox tables (nothing was applied): %w", readErr(err))
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bb.erasures_applied (request_uid, request_id, rows) VALUES ($1, $2, $3)
		ON CONFLICT (request_uid) DO NOTHING`, a.UID, a.ID, res.Rows); err != nil {
		return res, fmt.Errorf("recording the erasure on the copy (nothing was applied): %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("committing the erasure on the copy: %w", err)
	}
	// Every table the request changed is rewritten in the copy, whatever its
	// size: the copy is closed until it is.
	seen := map[tkey]bool{}
	for _, t := range res.Tables {
		k := tkey{t.Schema, t.Table}
		if seen[k] {
			continue
		}
		seen[k] = true
		res.Rewrites = append(res.Rewrites, branch.ErasureRewrite{Schema: t.Schema, Table: t.Table, Size: planned[k].Size, State: branch.RewritePending})
	}
	res.Rewrites = append(res.Rewrites, bbRewrites...)
	res.Verified = false
	return res, nil
}

// rowsByKey finds a table's rows by the keys a request kept, locked.
func rowsByKey(ctx context.Context, tx pgx.Tx, rel *relInfo, keys []string) ([]rowID, []string, error) {
	q := "SELECT x.tableoid, x.ctid::text, " + rel.keyExpr("x") + " FROM " + rel.rel + " x WHERE " + keyMatch(rel, "x") + " FOR UPDATE"
	rows, err := tx.Query(ctx, q, keys)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var ids []rowID
	var found []string
	for rows.Next() {
		var id rowID
		var key string
		if err := rows.Scan(&id.oid, &id.ctid, &key); err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
		found = append(found, key)
	}
	return ids, found, rows.Err()
}

func oidNames(ctx context.Context, tx pgx.Tx, ids []rowID) (map[uint32]string, error) {
	out := map[uint32]string{}
	for _, id := range ids {
		if _, ok := out[id.oid]; ok {
			continue
		}
		var n string
		if err := tx.QueryRow(ctx, "SELECT $1::oid::regclass::text", id.oid).Scan(&n); err != nil {
			return nil, err
		}
		out[id.oid] = n
	}
	return out, nil
}

// reapplySets is what a clear sets, from the plan's columns as the request
// kept them: NULL, DEFAULT, a placeholder in quotes, or a JSON path cleared.
func reapplySets(rel *relInfo, cols []branch.ErasureColumn) (*decided, error) {
	d := &decided{act: branch.ErasureActClear, columns: cols, paths: map[string][]string{}}
	for _, c := range cols {
		info, ok := rel.cols[c.Column]
		if !ok {
			return nil, fmt.Errorf("the column %s the request cleared is not in the copy", c.Column)
		}
		if c.Path != "" {
			d.paths[c.Column] = append(d.paths[c.Column], c.Path)
			continue
		}
		switch {
		case c.To == "NULL":
			d.sets = append(d.sets, setCol{col: c.Column, expr: "NULL"})
		case c.To == "DEFAULT":
			d.sets = append(d.sets, setCol{col: c.Column, expr: "DEFAULT"})
		case strings.HasPrefix(c.To, `"`):
			v, err := strconv.Unquote(c.To)
			if err != nil {
				return nil, fmt.Errorf("the placeholder %s of %s cannot be read: %v", c.To, c.Column, err)
			}
			d.sets = append(d.sets, setCol{col: c.Column, expr: "$" + info.typ, arg: &v})
		default:
			return nil, fmt.Errorf("the request cleared %s to %q, which cannot be applied again", c.Column, c.To)
		}
	}
	return d, nil
}

// deleteAadhaarPlacesByKey removes the Aadhaar exposure report's places in
// rows found again by key: every place of a row deleted, a cleared row's
// places in the columns cleared.
func deleteAadhaarPlacesByKey(ctx context.Context, tx pgx.Tx, k tkey, keyCols, keys []string, action string, cols []branch.ErasureColumn) (int, error) {
	var have bool
	if err := tx.QueryRow(ctx, "SELECT to_regclass('bb.aadhaar_places') IS NOT NULL").Scan(&have); err != nil || !have || len(keys) == 0 {
		return 0, err
	}
	var rks []string
	for _, key := range keys {
		if rk, ok := aadhaarRowKey(keyCols, key); ok {
			rks = append(rks, rk)
		}
	}
	if len(rks) == 0 {
		return 0, nil
	}
	q := "DELETE FROM bb.aadhaar_places WHERE schema_name = $1 AND table_name = $2 AND row_key = ANY($3)"
	args := []any{k.schema, k.table, rks}
	if action == branch.ErasureActClear {
		var cs []string
		for _, c := range cols {
			cs = append(cs, c.Column)
		}
		if len(cs) == 0 {
			return 0, nil
		}
		q += " AND column_name = ANY($4)"
		args = append(args, cs)
	}
	tag, err := tx.Exec(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
