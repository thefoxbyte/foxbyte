//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package dpdp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Retention acted on (point 11.3): the rows of a table whose period, as its
// inventory entry gives it, has ended. They are found by the date in a
// column the admin names, never by a value, and erased as an erasure
// request erases rows, by key, limited to that table: another table's rows
// follow their own retention, except what a foreign key takes with a delete.

// retentionPlan is a retention run's plan, read-only.
func retentionPlan(name, only string, seed branch.ErasureSeed, actor string) (branch.ErasurePlan, string, branch.ErasureSeed, error) {
	return planWith(name, nil, nil, actor, seed, nil, buildOpts{only: only, retention: true})
}

// dateTypes are the column types a start date can be read from.
var dateTypes = []string{"date", "timestamp without time zone", "timestamp with time zone"}

// retentionDue finds a table's rows dated before the cutoff, oldest first.
func retentionDue(name string, q branch.RetentionQuery) (branch.RetentionDue, error) {
	due := branch.RetentionDue{Schema: q.Schema, Table: q.Table, Column: q.Column, Cutoff: q.Cutoff, Rows: []branch.RetentionRow{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return due, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return due, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '1min'"); err != nil {
		return due, err
	}
	cat := &catalog{ctx: ctx, tx: tx, rels: map[tkey]*relInfo{}}
	rel, err := cat.rel(tkey{q.Schema, q.Table})
	if err != nil {
		return due, fmt.Errorf("%s.%s: %w", q.Schema, q.Table, err)
	}
	if len(rel.keyCols) == 0 {
		return due, fmt.Errorf("%s.%s has no primary key or replica identity, so its rows cannot be named to erase them", q.Schema, q.Table)
	}
	info, ok := rel.cols[q.Column]
	if !ok {
		return due, fmt.Errorf("%s.%s has no column %s", q.Schema, q.Table, q.Column)
	}
	if !contains(dateTypes, info.typ) {
		return due, fmt.Errorf("%s.%s.%s is a %s, not a date or a timestamp, so it cannot say when a row's period began", q.Schema, q.Table, q.Column, info.typ)
	}
	due.KeyColumns = rel.keyCols
	col := "x." + branch.QuoteIdent(q.Column)
	// A row retention erased already keeps its date when it was cleared:
	// it is left out, by key, compared as JSON.
	past := col + "::timestamptz < $1 AND NOT (" + strings.TrimSuffix(rel.keyExpr("x"), "::text") + " = ANY($2::jsonb[]))"
	exclude := q.Exclude
	if exclude == nil {
		exclude = []string{}
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FILTER (WHERE "+past+"), count(*) FILTER (WHERE "+col+" IS NULL) FROM "+rel.rel+" x",
		q.Cutoff, exclude).Scan(&due.Total, &due.Undated); err != nil {
		return due, readErr(err)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := tx.Query(ctx, "SELECT "+rel.keyExpr("x")+", "+col+"::timestamptz FROM "+rel.rel+" x WHERE "+past+" ORDER BY "+col+" LIMIT $3",
		q.Cutoff, exclude, limit)
	if err != nil {
		return due, readErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var r branch.RetentionRow
		if err := rows.Scan(&r.Key, &r.Since); err != nil {
			return due, err
		}
		r.Key = strings.TrimSpace(r.Key)
		due.Rows = append(due.Rows, r)
	}
	return due, rows.Err()
}
