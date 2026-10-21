//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/enterprise/schema"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func init() { branch.SetPIIScanner(scan) }

const (
	// scanTimeout bounds a whole scan; tableTimeout one table's read.
	scanTimeout  = 15 * time.Minute
	tableTimeout = "30s"
)

// column is one column of a table, as the catalog describes it.
type column struct {
	name    string
	typcat  string // pg_type.typcategory: S strings, N numbers, D dates, I network…
	typname string
}

type table struct {
	schema, name string
	kind         string // pg_class.relkind
	rows         int64  // the planner's estimate
	cols         []column
}

func (t table) ref() string   { return branch.QuoteIdent(t.schema) + "." + branch.QuoteIdent(t.name) }
func (t table) label() string { return t.schema + "." + t.name }

// scan reads a sample of every table on a branch and records what it finds.
//
// As the superuser, inside read-only transactions with a time limit each, so a
// scan can neither change anything nor hang on one large table. As the
// superuser because a scan that obeyed row-level security would report a
// branch clean while rows it could not see held exactly what it was looking
// for; reading is all it does with that, and what it keeps is counts.
func scan(name string, o branch.PIIScanOptions) (branch.PIIScan, error) {
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	if err := schema.EnsurePII(name); err != nil {
		return branch.PIIScan{}, err
	}
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return branch.PIIScan{}, err
	}
	defer conn.Close(context.Background())

	s := branch.PIIScan{Started: time.Now().UTC(), Actor: o.Actor, Sample: o.Sample, Skipped: []branch.PIISkip{}}
	tables, err := catalog(ctx, conn)
	if err != nil {
		return s, fmt.Errorf("reading the catalog: %w", err)
	}

	type found struct {
		t   table
		col string
		sig Signal
	}
	var all []found
	sawJSON, sawSampled := false, false
	for _, t := range tables {
		if t.kind == "f" {
			s.Skipped = append(s.Skipped, branch.PIISkip{Object: t.label(), Reason: "a foreign table: its data is held somewhere else"})
			continue
		}
		var read []column
		for _, c := range t.cols {
			switch {
			case c.typname == "json" || c.typname == "jsonb":
				sawJSON = true
				// Its name still says something; its documents are step 4.2.
				for _, sig := range Classify(c.name, "-", nil) {
					all = append(all, found{t, c.name, sig})
				}
			case strings.ContainsAny(c.typcat, "SNDI") && c.typcat != "":
				read = append(read, c)
			default:
				// bytea, uuid, booleans, arrays…: no value to read as an
				// identifier, but a column called aadhaar holding ciphertext
				// is still a finding worth a reviewer's time.
				for _, sig := range Classify(c.name, "-", nil) {
					all = append(all, found{t, c.name, sig})
				}
			}
		}
		if len(read) == 0 {
			continue
		}
		samples, sampled, err := sample(ctx, conn, t, read, o.Sample)
		if err != nil {
			s.Skipped = append(s.Skipped, branch.PIISkip{Object: t.label(), Reason: readFailure(err)})
			continue
		}
		if sampled {
			sawSampled = true
		}
		s.Tables++
		s.Columns += len(read)
		for i, c := range read {
			for _, sig := range Classify(c.name, c.typcat, samples[i]) {
				all = append(all, found{t, c.name, sig})
			}
			samples[i] = nil // done with the values; nothing below needs them
		}
	}

	s.Limits = limits(o.Sample, sawSampled, sawJSON)
	s.Finished = time.Now().UTC()

	// One transaction, so a scan's findings and its record appear together or
	// not at all.
	tx, err := conn.Begin(ctx)
	if err != nil {
		return s, err
	}
	defer tx.Rollback(context.Background())
	skipped, _ := json.Marshal(s.Skipped)
	lims, _ := json.Marshal(s.Limits)
	if err := tx.QueryRow(ctx, `INSERT INTO bb.pii_scans
			(started_at, finished_at, actor, sample_size, tables_scanned, columns_scanned, skipped, limits)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		s.Started, s.Finished, s.Actor, s.Sample, s.Tables, s.Columns, skipped, lims).Scan(&s.ID); err != nil {
		return s, fmt.Errorf("recording the scan: %w", err)
	}
	for _, f := range all {
		// A finding found again keeps its state: a reviewer's decision is
		// not undone by the next scan (step 4.6 makes them).
		if _, err := tx.Exec(ctx, `INSERT INTO bb.pii_findings
				(schema_name, table_name, column_name, json_path, category, rule, confidence, why,
				 matched, sampled, first_scan, last_scan)
				VALUES ($1, $2, $3, '', $4, $5, $6, $7, $8, $9, $10, $10)
				ON CONFLICT (schema_name, table_name, column_name, json_path, category) DO UPDATE SET
				  rule = EXCLUDED.rule, confidence = EXCLUDED.confidence, why = EXCLUDED.why,
				  matched = EXCLUDED.matched, sampled = EXCLUDED.sampled,
				  last_scan = EXCLUDED.last_scan, last_seen = now()`,
			f.t.schema, f.t.name, f.col, string(f.sig.Category), f.sig.Rule, string(f.sig.Confidence), f.sig.Why,
			f.sig.Matched, f.sig.Sampled, s.ID); err != nil {
			return s, fmt.Errorf("recording a finding: %w", err)
		}
	}
	return s, tx.Commit(ctx)
}

// catalog lists the tables a scan reads, with their columns.
//
// Tables, partitioned tables and materialized views, which hold data; foreign
// tables, so they can be named as not read. Not views, which show what tables
// hold; not partitions, which their parent's read covers; not the system's
// schemas, FoxByte's own (bb), or what an extension created.
func catalog(ctx context.Context, conn *pgx.Conn) ([]table, error) {
	rows, err := conn.Query(ctx, `
		SELECT n.nspname, c.relname, c.relkind::text, greatest(c.reltuples, 0)::bigint,
		       a.attname, t.typcategory::text, t.typname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		JOIN pg_type t ON t.oid = a.atttypid
		WHERE c.relkind IN ('r', 'p', 'm', 'f')
		  AND NOT c.relispartition
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'bb')
		  AND n.nspname NOT LIKE 'pg\_%'
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d
		                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
		ORDER BY n.nspname, c.relname, a.attnum`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []table
	for rows.Next() {
		var t table
		var c column
		if err := rows.Scan(&t.schema, &t.name, &t.kind, &t.rows, &c.name, &c.typcat, &c.typname); err != nil {
			return nil, err
		}
		if n := len(out); n > 0 && out[n-1].schema == t.schema && out[n-1].name == t.name {
			out[n-1].cols = append(out[n-1].cols, c)
			continue
		}
		t.cols = []column{c}
		out = append(out, t)
	}
	return out, rows.Err()
}

// sample reads up to n rows of the given columns, as text, NULLs left out. A
// large table is sampled by block (TABLESAMPLE) rather than read from the
// start, whose first rows are often the oldest and least like the rest.
// sampled reports that it was.
func sample(ctx context.Context, conn *pgx.Conn, t table, cols []column, n int) ([][]string, bool, error) {
	sel := make([]string, len(cols))
	for i, c := range cols {
		sel[i] = branch.QuoteIdent(c.name) + "::text"
	}
	from, sampled := t.ref(), false
	if (t.kind == "r" || t.kind == "m") && t.rows > int64(5*n) {
		pct := 100 * float64(5*n) / float64(t.rows)
		from += fmt.Sprintf(" TABLESAMPLE SYSTEM (%.6f)", pct)
		sampled = true
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '"+tableTimeout+"'"); err != nil {
		return nil, false, err
	}
	rows, err := tx.Query(ctx, fmt.Sprintf("SELECT %s FROM %s LIMIT %d", strings.Join(sel, ", "), from, n))
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := make([][]string, len(cols))
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, false, err
		}
		for i, v := range vals {
			if s, ok := v.(string); ok {
				out[i] = append(out[i], s)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return out, sampled, tx.Commit(ctx)
}

// readFailure says why a table could not be read, without repeating
// Postgres's message, which could name a value in some errors.
func readFailure(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "statement timeout"):
		return "reading it took longer than " + tableTimeout
	case strings.Contains(msg, "permission denied"):
		return "permission denied"
	default:
		return "it could not be read"
	}
}

// limits are what a scan's result cannot claim. Every result carries them,
// found or not.
func limits(n int, sampled, sawJSON bool) []string {
	l := []string{
		fmt.Sprintf("Up to %d rows of each table were read. A value in a row that was not read is not seen, so finding nothing does not show a table holds nothing.", n),
		"A check digit shows a value is well-formed, not that it was issued, or whose it is.",
		"Values longer than 64 characters are not read as identifiers: free text is a later step (4.3).",
		"Views are not scanned: they show what tables hold, and the tables are.",
	}
	if sampled {
		l = append(l, "Large tables were sampled by block (TABLESAMPLE SYSTEM), not row by row.")
	}
	if sawJSON {
		l = append(l, "JSON columns were judged by their names only: their documents are read path by path in a later step (4.2).")
	}
	return l
}
