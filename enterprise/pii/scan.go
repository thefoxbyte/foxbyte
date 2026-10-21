//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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

	s := branch.PIIScan{Started: time.Now().UTC(), Actor: o.Actor, Sample: o.Sample, NewOnly: o.NewOnly, Skipped: []branch.PIISkip{}}
	tables, err := catalog(ctx, conn)
	if err != nil {
		return s, fmt.Errorf("reading the catalog: %w", err)
	}
	// What earlier scans saw (4.7). Empty means this is the branch's
	// baseline: everything in it is known, and only what appears after it is
	// new.
	inv, err := inventory(ctx, conn)
	if err != nil {
		return s, fmt.Errorf("reading the inventory: %w", err)
	}
	baseline := len(inv) == 0
	var seen []place
	unchanged := 0

	type found struct {
		t    table
		col  string
		path string // inside a JSON column; "" for the column
		sig  Signal
	}
	var all []found
	var js jsonStats
	sawSampled := false
	for _, t := range tables {
		// Every column is in the inventory, read or not: its name is all the
		// inventory keeps.
		hasNew, hasJSON := false, false
		for _, c := range t.cols {
			p := place{t.schema, t.name, c.name, ""}
			seen = append(seen, p)
			if !inv[p] {
				hasNew = true
			}
			if isJSON(c) {
				hasJSON = true
			}
		}
		if t.kind == "f" {
			s.Skipped = append(s.Skipped, branch.PIISkip{Object: t.label(), Reason: "a foreign table: its data is held somewhere else"})
			continue
		}
		// A scan of what is new reads a table only if it has a column no scan
		// has seen, or a JSON column, whose new paths can only be found by
		// reading it.
		if o.NewOnly && !hasNew && !hasJSON && !baseline {
			unchanged++
			continue
		}
		var read []column
		for _, c := range t.cols {
			switch {
			case isJSON(c):
				// Its documents are walked path by path below; its own name
				// still says something (a jsonb called aadhaar).
				js.columns++
				for _, sig := range Classify(c.name, "-", nil) {
					all = append(all, found{t, c.name, "", sig})
				}
				read = append(read, c)
			case strings.ContainsAny(c.typcat, "SNDI") && c.typcat != "":
				read = append(read, c)
			default:
				// bytea, uuid, booleans, arrays…: no value to read as an
				// identifier, but a column called aadhaar holding ciphertext
				// is still a finding worth a reviewer's time.
				for _, sig := range Classify(c.name, "-", nil) {
					all = append(all, found{t, c.name, "", sig})
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
			if isJSON(c) {
				// A document over the size limit comes back as a marker,
				// not as itself (sample).
				docs := samples[i][:0]
				for _, d := range samples[i] {
					if d == tooLarge {
						js.large++
						continue
					}
					docs = append(docs, d)
				}
				paths, truncated, bad := walkJSON(docs, c.name)
				for _, p := range paths {
					seen = append(seen, place{t.schema, t.name, c.name, p.path})
				}
				js.paths += len(paths)
				js.bad += bad
				if truncated {
					js.truncated = append(js.truncated, t.label()+"."+c.name)
				}
				for _, p := range paths {
					for _, sig := range Classify(p.name, "S", p.values) {
						all = append(all, found{t, c.name, p.path, sig})
					}
				}
			} else {
				for _, sig := range Classify(c.name, c.typcat, samples[i]) {
					all = append(all, found{t, c.name, "", sig})
				}
			}
			samples[i] = nil // done with the values; nothing below needs them
		}
	}

	s.Limits = limits(o.Sample, sawSampled, js)
	if unchanged > 0 {
		s.Limits = append(s.Limits, fmt.Sprintf("A scan of what is new: %d table(s) with no column a scan had not seen were not read again, so a value added to an existing column there is not looked for.", unchanged))
	}
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
			(started_at, finished_at, actor, sample_size, tables_scanned, columns_scanned, skipped, limits, new_only)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		s.Started, s.Finished, s.Actor, s.Sample, s.Tables, s.Columns, skipped, lims, s.NewOnly).Scan(&s.ID); err != nil {
		return s, fmt.Errorf("recording the scan: %w", err)
	}
	for _, f := range all {
		// A finding found again keeps its state: a reviewer's decision is
		// not undone by the next scan (step 4.6 makes them).
		if _, err := tx.Exec(ctx, `INSERT INTO bb.pii_findings
				(schema_name, table_name, column_name, json_path, category, rule, confidence, why,
				 matched, sampled, first_scan, last_scan)
				VALUES ($1, $2, $3, $11, $4, $5, $6, $7, $8, $9, $10, $10)
				ON CONFLICT (schema_name, table_name, column_name, json_path, category) DO UPDATE SET
				  rule = EXCLUDED.rule, confidence = EXCLUDED.confidence, why = EXCLUDED.why,
				  matched = EXCLUDED.matched, sampled = EXCLUDED.sampled,
				  last_scan = EXCLUDED.last_scan, last_seen = now()`,
			f.t.schema, f.t.name, f.col, string(f.sig.Category), f.sig.Rule, string(f.sig.Confidence), f.sig.Why,
			f.sig.Matched, f.sig.Sampled, s.ID, f.path); err != nil {
			return s, fmt.Errorf("recording a finding: %w", err)
		}
	}
	if err := record(ctx, tx, seen, s.ID, baseline); err != nil {
		return s, fmt.Errorf("recording the inventory: %w", err)
	}
	return s, tx.Commit(ctx)
}

// place is a column, or a JSON path inside one: what the inventory keeps.
type place struct{ schema, table, column, path string }

// inventory reads every place earlier scans have seen.
func inventory(ctx context.Context, conn *pgx.Conn) (map[place]bool, error) {
	rows, err := conn.Query(ctx, `SELECT schema_name, table_name, column_name, json_path FROM bb.pii_columns`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inv := map[place]bool{}
	for rows.Next() {
		var p place
		if err := rows.Scan(&p.schema, &p.table, &p.column, &p.path); err != nil {
			return nil, err
		}
		inv[p] = true
	}
	return inv, rows.Err()
}

// record adds what this scan saw to the inventory: a place seen before is
// marked seen again, a new one comes in known (the baseline) or unclassified.
// One statement over arrays, since a branch can have thousands of columns.
func record(ctx context.Context, tx pgx.Tx, seen []place, scan int64, baseline bool) error {
	if len(seen) == 0 {
		return nil
	}
	status := branch.PIIUnclassified
	if baseline {
		status = branch.PIIKnown
	}
	n := len(seen)
	sc, tb, co, pa := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, p := range seen {
		sc[i], tb[i], co[i], pa[i] = p.schema, p.table, p.column, p.path
	}
	// An update for what was there and an insert for what was not, rather
	// than an upsert: an upsert takes a sequence number for every row it
	// touches, so the IDs people type would jump by thousands a scan.
	_, err := tx.Exec(ctx, `WITH seen AS (
			SELECT DISTINCT s, t, c, p FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS x(s, t, c, p)
		), again AS (
			UPDATE bb.pii_columns pc SET last_scan = $6
			FROM seen WHERE (pc.schema_name, pc.table_name, pc.column_name, pc.json_path) = (seen.s, seen.t, seen.c, seen.p)
		)
		INSERT INTO bb.pii_columns (schema_name, table_name, column_name, json_path, status, first_scan, last_scan)
		SELECT s, t, c, p, $5, $6, $6 FROM seen
		WHERE NOT EXISTS (SELECT 1 FROM bb.pii_columns pc
		                  WHERE (pc.schema_name, pc.table_name, pc.column_name, pc.json_path) = (seen.s, seen.t, seen.c, seen.p))
		ORDER BY s, t, c, p`,
		sc, tb, co, pa, status, scan)
	return err
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
		q := branch.QuoteIdent(c.name)
		sel[i] = q + "::text"
		if isJSON(c) {
			// Not a large document as itself: it would have to cross the
			// connection, be parsed, and be held, to be walked once.
			sel[i] = fmt.Sprintf("CASE WHEN pg_column_size(%s) > %d THEN %s ELSE %s::text END",
				q, maxDocument, branch.QuoteLiteral(tooLarge), q)
		}
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
		// The SQLSTATE, which names the kind of failure and never a value.
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			return "it could not be read (SQLSTATE " + pe.Code + ")"
		}
		return "it could not be read"
	}
}

// limits are what a scan's result cannot claim. Every result carries them,
// found or not.
func limits(n int, sampled bool, js jsonStats) []string {
	l := []string{
		fmt.Sprintf("Up to %d rows of each table were read. A value in a row that was not read is not seen, so finding nothing does not show a table holds nothing.", n),
		"A check digit shows a value is well-formed, not that it was issued, or whose it is.",
		"Values longer than 64 characters are not read as identifiers: free text is a later step (4.3).",
		"Views are not scanned: they show what tables hold, and the tables are.",
	}
	if sampled {
		l = append(l, "Large tables were sampled by block (TABLESAMPLE SYSTEM), not row by row.")
	}
	if js.columns > 0 {
		l = append(l, fmt.Sprintf("JSON documents were read path by path (%d path(s) in %d column(s)); an array's elements share one path, written [*], and nothing deeper than %d levels is read.",
			js.paths, js.columns, maxDepth))
	}
	if js.large > 0 {
		l = append(l, fmt.Sprintf("%d JSON document(s) larger than %d KB were not read.", js.large, maxDocument/1024))
	}
	if js.bad > 0 {
		l = append(l, fmt.Sprintf("%d value(s) in JSON columns could not be parsed and were not read.", js.bad))
	}
	if len(js.truncated) > 0 {
		l = append(l, fmt.Sprintf("Only the first %d paths of each column were classified, and %s had more.", maxPaths, strings.Join(js.truncated, ", ")))
	}
	return l
}

// jsonStats is what the walk of a scan's JSON columns could not cover.
type jsonStats struct {
	columns, paths, large, bad int
	truncated                  []string
}

// maxDocument is the largest JSON document read, in bytes as stored.
const maxDocument = 256 * 1024

// tooLarge marks a document over maxDocument in a sample. Not valid JSON (no
// JSON text starts with #), so it can never be mistaken for a document. Plain
// characters: Postgres text cannot hold a NUL, which is what the first try was.
const tooLarge = "#fox:too-large"

func isJSON(c column) bool { return c.typname == "json" || c.typname == "jsonb" }
