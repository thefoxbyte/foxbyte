//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/thefoxbyte/foxbyte/enterprise/schema"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// The Aadhaar exposure report's run (point 4.5): every row of a branch's
// tables read for Aadhaar numbers, and each place one sits kept by its row's
// key and the number's last four digits.
//
// As the superuser, for the scan's reason: a run that obeyed row-level
// security would call a branch clean while rows it could not see held exactly
// what it looks for. Read-only transactions, one a table, each with a time
// limit. The database filters each table for twelve digits in Aadhaar's shape,
// so only rows that may hold one cross the connection; the check digit is
// checked here. The numbers stay in this process's memory for the run, to
// group the places of one number as one person, and are never written.

func init() { branch.SetAadhaarReporter(runExposure) }

const (
	// runTimeout bounds a whole run.
	runTimeout = 2 * time.Hour
	// maxListedPerColumn and maxListed bound the places kept. A column that
	// holds every customer's number is one finding, said in its count; the
	// report lists the first places, not all of them.
	maxListedPerColumn = 10000
	maxListed          = 200000
	// maxGrouped bounds the distinct numbers held in memory to group places
	// by person. Past it, a new number's places are kept ungrouped (person 0).
	maxGrouped = 2000000
	// maxExposureDocument is the largest JSON document walked, as stored.
	maxExposureDocument = 16 << 20
)

// shapePG is the database's filter: twelve digits as four, four and four,
// with or without a space or hyphen between. A superset of what isAadhaarIn
// accepts, so the filter never drops a row the check would keep.
const shapePG = `[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}`

var shapeRE = regexp.MustCompile(`[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}`)

// findAadhaar returns the Aadhaar numbers in a text, as twelve digits each,
// in order and each once. A match must stand alone: twelve digits inside a
// longer number (a card's sixteen, a phone with its country code run on) are
// that number, not an Aadhaar.
func findAadhaar(s string) []string {
	var out []string
	for _, m := range shapeRE.FindAllStringIndex(s, -1) {
		if joined(s, m[0], -1) || joined(s, m[1]-1, +1) {
			continue
		}
		d := strings.NewReplacer(" ", "", "-", "").Replace(s[m[0]:m[1]])
		if len(d) != 12 || !verhoeff(d) {
			continue
		}
		dup := false
		for _, x := range out {
			if x == d {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, d)
		}
	}
	return out
}

// joined reports whether the digit at i continues into another beyond it, in
// direction dir: a digit next to it, or a space or hyphen and then a digit.
func joined(s string, i, dir int) bool {
	j := i + dir
	if j < 0 || j >= len(s) {
		return false
	}
	if isDigit(s[j]) {
		return true
	}
	if s[j] == ' ' || s[j] == '-' {
		k := j + dir
		return k >= 0 && k < len(s) && isDigit(s[k])
	}
	return false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// safeKey is a JSON key as a path may keep it. A key holding a long run of
// digits could be the number itself (documents keyed by Aadhaar), and a path
// is kept: it becomes *.
func safeKey(parent, key string) string {
	run, longest := 0, 0
	for i := 0; i < len(key); i++ {
		if isDigit(key[i]) {
			run++
			if run > longest {
				longest = run
			}
		} else if key[i] != ' ' && key[i] != '-' {
			run = 0
		}
	}
	if longest >= 8 {
		return parent + ".*"
	}
	return childPath(parent, key)
}

// docHit is one number found in a JSON document, and the path it was at.
type docHit struct{ path, number string }

// walkExposure finds the Aadhaar numbers in one JSON document, path by path:
// values, and keys (a document keyed by number). ok is false for a document
// that is not JSON.
func walkExposure(doc string) (hits []docHit, ok bool) {
	dec := json.NewDecoder(bytes.NewReader([]byte(doc)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	var walk func(v any, path string, depth int)
	walk = func(v any, path string, depth int) {
		if depth > maxDepth {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				child := safeKey(path, k)
				for _, n := range findAadhaar(k) {
					hits = append(hits, docHit{child, n})
				}
				walk(x[k], child, depth+1)
			}
		case []any:
			for _, c := range x {
				walk(c, path+"[*]", depth+1)
			}
		case string:
			for _, n := range findAadhaar(x) {
				hits = append(hits, docHit{path, n})
			}
		case json.Number:
			for _, n := range findAadhaar(x.String()) {
				hits = append(hits, docHit{path, n})
			}
		}
	}
	walk(v, "$", 0)
	return hits, true
}

// exposureTable is a table as a run reads it.
type exposureTable struct {
	table
	read    []column
	key     string // the SQL that names a row
	keyless bool   // named by ctid, not a primary key
	created string // the tracked created_at column, "" if none
}

type colKey struct{ schema, table, column, path string }

type placeKey struct {
	colKey
	row, last4 string
}

type colStat struct {
	numbers, rows int64
	listed        int
	capped        bool
}

// exposure is a run's working state: what it has found so far.
type exposure struct {
	people  map[uint64]int32
	grouped bool // every number has a person
	places  []placeKey
	kept    map[placeKey]int // index into places and the slices beside it
	person  []int32
	created []pgtype.Timestamptz
	cols    map[colKey]*colStat
	order   []colKey
}

func newExposure() *exposure {
	return &exposure{people: map[uint64]int32{}, grouped: true, kept: map[placeKey]int{}, cols: map[colKey]*colStat{}}
}

// add records the numbers found in one value of one row.
func (e *exposure) add(ck colKey, row string, created pgtype.Timestamptz, numbers []string) {
	if len(numbers) == 0 {
		return
	}
	st := e.cols[ck]
	if st == nil {
		st = &colStat{}
		e.cols[ck] = st
		e.order = append(e.order, ck)
	}
	st.rows++
	for _, n := range numbers {
		st.numbers++
		v, _ := strconv.ParseUint(n, 10, 64)
		p, ok := e.people[v]
		if !ok {
			if len(e.people) < maxGrouped {
				p = int32(len(e.people) + 1)
				e.people[v] = p
			} else {
				e.grouped = false
			}
		}
		pk := placeKey{ck, row, n[8:]}
		if _, dup := e.kept[pk]; dup {
			continue
		}
		if st.listed >= maxListedPerColumn || len(e.places) >= maxListed {
			st.capped = true
			continue
		}
		e.kept[pk] = len(e.places)
		e.places = append(e.places, pk)
		e.person = append(e.person, p)
		e.created = append(e.created, created)
		st.listed++
	}
}

// runExposure reads a branch for Aadhaar numbers and records what it found.
func runExposure(name string, o branch.AadhaarRunOptions) (branch.AadhaarRun, error) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	if err := schema.EnsurePII(name); err != nil {
		return branch.AadhaarRun{}, err
	}
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return branch.AadhaarRun{}, err
	}
	defer conn.Close(context.Background())

	r := branch.AadhaarRun{Started: time.Now().UTC(), Actor: o.Actor, Skipped: []branch.PIISkip{}}
	tables, err := exposureCatalog(ctx, conn)
	if err != nil {
		return r, fmt.Errorf("reading the catalog: %w", err)
	}
	e := newExposure()
	var st exposureStats
	for _, t := range tables {
		if t.kind == "f" {
			r.Skipped = append(r.Skipped, branch.PIISkip{Object: t.label(), Reason: "a foreign table: its data is held somewhere else"})
			continue
		}
		if len(t.read) == 0 {
			continue
		}
		n, err := readExposure(ctx, conn, t, o.TableTimeout, e, &st)
		if err != nil {
			r.Skipped = append(r.Skipped, branch.PIISkip{Object: t.label(), Reason: exposureFailure(err, o.TableTimeout)})
			continue
		}
		r.Tables++
		r.Columns += len(t.read)
		r.Rows += n
		if t.keyless {
			st.keyless = append(st.keyless, t.label())
		}
	}
	for _, c := range e.cols {
		r.Numbers += c.numbers
	}
	r.People = len(e.people)
	r.Listed = len(e.places)
	r.Limits = exposureLimits(e, st, o.Logs)
	r.Finished = time.Now().UTC()
	if err := recordExposure(ctx, conn, &r, e); err != nil || !o.Logs {
		return r, err
	}
	// The logs, with the numbers the tables' read still holds: a number in
	// both is one person. Every person numbered so far was in a table.
	lr, places := readExposureLogs(ctx, conn, name, o, e, int32(r.People))
	lr.BranchRun = r.ID
	return r, o.Store.RecordAadhaarLogs(&lr, places)
}

// exposureStats is what a run could not read, or read only in part.
type exposureStats struct {
	keyless []string
	large   int
	bad     int
}

// exposureCatalog lists the tables a run reads: the scan's catalog, less
// FoxByte's masks, with each table's key and tracked creation column.
func exposureCatalog(ctx context.Context, conn *pgx.Conn) ([]exposureTable, error) {
	tables, err := catalog(ctx, conn)
	if err != nil {
		return nil, err
	}
	keys := map[[2]string][]string{}
	rows, err := conn.Query(ctx, `SELECT n.nspname, c.relname, array_agg(a.attname ORDER BY k.ord)
		FROM pg_index i
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
		WHERE i.indisprimary
		GROUP BY n.nspname, c.relname`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s, t string
		var cols []string
		if err := rows.Scan(&s, &t, &cols); err != nil {
			rows.Close()
			return nil, err
		}
		keys[[2]string{s, t}] = cols
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	created := map[[2]string]string{}
	var tracking bool
	if err := conn.QueryRow(ctx, `SELECT to_regprocedure('bb.tracked_tables()') IS NOT NULL`).Scan(&tracking); err != nil {
		return nil, err
	}
	if tracking {
		rows, err := conn.Query(ctx, `SELECT n.nspname, c.relname, t.created_col
			FROM bb.tracked_tables() t JOIN pg_class c ON c.oid = t.rel JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE t.created_col <> ''`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var s, t, c string
			if err := rows.Scan(&s, &t, &c); err != nil {
				rows.Close()
				return nil, err
			}
			created[[2]string{s, t}] = c
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	var out []exposureTable
	for _, t := range tables {
		if t.schema == branch.MaskSchema {
			continue // FoxByte's masks: the masks of numbers, not numbers
		}
		x := exposureTable{table: t}
		for _, c := range t.cols {
			if exposureReads(c) {
				x.read = append(x.read, c)
			}
			if c.name == created[[2]string{t.schema, t.name}] && c.typname == "timestamptz" {
				x.created = c.name
			}
		}
		x.key, x.keyless = rowKeySQL(t, keys[[2]string{t.schema, t.name}])
		out = append(out, x)
	}
	return out, nil
}

// exposureReads says whether a run reads a column: anything that can hold the
// digits as text. Strings, numbers, arrays and composites of them, and JSON.
// Not binary (bytea's hex would be read as digits), dates, booleans, network
// addresses or geometry.
func exposureReads(c column) bool {
	if isJSON(c) {
		return true
	}
	switch c.typcat {
	case "S", "N", "A", "C":
		return true
	}
	return false
}

// rowKeySQL is the SQL naming a row as a place keeps it: id=42, or
// (a, b)=(1, x) for a key of more than one column. A table with no primary
// key is named by its physical position, with its partition's name for a
// partitioned one.
func rowKeySQL(t table, key []string) (string, bool) {
	switch {
	case len(key) == 1:
		return branch.QuoteLiteral(key[0]+"=") + " || " + branch.QuoteIdent(key[0]) + "::text", false
	case len(key) > 1:
		vals := make([]string, len(key))
		for i, k := range key {
			vals[i] = "coalesce(" + branch.QuoteIdent(k) + "::text, 'NULL')"
		}
		return branch.QuoteLiteral("("+strings.Join(key, ", ")+")=(") + " || " +
			strings.Join(vals, " || ', ' || ") + " || ')'", false
	case t.kind == "p":
		return "'ctid=' || tableoid::regclass::text || ':' || ctid::text", true
	default:
		return "'ctid=' || ctid::text", true
	}
}

// readExposure reads one table's rows that may hold a number, and adds what
// they hold. It returns how many rows the filter passed on.
func readExposure(ctx context.Context, conn *pgx.Conn, t exposureTable, timeout time.Duration, e *exposure, st *exposureStats) (int64, error) {
	sel := []string{t.key, "NULL::timestamptz"}
	if t.created != "" {
		sel[1] = branch.QuoteIdent(t.created)
	}
	where := make([]string, len(t.read))
	for i, c := range t.read {
		q := branch.QuoteIdent(c.name)
		where[i] = q + "::text ~ " + branch.QuoteLiteral(shapePG)
		if isJSON(c) {
			sel = append(sel, fmt.Sprintf("CASE WHEN pg_column_size(%s) > %d THEN %s ELSE %s::text END",
				q, maxExposureDocument, branch.QuoteLiteral(tooLarge), q))
		} else {
			sel = append(sel, q+"::text")
		}
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", timeout.Milliseconds())); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '10s'"); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, fmt.Sprintf("SELECT %s FROM %s WHERE %s",
		strings.Join(sel, ", "), t.ref(), strings.Join(where, " OR ")))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var n int64
	// A table's places are added only once its read has finished: a read
	// cut off by its time limit is skipped whole, not half-kept.
	type hit struct {
		ck      colKey
		row     string
		created pgtype.Timestamptz
		numbers []string
	}
	var hits []hit
	for rows.Next() {
		var key string
		var created pgtype.Timestamptz
		vals := make([]*string, len(t.read))
		dest := []any{&key, &created}
		for i := range vals {
			dest = append(dest, &vals[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return 0, err
		}
		n++
		for i, c := range t.read {
			v := vals[i]
			if v == nil {
				continue
			}
			base := colKey{t.schema, t.name, c.name, ""}
			if !isJSON(c) {
				if ns := findAadhaar(*v); len(ns) > 0 {
					hits = append(hits, hit{base, key, created, ns})
				}
				continue
			}
			if *v == tooLarge {
				st.large++
				continue
			}
			found, ok := walkExposure(*v)
			if !ok {
				st.bad++
				continue
			}
			// One value per path: a document holding a number at two paths
			// is two places.
			byPath := map[string][]string{}
			var paths []string
			for _, h := range found {
				if _, seen := byPath[h.path]; !seen {
					paths = append(paths, h.path)
				}
				byPath[h.path] = append(byPath[h.path], h.number)
			}
			for _, p := range paths {
				ck := base
				ck.path = p
				hits = append(hits, hit{ck, key, created, byPath[p]})
			}
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	for _, h := range hits {
		e.add(h.ck, h.row, h.created, h.numbers)
	}
	return n, nil
}

// exposureFailure says why a table could not be read, as readFailure does,
// with the run's own time limit.
func exposureFailure(err error, timeout time.Duration) string {
	if strings.Contains(err.Error(), "statement timeout") {
		return "reading it took longer than " + timeout.String()
	}
	if strings.Contains(err.Error(), "lock timeout") {
		return "it was locked by another session for longer than 10s"
	}
	return readFailure(err)
}

const (
	onlyTables = "Only the branch's tables were read. Query history, the audit log's statement text and the Blackbox are not read by this run."
	withLogs   = "The branch's logs were read too (query history, the audit log's statement text and the Blackbox); what they hold is in the logs part, for admins only."
)

// exposureLimits are what a run's report cannot claim. Every report carries
// them, found or not.
func exposureLimits(e *exposure, st exposureStats, logs bool) []string {
	l := []string{
		"Every row of every text, number, array and JSON column was read. The database passed on only rows holding twelve digits in Aadhaar's shape (four, four and four, with or without a space or hyphen), and each was then checked by its check digit.",
		"A check digit shows a number is well-formed, not that it was issued, or whose it is.",
		"There is no Aadhaar vault in FoxByte yet (point 13), so every number found is outside one.",
		onlyTables,
		"Not read: views (they show what tables hold, and the tables are read), FoxByte's masks, binary columns, and dates, booleans and network addresses.",
		"Since when is the first run that found a number in a place, or the row's created_at on a tracked table if that is earlier. A number there before the first run has no earlier date.",
	}
	if logs {
		l[3] = withLogs
	}
	capped := false
	for _, c := range e.cols {
		capped = capped || c.capped
	}
	if capped {
		l = append(l, fmt.Sprintf("At most %d places are kept for a column and %d for a run; a column's counts are in full.", maxListedPerColumn, maxListed))
	}
	if !e.grouped {
		l = append(l, fmt.Sprintf("More than %d distinct numbers were found; places of numbers past those are kept without a person.", maxGrouped))
	}
	if len(st.keyless) > 0 {
		l = append(l, "Rows of tables with no primary key are named by their physical position (ctid), which changes when a row is updated: "+strings.Join(st.keyless, ", ")+".")
	}
	if st.large > 0 {
		l = append(l, fmt.Sprintf("%d JSON document(s) larger than %d MB were not read.", st.large, maxExposureDocument>>20))
	}
	if st.bad > 0 {
		l = append(l, fmt.Sprintf("%d value(s) in JSON columns could not be parsed and were not read.", st.bad))
	}
	return l
}

// recordExposure writes a run, its columns and its places in one transaction.
func recordExposure(ctx context.Context, conn *pgx.Conn, r *branch.AadhaarRun, e *exposure) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	skipped, _ := json.Marshal(r.Skipped)
	lims, _ := json.Marshal(r.Limits)
	if err := tx.QueryRow(ctx, `INSERT INTO bb.aadhaar_runs
			(started_at, finished_at, actor, tables_read, columns_read, rows_read, numbers, people, listed, skipped, limits)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
		r.Started, r.Finished, r.Actor, r.Tables, r.Columns, r.Rows, r.Numbers, r.People, r.Listed, skipped, lims).Scan(&r.ID); err != nil {
		return fmt.Errorf("recording the run: %w", err)
	}

	if n := len(e.order); n > 0 {
		sc, tb, co, pa := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		nums, rws, lst, capd := make([]int64, n), make([]int64, n), make([]int32, n), make([]bool, n)
		for i, k := range e.order {
			c := e.cols[k]
			sc[i], tb[i], co[i], pa[i] = k.schema, k.table, k.column, k.path
			nums[i], rws[i], lst[i], capd[i] = c.numbers, c.rows, int32(c.listed), c.capped
		}
		if _, err := tx.Exec(ctx, `INSERT INTO bb.aadhaar_columns
				(run_id, schema_name, table_name, column_name, json_path, numbers, rows_with, listed, capped)
				SELECT $1, s, t, c, p, n, r, l, x
				FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::bigint[], $7::bigint[], $8::int[], $9::boolean[])
				  AS u(s, t, c, p, n, r, l, x)`,
			r.ID, sc, tb, co, pa, nums, rws, lst, capd); err != nil {
			return fmt.Errorf("recording the columns: %w", err)
		}
	}

	// Places in batches: one statement over arrays each, a place found
	// before keeping when it was first seen.
	const batch = 5000
	for from := 0; from < len(e.places); from += batch {
		to := min(from+batch, len(e.places))
		n := to - from
		sc, tb, co, pa, rk, l4 := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		for i, p := range e.places[from:to] {
			sc[i], tb[i], co[i], pa[i], rk[i], l4[i] = p.schema, p.table, p.column, p.path, p.row, p.last4
		}
		if _, err := tx.Exec(ctx, `INSERT INTO bb.aadhaar_places AS a
				(schema_name, table_name, column_name, json_path, row_key, last4, person,
				 first_run, last_run, first_seen, last_seen, row_created)
				SELECT s, t, c, p, k, l, pe, $9, $9, $10, $10, rc
				FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::int[], $8::timestamptz[])
				  AS u(s, t, c, p, k, l, pe, rc)
				ON CONFLICT (schema_name, table_name, column_name, json_path, row_key, last4) DO UPDATE SET
				  person = EXCLUDED.person, last_run = EXCLUDED.last_run, last_seen = EXCLUDED.last_seen,
				  row_created = EXCLUDED.row_created`,
			sc, tb, co, pa, rk, l4, e.person[from:to], e.created[from:to], r.ID, r.Started); err != nil {
			return fmt.Errorf("recording the places: %w", err)
		}
	}
	return tx.Commit(ctx)
}
