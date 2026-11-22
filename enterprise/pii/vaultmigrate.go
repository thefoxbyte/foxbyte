//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/enterprise/vault"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Moving a branch's Aadhaar numbers into the vault (point 13, step 13.3;
// docs/FOX_P13_Vault_Design.md, section 15). The engine (internal/branch,
// vaultmigrate.go) decides who may, and keeps the run; this reads and writes.
//
// As the superuser, as the exposure report reads: a migration that obeyed
// row-level security would leave the rows it could not see holding numbers.
//
//  1. The columns: the branch's latest exposure report's, or those named.
//     Each is planned: the key format it can hold, or why it cannot be moved
//     (no primary key, part of a key, a generated column, a view…).
//  2. Every row of them that may hold a number is read, and each distinct
//     number put in the vault, those that need the legacy format first, so a
//     number held in a bigint somewhere gets a key a bigint can hold.
//  3. Each column is rewritten in batches by its rows' keys, and only where
//     the value is still what was read: a row changed meanwhile is read again
//     on the next pass, as are rows written while the run ran.
//  4. The columns are read once more, and what is left is counted, with why.
//  5. Each table rewritten is vacuumed, so its rows' old versions go.
//
// The numbers are in this process's memory for the run, as the exposure
// report's are, and never written anywhere but the vault.

func init() { branch.SetVaultMigrator(migrateAadhaar) }

const (
	migrateTimeout   = 6 * time.Hour
	migrateStatement = 10 * time.Minute // a read, or a batch's write
	// migrateTokenise is numbers a vault call; migrateBatch rows a write.
	migrateTokenise = 2000
	migrateBatch    = 1000
	// migratePasses is how many times a column is rewritten before what is
	// left is counted: rows written while the run runs are caught by the next.
	migratePasses = 3
	// maxMigrateNumbers bounds the distinct numbers held in memory.
	maxMigrateNumbers = 5_000_000
	// opaqueKeyLen is an opaque Aadhaar key's length: AR and 26 characters.
	opaqueKeyLen = 28
)

// Why a number is left where it is.
const (
	leftOpaque   = "its key in the vault is opaque, which this column cannot hold"
	leftTooLong  = "the row's value with keys in it would be longer than the column allows"
	leftInNumber = "inside a longer JSON number, which a key cannot replace"
	leftNoKey    = "the vault gave no key for it"
)

// aadhaarSpan is one number in a text: where it stands, and its 12 digits.
type aadhaarSpan struct {
	start, end int
	digits     string
}

// aadhaarSpans finds the numbers in a text as findAadhaar does, standing
// alone and passing the check, with where each stands, every occurrence.
func aadhaarSpans(s string) []aadhaarSpan {
	var out []aadhaarSpan
	for _, m := range shapeRE.FindAllStringIndex(s, -1) {
		if joined(s, m[0], -1) || joined(s, m[1]-1, +1) {
			continue
		}
		d := strings.NewReplacer(" ", "", "-", "").Replace(s[m[0]:m[1]])
		if len(d) != 12 || !verhoeff(d) {
			continue
		}
		out = append(out, aadhaarSpan{m[0], m[1], d})
	}
	return out
}

// keyFor answers, for a number found in a place, the key to write there, or
// why none can be.
type keyFor func(digits string, jsonNumber bool) (key string, quote bool, why string)

// rewriteText replaces each number in a text with its key, and counts the
// numbers left, by why.
func rewriteText(s string, key keyFor) (string, int, map[string]int) {
	spans := aadhaarSpans(s)
	if len(spans) == 0 {
		return s, 0, nil
	}
	var b strings.Builder
	left := map[string]int{}
	n, at := 0, 0
	for _, sp := range spans {
		b.WriteString(s[at:sp.start])
		k, _, why := key(sp.digits, false)
		if why != "" {
			left[why]++
			b.WriteString(s[sp.start:sp.end])
		} else {
			b.WriteString(k)
			n++
		}
		at = sp.end
	}
	b.WriteString(s[at:])
	return b.String(), n, left
}

// rewriteJSON replaces each number in a JSON document where it stands: inside
// a string (a value or a key), within the text; as a JSON number of its own,
// by a legacy key as a number or any other key as a string. The rest of the
// document is kept as it was, byte for byte. ok is false for a document that
// is not JSON.
func rewriteJSON(doc string, key keyFor) (out string, n int, left map[string]int, ok bool) {
	if !json.Valid([]byte(doc)) {
		return doc, 0, nil, false
	}
	left = map[string]int{}
	var b strings.Builder
	add := func(m map[string]int) {
		for k, v := range m {
			left[k] += v
		}
	}
	for i := 0; i < len(doc); {
		c := doc[i]
		switch {
		case c == '"':
			j, escaped := i+1, false
			for ; j < len(doc); j++ {
				if doc[j] == '\\' {
					escaped = true
					j++
					continue
				}
				if doc[j] == '"' {
					break
				}
			}
			lit := doc[i : j+1]
			if !escaped {
				nt, k, l := rewriteText(lit[1:len(lit)-1], key)
				add(l)
				n += k
				b.WriteString(`"` + nt + `"`)
			} else {
				var str string
				if err := json.Unmarshal([]byte(lit), &str); err != nil {
					return doc, 0, nil, false
				}
				nt, k, l := rewriteText(str, key)
				add(l)
				n += k
				if k == 0 {
					b.WriteString(lit)
				} else {
					var enc bytes.Buffer
					e := json.NewEncoder(&enc)
					e.SetEscapeHTML(false)
					if err := e.Encode(nt); err != nil {
						return doc, 0, nil, false
					}
					b.WriteString(strings.TrimRight(enc.String(), "\n"))
				}
			}
			i = j + 1
		case c == '-' || (c >= '0' && c <= '9'):
			j := i
			for j < len(doc) && strings.IndexByte("0123456789+-.eE", doc[j]) >= 0 {
				j++
			}
			tok := doc[i:j]
			spans := aadhaarSpans(tok)
			switch {
			case len(spans) == 1 && spans[0].start == 0 && spans[0].end == len(tok):
				k, quote, why := key(spans[0].digits, true)
				switch {
				case why != "":
					left[why]++
					b.WriteString(tok)
				case quote:
					b.WriteString(`"` + k + `"`)
					n++
				default:
					b.WriteString(k)
					n++
				}
			case len(spans) > 0:
				left[leftInNumber] += len(spans)
				b.WriteString(tok)
			default:
				b.WriteString(tok)
			}
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), n, left, true
}

// migCol is a column as a run plans and moves it.
type migCol struct {
	report  *branch.VaultMigrateColumn
	tbl     string   // the table, quoted
	keys    []string // its primary key's columns, quoted
	keyType []string // and their types
	col     string   // the column, quoted
	typ     string   // its type, as format_type writes it
	json    bool
	legacy  bool // holds only numbers, or is too short for an opaque key
	maxLen  int  // char(n), varchar(n): n; else 0
}

// colFacts is what the catalog says of a column.
type colFacts struct {
	kind, typ, typcat, elemcat, typname string
	maxLen                              int
	generated, inKey, inForeign         bool
	keys, keyTypes                      []string
}

func migrateAadhaar(name string, r branch.VaultMigrateRun) (branch.VaultMigration, error) {
	m := branch.VaultMigration{Columns: []branch.VaultMigrateColumn{}, Limits: []string{}}
	ctx, cancel := context.WithTimeout(context.Background(), migrateTimeout)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return m, err
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `SET application_name = 'fox vault migrate'`); err != nil {
		return m, err
	}
	kind, ok := vault.KindOf(branch.VaultMigrateKind)
	if !ok || kind.IsLegacy == nil {
		return m, errors.New("this build has no Aadhaar kind with a legacy format")
	}

	wanted := r.Columns
	if len(wanted) == 0 {
		if wanted, err = exposedColumns(ctx, conn); err != nil {
			return m, err
		}
		if len(wanted) == 0 {
			m.Limits = append(m.Limits, "The branch's latest exposure report found no Aadhaar number in its tables, so there is nothing to move. Run the report again if the tables have changed since.")
			return m, nil
		}
	}
	cols, err := planMigration(ctx, conn, wanted, r.Format)
	if err != nil {
		return m, err
	}
	for _, c := range cols {
		m.Columns = append(m.Columns, *c.report)
	}
	syncReport := func() {
		for i, c := range cols {
			m.Columns[i] = *c.report
		}
	}

	// 2. Every number, and whether some place needs its key to be legacy.
	numbers := map[string]bool{} // digits -> needs legacy
	for _, c := range cols {
		if c.report.Skipped != "" {
			continue
		}
		if err := collectNumbers(ctx, conn, c, r.Format, numbers); err != nil {
			c.report.Skipped = "reading it failed: " + err.Error()
			continue
		}
		if len(numbers) > maxMigrateNumbers {
			syncReport()
			return m, fmt.Errorf("the columns hold more than %d distinct numbers: move them a few columns at a time (--column)", maxMigrateNumbers)
		}
	}
	m.Distinct = int64(len(numbers))
	syncReport()
	if r.Check != nil {
		if err := r.Check(m.Columns); err != nil {
			return m, err
		}
	}
	if r.DryRun {
		m.Limits = append(m.Limits, "A preview: nothing was put in the vault and no row was changed.")
		m.Limits = append(m.Limits, migrateLimits...)
		return m, nil
	}

	refs := map[string]string{}
	if err := tokeniseNumbers(numbers, refs, r, &m); err != nil {
		syncReport()
		return m, err
	}

	// 3 and 4: rewrite, pass by pass, and count what is left.
	tables := map[string]string{} // quoted -> as a reader writes it
	for _, c := range cols {
		if c.report.Skipped != "" {
			continue
		}
		passes, err := moveColumn(ctx, conn, c, kind, refs, r, &m)
		m.Passes = max(m.Passes, passes)
		if err != nil {
			syncReport()
			return m, err
		}
		if c.report.Replaced > 0 {
			tables[c.tbl] = c.report.Schema + "." + c.report.Table
		}
	}
	syncReport()

	// 5. The tables' old row versions.
	var names []string
	for t := range tables {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		if _, err := conn.Exec(ctx, "VACUUM "+t); err != nil {
			m.Limits = append(m.Limits, fmt.Sprintf("%s could not be vacuumed (%v), so its rows' old versions, numbers and all, stay in its files until it is: run VACUUM on it.", tables[t], err))
			continue
		}
		m.Vacuumed = append(m.Vacuumed, tables[t])
	}
	m.Limits = append(m.Limits, migrateLimits...)
	return m, nil
}

var migrateLimits = []string{
	"Only the columns listed were read and rewritten. Run the exposure report again to see what the branch still holds.",
	"Query history, the audit log's statement text and the Blackbox are not changed: the exposure report's logs part keeps listing what they hold, and the Blackbox's chain is never rewritten.",
	"A number's old value may remain in the write-ahead log, its archive and backups taken before the run, until they expire.",
}

// exposedColumns are the columns the branch's latest exposure report found a
// number in, each once (a JSON column's paths are the column).
func exposedColumns(ctx context.Context, conn *pgx.Conn) ([]string, error) {
	var have bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('bb.aadhaar_runs') IS NOT NULL AND to_regclass('bb.aadhaar_columns') IS NOT NULL`).Scan(&have); err != nil {
		return nil, err
	}
	var run int64
	if have {
		err := conn.QueryRow(ctx, `SELECT id FROM bb.aadhaar_runs ORDER BY id DESC LIMIT 1`).Scan(&run)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	if run == 0 {
		return nil, fmt.Errorf("%w: the branch has no Aadhaar exposure report yet, and a migration moves the columns it found: run it first (fox pii aadhaar run --branch <branch>), or name the columns (--column)", branch.ErrInvalidRequest)
	}
	rows, err := conn.Query(ctx, `SELECT DISTINCT schema_name || '.' || table_name || '.' || column_name
		FROM bb.aadhaar_columns WHERE run_id = $1 ORDER BY 1`, run)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// planMigration reads each column's facts and decides its format, or why it
// is not moved.
func planMigration(ctx context.Context, conn *pgx.Conn, wanted []string, format string) ([]*migCol, error) {
	var out []*migCol
	seen := map[string]bool{}
	for _, w := range wanted {
		if seen[w] {
			continue
		}
		seen[w] = true
		parts := strings.SplitN(w, ".", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("%w: a column is schema.table.column, not %q", branch.ErrInvalidRequest, w)
		}
		rep := &branch.VaultMigrateColumn{Schema: parts[0], Table: parts[1], Column: parts[2]}
		c := &migCol{report: rep, tbl: branch.QuoteIdent(parts[0]) + "." + branch.QuoteIdent(parts[1]), col: branch.QuoteIdent(parts[2])}
		out = append(out, c)
		f, found, err := readColFacts(ctx, conn, parts[0], parts[1], parts[2])
		if err != nil {
			return nil, err
		}
		if !found {
			rep.Skipped = "there is no such column"
			continue
		}
		rep.Type, c.typ, c.maxLen = f.typ, f.typ, f.maxLen
		c.keys, c.keyType = f.keys, f.keyTypes
		c.json = f.typname == "json" || f.typname == "jsonb"
		switch {
		case parts[0] == branch.MaskSchema || parts[0] == "bb" || parts[0] == "bb_f1" || strings.HasPrefix(parts[0], "pg_") || parts[0] == "information_schema":
			rep.Skipped = "it is FoxByte's or PostgreSQL's own"
		case f.kind == "v" || f.kind == "m":
			rep.Skipped = "a view: move the tables it reads"
		case f.kind == "f":
			rep.Skipped = "a foreign table: its data is held somewhere else"
		case f.kind != "r" && f.kind != "p":
			rep.Skipped = "not a table"
		case len(f.keys) == 0:
			rep.Skipped = "the table has no primary key, so its rows cannot be named to rewrite them safely"
		case f.inKey:
			rep.Skipped = "it is part of the table's primary key"
		case f.inForeign:
			rep.Skipped = "it is part of a foreign key: its tables are moved together, by hand"
		case f.generated:
			rep.Skipped = "a generated column: move the columns it is made from"
		case !c.json && !strings.Contains("SNAC", f.typcat):
			rep.Skipped = "its type cannot hold a number as text"
		}
		if rep.Skipped != "" {
			continue
		}
		numeric := f.typcat == "N" || (f.typcat == "A" && f.elemcat == "N")
		c.legacy = numeric || (f.maxLen > 0 && f.maxLen < opaqueKeyLen)
		switch {
		case format == vault.FormatOpaque && c.legacy:
			rep.Skipped = "it cannot hold an opaque key, and --format opaque was asked for"
		case format != "":
			rep.Format = format
		case c.json:
			rep.Format = "mixed"
		case c.legacy:
			rep.Format = vault.FormatLegacy
		default:
			rep.Format = vault.FormatOpaque
		}
	}
	return out, nil
}

func readColFacts(ctx context.Context, conn *pgx.Conn, schema, table, column string) (colFacts, bool, error) {
	var f colFacts
	var oid uint32
	err := conn.QueryRow(ctx, `SELECT c.oid, c.relkind::text, format_type(a.atttypid, a.atttypmod), t.typcategory::text,
			coalesce(et.typcategory::text, ''), t.typname,
			CASE WHEN coalesce(et.typname, t.typname) IN ('bpchar', 'varchar') AND a.atttypmod > 4 THEN a.atttypmod - 4 ELSE 0 END,
			a.attgenerated <> '',
			EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisprimary AND a.attnum = ANY (i.indkey::int2[])),
			EXISTS (SELECT 1 FROM pg_constraint k WHERE k.contype = 'f'
				AND ((k.conrelid = c.oid AND a.attnum = ANY (k.conkey)) OR (k.confrelid = c.oid AND a.attnum = ANY (k.confkey))))
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		JOIN pg_type t ON t.oid = a.atttypid
		LEFT JOIN pg_type et ON et.oid = t.typelem AND t.typcategory = 'A'
		WHERE n.nspname = $1 AND c.relname = $2 AND a.attname = $3`, schema, table, column).
		Scan(&oid, &f.kind, &f.typ, &f.typcat, &f.elemcat, &f.typname, &f.maxLen, &f.generated, &f.inKey, &f.inForeign)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, false, nil
	}
	if err != nil {
		return f, false, err
	}
	rows, err := conn.Query(ctx, `SELECT a.attname, format_type(a.atttypid, a.atttypmod)
		FROM pg_index i
		CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
		WHERE i.indrelid = $1 AND i.indisprimary ORDER BY k.ord`, oid)
	if err != nil {
		return f, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, t string
		if err := rows.Scan(&k, &t); err != nil {
			return f, false, err
		}
		f.keys = append(f.keys, branch.QuoteIdent(k))
		f.keyTypes = append(f.keyTypes, t)
	}
	return f, true, rows.Err()
}

// shapeWhere is the database's filter for rows that may hold a number.
func (c *migCol) shapeWhere() string {
	return c.col + "::text ~ " + branch.QuoteLiteral(shapePG)
}

// rewrite is a value with its numbers replaced: the new value, how many were
// replaced, and why any were left.
func (c *migCol) rewrite(v string, key keyFor) (string, int, map[string]int) {
	if c.json {
		out, n, left, ok := rewriteJSON(v, key)
		if !ok {
			return v, 0, map[string]int{"the value is not JSON": 1}
		}
		return out, n, left
	}
	return rewriteText(v, key)
}

// needsLegacy is whether a number found in this column, as a JSON number or
// not, should get a legacy key when it is first put in the vault.
func (c *migCol) needsLegacy(format string, jsonNumber bool) bool {
	switch format {
	case vault.FormatLegacy:
		return true
	case vault.FormatOpaque:
		return false
	}
	return c.legacy || jsonNumber
}

// collectNumbers reads a column's rows that may hold a number, and adds each
// number to numbers, marked when some place needs it legacy.
func collectNumbers(ctx context.Context, conn *pgx.Conn, c *migCol, format string, numbers map[string]bool) error {
	return readRows(ctx, conn, c, false, func(_ []string, v string) {
		row := 0
		c.rewrite(v, func(d string, jsonNumber bool) (string, bool, string) {
			row++
			numbers[d] = numbers[d] || c.needsLegacy(format, jsonNumber)
			return "", false, "counted"
		})
		if row > 0 {
			c.report.Rows++
			c.report.Numbers += int64(row)
		}
	})
}

// readRows reads, in a read-only transaction with a time limit, the rows of a
// column that may hold a number: with their keys as text when withKeys.
func readRows(ctx context.Context, conn *pgx.Conn, c *migCol, withKeys bool, each func(keys []string, v string)) error {
	sel := []string{c.col + "::text"}
	if withKeys {
		for _, k := range c.keys {
			sel = append(sel, k+"::text")
		}
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d; SET LOCAL lock_timeout = '10s'", migrateStatement.Milliseconds())); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, fmt.Sprintf("SELECT %s FROM %s WHERE %s", strings.Join(sel, ", "), c.tbl, c.shapeWhere()))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		vals := make([]*string, len(sel))
		dest := make([]any, len(sel))
		for i := range vals {
			dest[i] = &vals[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		if vals[0] == nil {
			continue
		}
		keys := make([]string, 0, len(sel)-1)
		null := false
		for _, k := range vals[1:] {
			if k == nil {
				null = true
				break
			}
			keys = append(keys, *k)
		}
		if !null {
			each(keys, *vals[0])
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// tokeniseNumbers puts every number in the vault: those some place needs as
// legacy first, so they are made legacy if they are new.
func tokeniseNumbers(numbers map[string]bool, refs map[string]string, r branch.VaultMigrateRun, m *branch.VaultMigration) error {
	var legacy, opaque []string
	for d, l := range numbers {
		if _, done := refs[d]; done {
			continue
		}
		if l {
			legacy = append(legacy, d)
		} else {
			opaque = append(opaque, d)
		}
	}
	sort.Strings(legacy)
	sort.Strings(opaque)
	for _, g := range []struct {
		values []string
		format string
	}{{legacy, vault.FormatLegacy}, {opaque, vault.FormatOpaque}} {
		for i := 0; i < len(g.values); i += migrateTokenise {
			batch := g.values[i:min(i+migrateTokenise, len(g.values))]
			keys, made, err := r.Tokenise(batch, g.format)
			if err != nil {
				return fmt.Errorf("putting numbers in the vault: %w", err)
			}
			for j, d := range batch {
				refs[d] = keys[j]
			}
			m.Made += int64(made)
			m.Reused += int64(len(batch) - made)
		}
	}
	return nil
}

// keyIn is the key for a number in this column: the vault's, if the column can
// hold it.
func (c *migCol) keyIn(kind *vault.Kind, refs map[string]string) keyFor {
	return func(d string, jsonNumber bool) (string, bool, string) {
		k, ok := refs[d]
		if !ok || k == "" {
			return "", false, leftNoKey
		}
		legacy := kind.IsLegacy(k)
		switch {
		case c.json && jsonNumber:
			return k, !legacy, ""
		case c.legacy && !legacy:
			return "", false, leftOpaque
		}
		return k, false, ""
	}
}

type rowChange struct {
	keys     []string
	old, new string
}

// moveColumn rewrites a column, pass by pass, until a pass finds nothing it
// can replace; what that pass finds is what is left. It returns the passes
// that wrote.
func moveColumn(ctx context.Context, conn *pgx.Conn, c *migCol, kind *vault.Kind, refs map[string]string, r branch.VaultMigrateRun, m *branch.VaultMigration) (int, error) {
	key := c.keyIn(kind, refs)
	for pass := 1; ; pass++ {
		var changes []rowChange
		left := map[string]int64{}
		var leftRows int64
		unknown := map[string]bool{}
		err := readRows(ctx, conn, c, true, func(keys []string, v string) {
			// A number put in since the first read has no key yet.
			c.rewrite(v, func(d string, jsonNumber bool) (string, bool, string) {
				if _, ok := refs[d]; !ok {
					unknown[d] = unknown[d] || c.needsLegacy(r.Format, jsonNumber)
				}
				return "", false, "counted"
			})
			nv, n, why := c.rewrite(v, key)
			if n > 0 && c.maxLen > 0 && !c.legacy && utf8.RuneCountInString(nv) > c.maxLen {
				nv, n, why = v, 0, map[string]int{leftTooLong: len(aadhaarSpans(v))}
			}
			if n > 0 {
				changes = append(changes, rowChange{keys, v, nv})
			}
			if len(why) > 0 && n == 0 {
				leftRows++
				for w, k := range why {
					left[w] += int64(k)
				}
			}
		})
		if err != nil {
			c.report.LeftWhy = map[string]int64{"reading it failed: " + err.Error(): 1}
			c.report.Left = max(c.report.Left, 1)
			return pass - 1, nil
		}
		if len(unknown) > 0 && pass <= migratePasses {
			if err := tokeniseNumbers(unknown, refs, r, m); err != nil {
				return pass - 1, err
			}
			pass-- // read again, now with keys for them
			continue
		}
		if len(changes) == 0 || pass > migratePasses {
			// A row with something replaced and something left counts as left
			// on the next read, so it is read once more here.
			c.report.Left = leftRows + int64(len(changes))
			if len(changes) > 0 {
				left["written again while the run ran, after its last pass"] += int64(len(changes))
			}
			if len(left) > 0 {
				c.report.LeftWhy = left
			} else {
				c.report.LeftWhy = nil
			}
			return pass - 1, nil
		}
		for i := 0; i < len(changes); i += migrateBatch {
			n, err := writeBatch(ctx, conn, c, changes[i:min(i+migrateBatch, len(changes))])
			if err != nil {
				c.report.LeftWhy = map[string]int64{"writing it failed: " + err.Error(): 1}
				c.report.Left = max(c.report.Left, 1)
				return pass, nil
			}
			c.report.Replaced += n
		}
	}
}

// writeBatch writes a batch of rows' new values, each only where the row
// still holds the value read, in one transaction with a time limit.
func writeBatch(ctx context.Context, conn *pgx.Conn, c *migCol, changes []rowChange) (int64, error) {
	cols := len(c.keys)
	arrays := make([][]string, cols+2)
	for _, ch := range changes {
		for i, k := range ch.keys {
			arrays[i] = append(arrays[i], k)
		}
		arrays[cols] = append(arrays[cols], ch.old)
		arrays[cols+1] = append(arrays[cols+1], ch.new)
	}
	params := make([]string, cols+2)
	names := make([]string, cols+2)
	args := make([]any, cols+2)
	var match []string
	for i := range params {
		params[i] = fmt.Sprintf("$%d::text[]", i+1)
		args[i] = arrays[i]
		if i < cols {
			names[i] = fmt.Sprintf("k%d", i)
			match = append(match, fmt.Sprintf("t.%s = v.k%d::%s", c.keys[i], i, c.keyType[i]))
		}
	}
	names[cols], names[cols+1] = "o", "n"
	match = append(match, "t."+c.col+"::text = v.o")
	sql := fmt.Sprintf("UPDATE %s AS t SET %s = v.n::%s FROM unnest(%s) AS v(%s) WHERE %s",
		c.tbl, c.col, c.typ, strings.Join(params, ", "), strings.Join(names, ", "), strings.Join(match, " AND "))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d; SET LOCAL lock_timeout = '30s'", migrateStatement.Milliseconds())); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx.Commit(ctx)
}
