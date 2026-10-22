// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// "Did you mean `customers`?" (point 9.2). When Postgres says a table or a
// column does not exist, look for the name that was probably meant and say so,
// with what to write instead, so the console can offer a one-click fix and
// `fox sql` can print it.
//
// Only names the caller can see are offered: tables they may SELECT from, and
// for a column only the columns of tables the statement names. A suggestion is
// made only when one name is clearly closest. Two equally close, or nothing
// close enough, is no suggestion: a confident wrong guess is worse than none.

// Suggestion is a name that was probably meant.
type Suggestion struct {
	Kind   string `json:"kind"`   // table or column
	Wrong  string `json:"wrong"`  // as Postgres reported it
	Right  string `json:"right"`  // the name that exists
	Insert string `json:"insert"` // what to write: quoted when it must be
}

var (
	reMissingRelation = regexp.MustCompile(`relation "([^"]+)" does not exist`)
	reMissingColumn   = regexp.MustCompile(`column (?:"([^"]+)"|([^ ]+)) does not exist`)
	// Postgres's own guess for a column, when it has exactly one.
	rePgColumnHint = regexp.MustCompile(`^Perhaps you meant to reference the column "(?:[^".]+\.)?([^"]+)"\.$`)
)

// suggestFor reads a failed statement's error and, when it names a table or a
// column that does not exist, finds the one probably meant. conn must be usable
// again (the failed statement's transaction over).
func suggestFor(ctx context.Context, conn *pgx.Conn, sql string, err error) *Suggestion {
	var pg *pgconn.PgError
	if conn == nil || !errors.As(err, &pg) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	switch pg.Code {
	case "42P01": // undefined_table
		m := reMissingRelation.FindStringSubmatch(pg.Message)
		if m == nil {
			return nil
		}
		wrong := m[1]
		schema, name := "", wrong
		if i := strings.LastIndex(wrong, "."); i > 0 {
			schema, name = wrong[:i], wrong[i+1:]
		}
		tables, err := visibleTables(ctx, conn)
		if err != nil {
			return nil
		}
		var names []string
		for _, t := range tables {
			if schema == "" || strings.EqualFold(t[0], schema) {
				names = append(names, t[1])
			}
		}
		right, ok := closest(name, names)
		if !ok {
			return nil
		}
		return &Suggestion{Kind: "table", Wrong: name, Right: right, Insert: quoteIdentIfNeeded(right)}
	case "42703": // undefined_column
		m := reMissingColumn.FindStringSubmatch(pg.Message)
		if m == nil {
			return nil
		}
		wrong := m[1] + m[2]
		if i := strings.LastIndex(wrong, "."); i >= 0 {
			wrong = wrong[i+1:]
		}
		if h := rePgColumnHint.FindStringSubmatch(pg.Hint); h != nil {
			return &Suggestion{Kind: "column", Wrong: wrong, Right: h[1], Insert: quoteIdentIfNeeded(h[1])}
		}
		cols, err := columnsOfNamedTables(ctx, conn, sql)
		if err != nil {
			return nil
		}
		right, ok := closest(wrong, cols)
		if !ok {
			return nil
		}
		return &Suggestion{Kind: "column", Wrong: wrong, Right: right, Insert: quoteIdentIfNeeded(right)}
	}
	return nil
}

// visibleTables is every table, view and foreign table the caller may read,
// outside the system schemas, as [schema, name].
func visibleTables(ctx context.Context, conn *pgx.Conn) ([][2]string, error) {
	rows, err := conn.Query(ctx, `SELECT n.nspname, c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r','p','v','m','f')
		  AND n.nspname NOT IN ('pg_catalog','information_schema','bb_f1') AND n.nspname NOT LIKE 'pg_toast%'
		  AND has_table_privilege(c.oid, 'SELECT')
		LIMIT 20000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var s, n string
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out = append(out, [2]string{s, n})
	}
	return out, rows.Err()
}

// columnsOfNamedTables is the columns of the tables a statement names: any
// visible table whose name appears in it as a word. Guessing a column from
// every table in the database would offer names from tables the statement
// never touches.
func columnsOfNamedTables(ctx context.Context, conn *pgx.Conn, sql string) ([]string, error) {
	tables, err := visibleTables(ctx, conn)
	if err != nil {
		return nil, err
	}
	lower := strings.ToLower(sql)
	var oids []string
	seen := map[string]bool{}
	for _, t := range tables {
		if namedIn(lower, strings.ToLower(t[1])) && !seen[t[0]+"."+t[1]] {
			seen[t[0]+"."+t[1]] = true
			oids = append(oids, quoteIdent(t[0])+"."+quoteIdent(t[1]))
		}
	}
	if len(oids) == 0 {
		return nil, nil
	}
	rows, err := conn.Query(ctx, `SELECT DISTINCT a.attname FROM pg_attribute a
		WHERE a.attrelid = ANY($1::regclass[]) AND a.attnum > 0 AND NOT a.attisdropped`, oids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// namedIn reports whether name appears in sql as a whole word.
func namedIn(sql, name string) bool {
	for i := 0; ; {
		j := strings.Index(sql[i:], name)
		if j < 0 {
			return false
		}
		a, b := i+j, i+j+len(name)
		if (a == 0 || !identChar(sql[a-1])) && (b == len(sql) || !identChar(sql[b])) {
			return true
		}
		i = a + 1
	}
}

func identChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// closest is the one candidate nearest to wrong, ignoring case, when it is
// clearly the nearest and near enough: at most a third of the name's length in
// edits (at least one), and no other candidate as near.
func closest(wrong string, candidates []string) (string, bool) {
	w := strings.ToLower(wrong)
	limit := max(1, len([]rune(w))/3)
	best, bestD, tie := "", limit+1, false
	for _, c := range candidates {
		if c == wrong {
			continue // it exists as typed: something else is wrong
		}
		d := editDistance(w, strings.ToLower(c))
		switch {
		case d < bestD:
			best, bestD, tie = c, d, false
		case d == bestD && !strings.EqualFold(c, best):
			tie = true
		}
	}
	if best == "" || tie || bestD > limit {
		return "", false
	}
	return best, true
}

// editDistance is the optimal string alignment distance: insertions,
// deletions, substitutions, and swapping two neighbours, each one edit, which
// is how names are mistyped.
func editDistance(a, b string) int {
	x, y := []rune(a), []rune(b)
	d := make([][]int, len(x)+1)
	for i := range d {
		d[i] = make([]int, len(y)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(x); i++ {
		for j := 1; j <= len(y); j++ {
			cost := 1
			if x[i-1] == y[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && x[i-1] == y[j-2] && x[i-2] == y[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(x)][len(y)]
}

var plainIdent = regexp.MustCompile(`^[a-z_][a-z0-9_$]*$`)

// quoteIdentIfNeeded writes a name the way SQL must spell it: as it is when it
// is lower case and plain, in double quotes otherwise.
func quoteIdentIfNeeded(s string) string {
	if plainIdent.MatchString(s) && !reservedWord[s] {
		return s
	}
	return quoteIdent(s)
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// The reserved words a table or column name cannot be written as without
// quotes; the common ones, which is where a real name collides.
var reservedWord = map[string]bool{
	"all": true, "and": true, "any": true, "as": true, "asc": true, "case": true, "check": true,
	"column": true, "constraint": true, "create": true, "default": true, "desc": true, "distinct": true,
	"do": true, "else": true, "end": true, "false": true, "for": true, "foreign": true, "from": true,
	"grant": true, "group": true, "having": true, "in": true, "limit": true, "not": true, "null": true,
	"offset": true, "on": true, "or": true, "order": true, "primary": true, "references": true,
	"select": true, "table": true, "then": true, "to": true, "true": true, "union": true, "unique": true,
	"user": true, "using": true, "when": true, "where": true, "with": true,
}
