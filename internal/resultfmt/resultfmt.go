// SPDX-License-Identifier: AGPL-3.0-or-later

// Package resultfmt writes a query result as CSV, tab-separated values,
// Markdown, JSON or INSERT statements: what `fox sql --format` prints, and
// what the console's Copy menu puts on the clipboard.
//
// The console does the same in TypeScript (web/src/copyformat.ts), because it
// copies what is already on screen and should not ask the server again. The
// two are held to one behaviour by one set of cases both test suites read,
// web/src/copyformat.vectors.json: a change to either that the other does not
// share fails a test.
//
// Values are what the query API returns: nil, bool, string, and numbers
// (int64 or float64 from the engine, json.Number or float64 from JSON). JSON
// and numeric columns arrive as text, and stay text.
package resultfmt

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Options say how to write a result.
type Options struct {
	Format string // csv, tsv, markdown (md), json, insert
	// Header writes the column names first, for CSV and TSV. Markdown always
	// has one, and JSON and INSERT name the columns in every row.
	Header bool
	// Safe escapes text that a spreadsheet would run as a formula, for CSV and
	// TSV: a cell that begins with = + - @, a tab, a carriage return or a line
	// feed (or a full-width = + - @) gets a leading apostrophe. Numbers,
	// negative ones included, are left alone (OWASP's CSV injection advice).
	Safe bool
	// Table is the table INSERT statements name.
	Table string
}

// Formats lists the formats, as `--format` takes them.
var Formats = []string{"csv", "tsv", "markdown", "json", "insert"}

// Format writes cols and rows in the chosen format, ending with a newline
// when there is anything to write.
func Format(cols []string, rows [][]any, o Options) (string, error) {
	switch o.Format {
	case "csv":
		return delimited(cols, rows, ',', o), nil
	case "tsv":
		return delimited(cols, rows, '\t', o), nil
	case "markdown", "md":
		return markdown(cols, rows), nil
	case "json":
		return jsonRows(cols, rows)
	case "insert":
		if strings.TrimSpace(o.Table) == "" {
			return "", fmt.Errorf("INSERT statements need a table name")
		}
		return inserts(cols, rows, o.Table), nil
	}
	return "", fmt.Errorf("unknown format %q (one of %s)", o.Format, strings.Join(Formats, ", "))
}

// text is a value as a cell shows it, and whether it was SQL NULL.
func text(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", true
	case string:
		return t, false
	case bool:
		if t {
			return "true", false
		}
		return "false", false
	case json.Number:
		return t.String(), false
	case int:
		return strconv.Itoa(t), false
	case int16:
		return strconv.FormatInt(int64(t), 10), false
	case int32:
		return strconv.FormatInt(int64(t), 10), false
	case int64:
		return strconv.FormatInt(t, 10), false
	case float32:
		return jsNumber(float64(t)), false
	case float64:
		return jsNumber(t), false
	}
	return fmt.Sprintf("%v", v), false
}

func isNumber(v any) bool {
	switch v.(type) {
	case json.Number, int, int16, int32, int64, float32, float64:
		return true
	}
	return false
}

// jsNumber writes a float as JavaScript's String(n) does, so the console and
// the CLI agree: plain digits from 1e-6 up to 1e21, exponent notation outside.
func jsNumber(f float64) string {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	a := math.Abs(f)
	if a == 0 || (a >= 1e-6 && a < 1e21) {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // 1e+21, 1.5e-08
	mant, exp, _ := strings.Cut(s, "e")
	sign, digits := exp[:1], strings.TrimLeft(exp[1:], "0")
	return mant + "e" + sign + digits
}

var looksNumeric = regexp.MustCompile(`^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$`)

// formulaStart reports whether a spreadsheet would read s as a formula.
func formulaStart(s string) bool {
	if s == "" {
		return false
	}
	for _, p := range []string{"=", "+", "-", "@", "\t", "\r", "\n", "＝", "＋", "－", "＠"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// delimited writes CSV or TSV: a field is quoted when it holds the delimiter,
// a double quote, a carriage return or a line feed, with quotes doubled (RFC
// 4180). NULL is an empty field.
func delimited(cols []string, rows [][]any, sep rune, o Options) string {
	var b strings.Builder
	if o.Header {
		head := make([]any, len(cols))
		for i, c := range cols {
			head[i] = c
		}
		b.WriteString(delimitedLine(head, sep, false))
	}
	for _, r := range rows {
		b.WriteString(delimitedLine(r, sep, o.Safe))
	}
	return b.String()
}

// delimitedLine is one CSV or TSV line, with its line feed.
func delimitedLine(vals []any, sep rune, safe bool) string {
	fs := make([]string, len(vals))
	for i, v := range vals {
		s, _ := text(v)
		if safe && !isNumber(v) && !looksNumeric.MatchString(s) && formulaStart(s) {
			s = "'" + s
		}
		if strings.ContainsRune(s, sep) || strings.ContainsAny(s, "\"\r\n") {
			s = `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
		}
		fs[i] = s
	}
	return strings.Join(fs, string(sep)) + "\n"
}

// markdown writes a GitHub-flavoured table. A pipe is escaped, a line break
// becomes <br>, and NULL is written NULL, as the console's grid shows it.
func markdown(cols []string, rows [][]any) string {
	cell := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, "|", `\|`)
		s = strings.ReplaceAll(s, "\r\n", "<br>")
		s = strings.ReplaceAll(s, "\n", "<br>")
		return strings.ReplaceAll(s, "\r", "<br>")
	}
	var b strings.Builder
	head := make([]string, len(cols))
	rule := make([]string, len(cols))
	for i, c := range cols {
		head[i], rule[i] = cell(c), "---"
	}
	b.WriteString("| " + strings.Join(head, " | ") + " |\n")
	b.WriteString("| " + strings.Join(rule, " | ") + " |\n")
	for _, r := range rows {
		fs := make([]string, len(r))
		for i, v := range r {
			s, null := text(v)
			if null {
				s = "NULL"
			}
			fs[i] = cell(s)
		}
		b.WriteString("| " + strings.Join(fs, " | ") + " |\n")
	}
	return b.String()
}

// keys makes column names usable as JSON keys: a repeated name gets _2, _3.
func keys(cols []string) []string {
	out := make([]string, len(cols))
	seen := map[string]int{}
	for i, c := range cols {
		seen[c]++
		out[i] = c
		if n := seen[c]; n > 1 {
			out[i] = fmt.Sprintf("%s_%d", c, n)
		}
	}
	return out
}

// jsonRows writes an array of objects, one per row, keys in column order,
// two-space indented as the console's row view is.
func jsonRows(cols []string, rows [][]any) (string, error) {
	ks := keys(cols)
	if len(rows) == 0 {
		return "[]\n", nil
	}
	var b strings.Builder
	b.WriteString("[\n")
	for ri, r := range rows {
		o, err := jsonObject(ks, r)
		if err != nil {
			return "", err
		}
		b.WriteString(o)
		if ri < len(rows)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("]\n")
	return b.String(), nil
}

// marshal is json.Marshal without HTML escaping, as JSON.stringify writes.
func marshal(v any) ([]byte, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(sb.String(), "\n")), nil
}

// reserved are words that cannot be a bare identifier in an INSERT's column
// list or table name, and so are quoted (PostgreSQL's reserved keywords).
var reserved = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`all analyse analyze and any array as asc asymmetric both case cast check
		collate column constraint create current_catalog current_date current_role current_time
		current_timestamp current_user default deferrable desc distinct do else end except false fetch
		for foreign from grant group having in initially intersect into lateral leading limit localtime
		localtimestamp not null offset on only or order placing primary references returning select
		session_user some symmetric system_user table then to trailing true union unique user using
		variadic when where window with`) {
		reserved[w] = true
	}
}

var bareIdent = regexp.MustCompile(`^[a-z_][a-z0-9_$]*$`)

// Ident quotes a name for SQL unless it can stand bare.
func Ident(s string) string {
	if bareIdent.MatchString(s) && !reserved[s] {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// tableName quotes each part of schema.table that needs it. A name already
// written with quotes is kept as it is.
func tableName(t string) string {
	t = strings.TrimSpace(t)
	if strings.Contains(t, `"`) {
		return t
	}
	parts := strings.Split(t, ".")
	for i, p := range parts {
		parts[i] = Ident(p)
	}
	return strings.Join(parts, ".")
}

// literal writes a value as SQL: NULL, TRUE/FALSE, a number as it is, and text
// in single quotes with quotes doubled.
func literal(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case bool:
		if t {
			return "TRUE"
		}
		return "FALSE"
	}
	s, _ := text(v)
	if isNumber(v) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// inserts writes one INSERT per row.
func inserts(cols []string, rows [][]any, table string) string {
	qc := make([]string, len(cols))
	for i, c := range cols {
		qc[i] = Ident(c)
	}
	prefix := "INSERT INTO " + tableName(table) + " (" + strings.Join(qc, ", ") + ") VALUES ("
	var b strings.Builder
	for _, r := range rows {
		vs := make([]string, len(r))
		for i, v := range r {
			vs[i] = literal(v)
		}
		b.WriteString(prefix + strings.Join(vs, ", ") + ");\n")
	}
	return b.String()
}
