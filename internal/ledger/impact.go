// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	_ "embed"
	"strings"
	"unicode"
)

// SchemaImpact is the idempotent SQL for Blackbox impact analysis
// (bb.blast_radius). Apply it after the other Blackbox schemas.
//
//go:embed impact.sql
var SchemaImpact string

// Target is the object a statement changes, as found in its text.
type Target struct {
	Object string // as written, quotes kept (e.g. public."Orders"), for to_regclass
	Column string // the column's name (unquoted, folded like PostgreSQL), "" if none
	Action string // drop | drop-column | alter-column-type | alter-column | rename | rename-column | truncate | alter | create-index | grant | revoke
}

// Destructive reports whether the change can lose data or break code that reads
// the object.
func (t Target) Destructive() bool {
	switch t.Action {
	case "drop", "drop-column", "alter-column-type", "truncate", "rename", "rename-column":
		return true
	}
	return false
}

type sqlToken struct {
	raw    string // as written
	val    string // identifier value: unquoted, folded
	quoted bool
	punct  bool
}

// keyword reports whether the token is the unquoted keyword kw (case-insensitive).
func (t sqlToken) keyword(kw string) bool {
	return !t.quoted && !t.punct && strings.EqualFold(t.raw, kw)
}

func (t sqlToken) ident() bool { return !t.punct }

// tokenizeSQL splits the first statement of sql into words, quoted identifiers
// and punctuation, skipping comments and stopping at a semicolon.
func tokenizeSQL(sql string, max int) []sqlToken {
	var toks []sqlToken
	rs := []rune(sql)
	for i := 0; i < len(rs) && len(toks) < max; {
		r := rs[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '-' && i+1 < len(rs) && rs[i+1] == '-':
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
		case r == '/' && i+1 < len(rs) && rs[i+1] == '*':
			i += 2
			for i+1 < len(rs) && !(rs[i] == '*' && rs[i+1] == '/') {
				i++
			}
			i += 2
		case r == ';':
			return toks
		case r == '"':
			j := i + 1
			var val strings.Builder
			for j < len(rs) {
				if rs[j] == '"' {
					if j+1 < len(rs) && rs[j+1] == '"' {
						val.WriteRune('"')
						j += 2
						continue
					}
					break
				}
				val.WriteRune(rs[j])
				j++
			}
			end := j + 1
			if end > len(rs) {
				end = len(rs)
			}
			toks = append(toks, sqlToken{raw: string(rs[i:end]), val: val.String(), quoted: true})
			i = end
		case unicode.IsLetter(r) || r == '_' || unicode.IsDigit(r) || r == '$':
			j := i
			for j < len(rs) && (unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j]) || rs[j] == '_' || rs[j] == '$') {
				j++
			}
			w := string(rs[i:j])
			toks = append(toks, sqlToken{raw: w, val: strings.ToLower(w)})
			i = j
		default:
			toks = append(toks, sqlToken{raw: string(r), val: string(r), punct: true})
			i++
		}
	}
	return toks
}

// ParseTarget finds the table, view, index or sequence (and column) a DDL
// statement changes. It returns false when the statement has no such target it
// recognises. Only the first object of a multi-object DROP is returned.
func ParseTarget(sql string) (Target, bool) {
	toks := tokenizeSQL(sql, 256)
	at := func(i int, kws ...string) bool {
		if i+len(kws) > len(toks) {
			return false
		}
		for k, kw := range kws {
			if !toks[i+k].keyword(kw) {
				return false
			}
		}
		return true
	}
	// name reads a possibly schema-qualified identifier at i.
	name := func(i int) (string, int, bool) {
		if i >= len(toks) || !toks[i].ident() {
			return "", i, false
		}
		parts := []string{toks[i].raw}
		i++
		for len(parts) < 3 && i+1 < len(toks) && toks[i].punct && toks[i].raw == "." && toks[i+1].ident() {
			parts = append(parts, toks[i+1].raw)
			i += 2
		}
		return strings.Join(parts, "."), i, true
	}
	skip := func(i int, kws ...string) int {
		if at(i, kws...) {
			return i + len(kws)
		}
		return i
	}
	objectType := func(i int) (int, bool) {
		for _, kws := range [][]string{{"MATERIALIZED", "VIEW"}, {"FOREIGN", "TABLE"}, {"TABLE"}, {"VIEW"}, {"INDEX"}, {"SEQUENCE"}} {
			if at(i, kws...) {
				return i + len(kws), true
			}
		}
		return i, false
	}
	colName := func(i int) (string, int, bool) {
		if i >= len(toks) || !toks[i].ident() {
			return "", i, false
		}
		return toks[i].val, i + 1, true
	}

	switch {
	case at(0, "DROP"):
		i, ok := objectType(1)
		if !ok {
			return Target{}, false
		}
		i = skip(i, "CONCURRENTLY")
		i = skip(i, "IF", "EXISTS")
		obj, _, ok := name(i)
		return Target{Object: obj, Action: "drop"}, ok

	case at(0, "TRUNCATE"):
		i := skip(1, "TABLE")
		i = skip(i, "ONLY")
		obj, _, ok := name(i)
		return Target{Object: obj, Action: "truncate"}, ok

	case at(0, "ALTER"):
		i, ok := objectType(1)
		if !ok {
			return Target{}, false
		}
		i = skip(i, "IF", "EXISTS")
		i = skip(i, "ONLY")
		obj, i, ok := name(i)
		if !ok {
			return Target{}, false
		}
		t := Target{Object: obj, Action: "alter"}
		for j := i; j < len(toks); j++ {
			switch {
			case at(j, "RENAME", "TO"):
				t.Action = "rename"
				return t, true
			case at(j, "RENAME"):
				k := skip(j+1, "COLUMN")
				if at(k, "CONSTRAINT") {
					return t, true
				}
				if c, k2, ok := colName(k); ok && at(k2, "TO") {
					t.Column, t.Action = c, "rename-column"
				}
				return t, true
			case at(j, "DROP", "COLUMN"):
				k := skip(j+2, "IF", "EXISTS")
				if c, _, ok := colName(k); ok {
					t.Column, t.Action = c, "drop-column"
				}
				return t, true
			case at(j, "DROP") && !at(j+1, "CONSTRAINT") && !at(j+1, "DEFAULT") && !at(j+1, "NOT") &&
				!at(j+1, "EXPRESSION") && !at(j+1, "IDENTITY"):
				k := skip(j+1, "IF", "EXISTS")
				if c, _, ok := colName(k); ok {
					t.Column, t.Action = c, "drop-column"
				}
				return t, true
			case at(j, "ALTER"):
				k := skip(j+1, "COLUMN")
				c, k, ok := colName(k)
				if !ok {
					return t, true
				}
				t.Column, t.Action = c, "alter-column"
				if at(k, "TYPE") || at(k, "SET", "DATA", "TYPE") {
					t.Action = "alter-column-type"
				}
				return t, true
			}
		}
		return t, true

	case at(0, "CREATE"):
		for j := 1; j < len(toks); j++ {
			if at(j, "INDEX") {
				for k := j + 1; k < len(toks); k++ {
					if at(k, "ON") {
						obj, _, ok := name(skip(k+1, "ONLY"))
						return Target{Object: obj, Action: "create-index"}, ok
					}
				}
				return Target{}, false
			}
			if at(j, "TABLE") || at(j, "VIEW") || at(j, "FUNCTION") || at(j, "PROCEDURE") {
				return Target{}, false
			}
		}
		return Target{}, false

	case at(0, "GRANT"), at(0, "REVOKE"):
		action := strings.ToLower(toks[0].raw)
		for j := 1; j < len(toks); j++ {
			if at(j, "ON") {
				k := j + 1
				if at(k, "ALL") || at(k, "SCHEMA") || at(k, "FUNCTION") || at(k, "DATABASE") || at(k, "SEQUENCE") && at(k+1, "ALL") {
					return Target{}, false
				}
				k = skip(k, "TABLE")
				k = skip(k, "SEQUENCE")
				obj, _, ok := name(k)
				return Target{Object: obj, Action: action}, ok
			}
		}
		return Target{}, false
	}
	return Target{}, false
}
