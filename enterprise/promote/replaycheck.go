//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package promote

import (
	"errors"
	"fmt"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// What a request may carry.
//
// An entry's statement is the source's whole current_query(): everything its
// author sent in one message, which can be more than the change it was recorded
// for. Replayed onto the target, a COMMIT in it ends the one transaction the
// request is applied in, and a SET ROLE or SET bb.actor changes who the rest
// runs as, or is recorded as. So a request is refused if any statement in any
// entry would do that: when it is asked for, and again when it is applied,
// because what is applied is a stored snapshot.
//
// This is the Go counterpart of bb._sql_statements, and stricter, because here a
// misread is a way in rather than a wrong risk label. It follows the server's
// own lexer where that function does not: a line comment also ends at a carriage
// return, an E'' string keeps its escapes across a newline-separated
// continuation, an identifier runs through any '$' in it, and a semicolon inside
// parentheses or a BEGIN ATOMIC body does not end the statement. Text it cannot
// read is refused, not passed.
//
// What it cannot see is SQL assembled at run time, or held in a function that the
// same message calls. Those run with the applying role's rights and nothing more:
// a COMMIT there is an error inside a transaction block, and the role has no
// other role to become (apply).

type tokenKind int

const (
	tokWord    tokenKind = iota // a keyword or unquoted name, in lower case
	tokQuoted                   // a "quoted name", in lower case: settings ignore case
	tokEscaped                  // a U&"name" with escapes, whose meaning is not worked out
	tokString                   // any string literal
	tokPunct                    // one character of anything else
)

type token struct {
	kind tokenKind
	text string
	// plain is a string token whose text is exactly its value: no escapes to
	// interpret. Set for '…' and $…$ only.
	plain bool
}

func (t token) is(kind tokenKind, text string) bool { return t.kind == kind && t.text == text }

var errUnreadable = errors.New("its quoting or comments do not close")

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}
func isDigit(c byte) bool     { return c >= '0' && c <= '9' }
func isTagStart(c byte) bool  { return c == '_' || c >= 0x80 || lower(c) >= 'a' && lower(c) <= 'z' }
func isIdentCont(c byte) bool { return isTagStart(c) || isDigit(c) || c == '$' }

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// lexSQL splits a message into tokens as the server's scanner would.
func lexSQL(q string) ([]token, error) {
	if strings.IndexByte(q, 0) >= 0 {
		return nil, errors.New("it holds a NUL byte")
	}
	var out []token
	n := len(q)
	for i := 0; i < n; {
		c := q[i]
		switch {
		case isSpace(c):
			i++
		case strings.HasPrefix(q[i:], "--"):
			i = lineEnd(q, i)
		case strings.HasPrefix(q[i:], "/*"):
			end, err := blockCommentEnd(q, i)
			if err != nil {
				return nil, err
			}
			i = end
		case c == '\'':
			t, end, err := lexString(q, i, false)
			if err != nil {
				return nil, err
			}
			t.plain = true
			out, i = append(out, t), end
		case c == '"':
			t, end, err := lexQuoted(q, i)
			if err != nil {
				return nil, err
			}
			out, i = append(out, t), end
		case c == '$':
			t, end, err := lexDollar(q, i)
			if err != nil {
				return nil, err
			}
			out, i = append(out, t), end
		case isDigit(c):
			for i < n && isDigit(q[i]) {
				i++
			}
		case isTagStart(c):
			t, end, err := lexWord(q, i)
			if err != nil {
				return nil, err
			}
			out, i = append(out, t), end
		default:
			out = append(out, token{kind: tokPunct, text: string(c)})
			i++
		}
	}
	return out, nil
}

func lineEnd(q string, i int) int {
	for i < len(q) && q[i] != '\n' && q[i] != '\r' {
		i++
	}
	return i
}

// blockCommentEnd finds the end of a /* comment */, which nests.
func blockCommentEnd(q string, i int) (int, error) {
	depth := 1
	for i += 2; i < len(q); {
		switch {
		case strings.HasPrefix(q[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(q[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				return i, nil
			}
		default:
			i++
		}
	}
	return 0, errUnreadable
}

// lexWord reads a name or keyword, and the literal it prefixes if it is one:
// the name is taken whole first, so `note'x'` is not an E” string.
func lexWord(q string, i int) (token, int, error) {
	start := i
	for i < len(q) && isIdentCont(q[i]) {
		i++
	}
	word := strings.ToLower(q[start:i])
	if i < len(q) && q[i] == '\'' {
		switch word {
		case "e":
			return lexString(q, i, true)
		case "b", "x", "n":
			return lexString(q, i, false)
		}
	}
	if word == "u" && i+1 < len(q) && q[i] == '&' {
		switch q[i+1] {
		case '\'':
			return lexString(q, i+1, false)
		case '"':
			t, end, err := lexQuoted(q, i+1)
			if err == nil && strings.Contains(t.text, `\`) {
				t.kind = tokEscaped
			}
			return t, end, err
		}
	}
	return token{kind: tokWord, text: word}, i, nil
}

// lexString reads a string from its opening quote, with any continuation: two
// literals separated by a newline are one, and the first's rules hold in both.
func lexString(q string, i int, escapes bool) (token, int, error) {
	var b strings.Builder
	for i++; i < len(q); {
		c := q[i]
		switch {
		case escapes && c == '\\':
			if i+1 >= len(q) {
				return token{}, 0, errUnreadable
			}
			b.WriteString(q[i : i+2])
			i += 2
		case c == '\'' && i+1 < len(q) && q[i+1] == '\'':
			b.WriteByte('\'')
			i += 2
		case c == '\'':
			next, ok := stringContinues(q, i+1)
			if !ok {
				return token{kind: tokString, text: b.String()}, i + 1, nil
			}
			i = next + 1
		default:
			b.WriteByte(c)
			i++
		}
	}
	return token{}, 0, errUnreadable
}

// stringContinues reports whether what follows a closing quote carries on the
// string: whitespace holding a newline, then a quote. It returns that quote.
// Line comments count as whitespace here, block comments do not.
func stringContinues(q string, i int) (int, bool) {
	newline := false
	for i < len(q) {
		switch {
		case q[i] == '\n' || q[i] == '\r':
			newline = true
			i++
		case isSpace(q[i]):
			i++
		case strings.HasPrefix(q[i:], "--"):
			i = lineEnd(q, i)
		default:
			return i, newline && q[i] == '\''
		}
	}
	return i, false
}

func lexQuoted(q string, i int) (token, int, error) {
	var b strings.Builder
	for i++; i < len(q); i++ {
		if q[i] != '"' {
			b.WriteByte(q[i])
			continue
		}
		if i+1 < len(q) && q[i+1] == '"' {
			b.WriteByte('"')
			i++
			continue
		}
		return token{kind: tokQuoted, text: strings.ToLower(b.String())}, i + 1, nil
	}
	return token{}, 0, errUnreadable
}

// lexDollar reads a $tag$ string, or a parameter or stray dollar if it is not one.
func lexDollar(q string, i int) (token, int, error) {
	j := i + 1
	if j < len(q) && isTagStart(q[j]) {
		for j < len(q) && (isTagStart(q[j]) || isDigit(q[j])) {
			j++
		}
	}
	if j < len(q) && q[j] == '$' {
		delim := q[i : j+1]
		end := strings.Index(q[j+1:], delim)
		if end < 0 {
			return token{}, 0, errUnreadable
		}
		return token{kind: tokString, text: q[j+1 : j+1+end], plain: true}, j + 1 + end + len(delim), nil
	}
	for j = i + 1; j < len(q) && isDigit(q[j]); j++ {
	}
	return token{kind: tokPunct, text: "$"}, j, nil
}

// splitStatements cuts a message at its top-level semicolons. A semicolon inside
// parentheses belongs to a CREATE RULE, and one in a BEGIN ATOMIC body to the
// function: neither ends the statement, and the grammar allows neither
// transaction control. Anything else that hides a semicolon that way does not
// parse, and the server rejects the whole message before running any of it.
func splitStatements(toks []token) [][]token {
	var out [][]token
	start, parens, atomic := 0, 0, 0
	for i, t := range toks {
		switch {
		case t.is(tokPunct, "("):
			parens++
		case t.is(tokPunct, ")"):
			if parens > 0 {
				parens--
			}
		case parens > 0:
		case t.is(tokWord, "begin") && atomic == 0 && i+1 < len(toks) &&
			toks[i+1].is(tokWord, "atomic") && isRoutine(toks[start:]):
			atomic = 1
		case t.is(tokWord, "case") && atomic > 0:
			atomic++
		case t.is(tokWord, "end") && atomic > 0:
			atomic--
		case t.is(tokPunct, ";") && atomic == 0:
			if i > start {
				out = append(out, toks[start:i])
			}
			start = i + 1
		}
	}
	if start < len(toks) {
		out = append(out, toks[start:])
	}
	return out
}

// isRoutine reports whether a statement is CREATE [OR REPLACE] FUNCTION or
// PROCEDURE, the only ones BEGIN ATOMIC can belong to.
func isRoutine(s []token) bool {
	word := func(i int) string { return wordAt(s, i) }
	if word(0) != "create" {
		return false
	}
	i := 1
	if word(1) == "or" && word(2) == "replace" {
		i = 3
	}
	return word(i) == "function" || word(i) == "procedure"
}

func wordAt(s []token, i int) string {
	if i < len(s) && s[i].kind == tokWord {
		return s[i].text
	}
	return ""
}

// transactionControl is every statement that starts, ends or rewinds a
// transaction, by its first word. A savepoint counts: rolling back to one undoes
// entries the request would still report as applied.
var transactionControl = map[string]bool{
	"begin": true, "start": true, "commit": true, "end": true, "rollback": true, "abort": true,
	"savepoint": true, "release": true,
}

// refusedSettings are the settings a replayed statement may not change. A role
// or session authorization is who the statement runs as, the bb.* settings (by
// prefix) and application_name are who the Blackbox records and whether the
// guardrail is overridden, and session_replication_role switches triggers off.
// The two encodings change how the server reads the entries after this one, and
// so whether this check read them the same way.
var refusedSettings = map[string]bool{
	"role": true, "session_authorization": true, "session_replication_role": true, "application_name": true,
	"standard_conforming_strings": true, "client_encoding": true, "names": true, "transaction": true,
}

func refusedSetting(name string) bool {
	return refusedSettings[name] || strings.HasPrefix(name, "bb.")
}

// statementRefusal says why one statement cannot be replayed, or "" if it can.
func statementRefusal(s []token) string {
	head := wordAt(s, 0)
	switch {
	case transactionControl[head]:
		return fmt.Sprintf("%s is transaction control, and a request is applied in one transaction", strings.ToUpper(head))
	case head == "prepare" && wordAt(s, 1) == "transaction":
		return "PREPARE TRANSACTION is transaction control, and a request is applied in one transaction"
	case head == "set":
		return setRefusal(s[1:], "SET")
	case head == "reset":
		return setRefusal(s[1:], "RESET")
	case head == "do":
		for _, t := range s[1:] {
			if t.kind == tokString {
				if r := bodyRefusal(t.text); r != "" {
					return "its DO block: " + r
				}
			}
		}
	}
	return setConfigRefusal(s)
}

// setRefusal judges what follows SET or RESET, down to the name of the setting.
func setRefusal(rest []token, verb string) string {
	i := 0
	if w := wordAt(rest, 0); w == "local" || (w == "session" && wordAt(rest, 1) != "authorization" && wordAt(rest, 1) != "characteristics") {
		i = 1
	}
	var name strings.Builder
	for ; i < len(rest); i++ {
		if rest[i].kind != tokWord && rest[i].kind != tokQuoted {
			return fmt.Sprintf("the setting its %s changes cannot be read", verb)
		}
		name.WriteString(rest[i].text)
		if i+1 >= len(rest) || !rest[i+1].is(tokPunct, ".") {
			break
		}
		name.WriteByte('.')
		i++
	}
	n := name.String()
	switch {
	case n == "":
		return fmt.Sprintf("the setting its %s changes cannot be read", verb)
	case n == "session" && i+1 < len(rest):
		if w := wordAt(rest, i+1); w == "authorization" || w == "characteristics" {
			return fmt.Sprintf("%s SESSION %s changes what the session is", verb, strings.ToUpper(w))
		}
	case n == "all" && verb == "RESET":
		return "RESET ALL clears the settings that attribute the request"
	case refusedSetting(n):
		return fmt.Sprintf("%s %s changes who it runs or is recorded as, or how the rest is read", verb, n)
	}
	return ""
}

// setConfigRefusal finds set_config() anywhere in a statement: SET by another
// name, and common enough with a harmless first argument that only the refused
// settings, or one that cannot be read, stop it.
func setConfigRefusal(s []token) string {
	for i, t := range s {
		if (t.kind != tokWord && t.kind != tokQuoted) || t.text != "set_config" ||
			i+1 >= len(s) || !s[i+1].is(tokPunct, "(") {
			continue
		}
		if i+3 >= len(s) || s[i+2].kind != tokString || !s[i+2].plain || !s[i+3].is(tokPunct, ",") {
			return "the setting its set_config() changes cannot be read"
		}
		if name := strings.ToLower(s[i+2].text); refusedSetting(name) {
			return fmt.Sprintf("set_config() on %s changes who it runs or is recorded as", name)
		}
	}
	return ""
}

// bodyRefusal looks inside a DO block for the same things, in literal form. A
// block is not split into statements: BEGIN and END are its own syntax there, so
// transaction control is left to the server, which refuses it inside a
// transaction block. A SET counts only where a PL/pgSQL statement can start, so
// that `UPDATE t SET role = 1` is left alone.
func bodyRefusal(body string) string {
	toks, err := lexSQL(body)
	if err != nil {
		return "it cannot be read: " + err.Error()
	}
	return tokensRefusal(toks, 0)
}

func tokensRefusal(toks []token, depth int) string {
	if r := setConfigRefusal(toks); r != "" {
		return r
	}
	for i, t := range toks {
		if t.kind == tokWord && (t.text == "set" || t.text == "reset") && startsStatement(toks, i) {
			if r := setRefusal(toks[i+1:], strings.ToUpper(t.text)); r != "" {
				return r
			}
		}
		// EXECUTE 'SET ROLE …': a string in the block may be SQL. One that does
		// not lex is not SQL, so it says nothing either way.
		if t.kind == tokString && depth < 2 {
			if inner, err := lexSQL(t.text); err == nil {
				if r := tokensRefusal(inner, depth+1); r != "" {
					return r
				}
			}
		}
	}
	return ""
}

func startsStatement(toks []token, i int) bool {
	if i == 0 || toks[i-1].is(tokPunct, ";") {
		return true
	}
	switch wordAt(toks, i-1) {
	case "begin", "then", "else", "loop":
		return true
	}
	return false
}

// replayRefusal says why a whole message cannot be replayed, or "" if it can.
func replayRefusal(statement string) string {
	toks, err := lexSQL(statement)
	if err != nil {
		return "it cannot be read: " + err.Error()
	}
	for _, t := range toks {
		if t.kind == tokEscaped || t.is(tokWord, "uescape") {
			return `it uses a U&"…" name with escapes, whose meaning this check does not work out`
		}
	}
	for _, s := range splitStatements(toks) {
		if r := statementRefusal(s); r != "" {
			return r
		}
	}
	return ""
}

// checkReplayable refuses a request holding any entry that cannot be replayed.
func checkReplayable(entries []branch.RequestEntry) error {
	var bad []string
	for _, e := range entries {
		if r := replayRefusal(e.Statement); r != "" {
			bad = append(bad, fmt.Sprintf("entry %d (%s %s): %s", e.ID, e.CommandTag, e.Object, r))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("%w:\n  %s\nNothing was applied. Make the change again on the source without those statements "+
		"(`%s blackbox` shows what it ran), or apply it by hand", branch.ErrNotReplayable, strings.Join(bad, "\n  "), brand.CLI)
}
