// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// MCP run_sql's answer goes to a model, and used to be psql's whole output,
// held in memory for up to ten minutes: one SELECT * on a large table could
// exhaust the host and send gigabytes on to the model. It now runs over pgx,
// under the same row cap as the console (1,000 per statement), a cap on the
// text returned, and a statement timeout, and says when it left rows out.
const (
	// MCPRowCap is how many rows of one statement are shown, as in the console.
	MCPRowCap = 1000
	// MCPByteCap is how much text one answer carries, about a quarter of a
	// MiB: as much as a model can usefully read.
	MCPByteCap = 256 << 10
	// DefaultMCPStatementTimeout bounds one run_sql call on the server, so a
	// query nobody is waiting for any more does not run on.
	DefaultMCPStatementTimeout = time.Minute

	// maxColWidth is the widest a column is padded to.
	maxColWidth = 64
)

// MCPStatementTimeout is FOX_MCP_STATEMENT_TIMEOUT, or a minute.
func MCPStatementTimeout() time.Duration {
	return envDurationOr("FOX_MCP_STATEMENT_TIMEOUT", DefaultMCPStatementTimeout)
}

// clientQueryCapped runs sql as login on a branch and renders the results as
// text. The login, and what it is told at login, are exactly what psql was
// given: the same role and password, and the same options string PGOPTIONS
// carried, so the Blackbox names the same actor either way.
func clientQueryCapped(branchName, sql, tool string, login engineLogin, options string) (string, error) {
	addr, err := EnsureRunning(branchName)
	if err != nil {
		return "", err
	}
	// The user is set below, not in the URL: an agent role's name holds ':' and '@'.
	cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://%s/%s", addr, pgDatabase))
	if err != nil {
		return "", err
	}
	timeout := MCPStatementTimeout()
	cfg.User, cfg.Password = login.role, login.password
	cfg.RuntimeParams["application_name"] = tool
	cfg.RuntimeParams["statement_timeout"] = fmt.Sprint(timeout.Milliseconds())
	if options != "" {
		cfg.RuntimeParams["options"] = options
	}
	c := newTextCollector(MCPRowCap, MCPByteCap)
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { c.notice(n) }

	// The client's own deadline is a little past the server's, so the server's
	// timeout is what normally ends a long query, with its own message.
	ctx, cancel := context.WithTimeout(context.Background(), timeout+10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("connecting to %q: %w", branchName, err)
	}
	defer conn.Close(context.Background())

	// The simple protocol, as psql -c used: it takes several statements in one
	// string, and runs them in one implicit transaction.
	rdr := conn.PgConn().Exec(ctx, sql)
	for rdr.NextResult() {
		rr := rdr.ResultReader()
		fds := rr.FieldDescriptions()
		cols := make([]string, len(fds))
		for i, f := range fds {
			cols[i] = f.Name
		}
		c.begin(cols)
		// Every row is read, but only those within the caps are kept: stopping
		// early would leave the connection mid-result, and cancelling would roll
		// back the statements before this one. The statement timeout bounds how
		// long the rest can take.
		for rr.NextRow() {
			c.row(rr.Values())
		}
		tag, err := rr.Close()
		c.end(tag.String(), err)
	}
	if err := rdr.Close(); err != nil {
		c.fail(err)
		out := c.String()
		return out, errors.New(out)
	}
	return c.String(), nil
}

// textCollector renders query results as psql's aligned tables, keeping no
// more than maxRows rows of a statement and maxBytes of text in all.
type textCollector struct {
	maxRows, maxBytes int
	b                 strings.Builder
	used              int  // bytes kept so far, across every statement
	cut               bool // a value of the current statement was shortened
	noticesCut        bool

	cols  []string
	rows  [][]string
	total int // rows the statement returned, kept or not
	notes []string
}

func newTextCollector(maxRows, maxBytes int) *textCollector {
	return &textCollector{maxRows: maxRows, maxBytes: maxBytes}
}

func (c *textCollector) notice(n *pgconn.Notice) {
	line := fmt.Sprintf("%s:  %s", n.Severity, n.Message)
	if c.used+len(line) <= c.maxBytes {
		c.notes = append(c.notes, line)
		c.used += len(line) + 1
	} else {
		c.noticesCut = true
	}
}

func (c *textCollector) begin(cols []string) {
	c.cols, c.rows, c.total, c.cut = cols, nil, 0, false
}

func (c *textCollector) row(vals [][]byte) {
	c.total++
	if len(c.rows) >= c.maxRows || c.used >= c.maxBytes {
		return
	}
	row := make([]string, len(vals))
	for i, v := range vals {
		if v == nil {
			continue // NULL shows as nothing, as in psql
		}
		s := string(v)
		if room := c.maxBytes - c.used; len(s) > room {
			s = truncUTF8(s, room) + "…"
			c.cut = true
		}
		c.used += len(s) + 3
		row[i] = s
	}
	c.rows = append(c.rows, row)
}

func (c *textCollector) end(tag string, err error) {
	c.flushNotes()
	if c.b.Len() > 0 {
		c.b.WriteString("\n")
	}
	if len(c.cols) > 0 {
		c.table()
	} else if tag != "" {
		c.b.WriteString(tag + "\n")
	}
	if err != nil {
		c.writeErr(err)
	}
}

func (c *textCollector) fail(err error) {
	c.flushNotes()
	// The error of the statement that failed is already written by end;
	// anything else (a lost connection, a timeout reached between results) is
	// said here.
	if !strings.Contains(c.b.String(), errText(err)) {
		c.writeErr(err)
	}
}

func (c *textCollector) flushNotes() {
	for _, n := range c.notes {
		c.b.WriteString(n + "\n")
	}
	c.notes = nil
}

func errText(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Severity + ":  " + pg.Message
	}
	return "ERROR:  " + err.Error()
}

func (c *textCollector) writeErr(err error) {
	c.b.WriteString(errText(err) + "\n")
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		if pg.Detail != "" {
			c.b.WriteString("DETAIL:  " + pg.Detail + "\n")
		}
		if pg.Hint != "" {
			c.b.WriteString("HINT:  " + pg.Hint + "\n")
		}
	}
}

// table writes one statement's result the way psql's aligned format does,
// followed by a line saying plainly when rows were left out.
func (c *textCollector) table() {
	width := make([]int, len(c.cols))
	for i, h := range c.cols {
		width[i] = utf8.RuneCountInString(h)
	}
	for _, r := range c.rows {
		for i, v := range r {
			width[i] = max(width[i], utf8.RuneCountInString(oneLine(v)))
		}
	}
	// A long value is not padded to: one wide cell would otherwise widen every
	// row, the header and the rule, past the size the answer is held to.
	for i := range width {
		width[i] = min(width[i], maxColWidth)
	}
	line := func(cells []string, center bool) {
		var l strings.Builder
		for i, v := range cells {
			if i > 0 {
				l.WriteString(" | ")
			} else {
				l.WriteString(" ")
			}
			v = oneLine(v)
			pad := max(width[i]-utf8.RuneCountInString(v), 0)
			if center {
				l.WriteString(strings.Repeat(" ", pad/2) + v + strings.Repeat(" ", pad-pad/2))
			} else {
				l.WriteString(v + strings.Repeat(" ", pad))
			}
		}
		// No trailing spaces, as psql leaves none after the last column.
		c.b.WriteString(strings.TrimRight(l.String(), " ") + "\n")
	}
	line(c.cols, true)
	for i, w := range width {
		if i > 0 {
			c.b.WriteString("+")
		}
		c.b.WriteString(strings.Repeat("-", w+2))
	}
	c.b.WriteString("\n")
	for _, r := range c.rows {
		line(r, false)
	}
	switch {
	case len(c.rows) < c.total:
		fmt.Fprintf(&c.b, "(%d rows; truncated: only the first %d are shown, at most %d rows or %d KiB per answer. Add a LIMIT or a WHERE to see the rest.)\n",
			c.total, len(c.rows), c.maxRows, c.maxBytes>>10)
	case c.cut:
		fmt.Fprintf(&c.b, "(%d rows; truncated: values were cut to keep the answer within %d KiB)\n", c.total, c.maxBytes>>10)
	case c.total == 1:
		c.b.WriteString("(1 row)\n")
	default:
		fmt.Fprintf(&c.b, "(%d rows)\n", c.total)
	}
}

func (c *textCollector) String() string {
	c.flushNotes()
	if c.noticesCut {
		c.b.WriteString("(truncated: some notices were left out to keep the answer within its size)\n")
		c.noticesCut = false
	}
	return strings.TrimRight(c.b.String(), "\n")
}

// oneLine keeps a table to one line per row, writing a value's line breaks as
// \n: psql wraps a multi-line value across lines with + markers, which is no
// easier for a model to read, and dropping the rest would lose it.
func oneLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", `\r`), "\n", `\n`)
}

// truncUTF8 cuts s to at most n bytes without splitting a character.
func truncUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
