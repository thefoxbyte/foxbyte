// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
)

// fakePG is just enough of a Postgres server to see what the console asks it
// to do: transactions, cursors, the extended and simple protocols, and how
// many rows it was made to produce. A query's size is set per SQL text.
type fakePG struct {
	t    *testing.T
	ln   net.Listener
	size map[string]int // query text -> rows it returns

	mu       sync.Mutex
	log      []string // every statement, in order
	produced int      // rows the "server" generated, all sessions together
	conns    int
	// discards is what each DISCARD ALL found: the transaction state and the
	// open cursors at that moment, which must be "I" and none.
	discards []string
}

func newFakePG(t *testing.T, size map[string]int) *fakePG {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePG{t: t, ln: ln, size: size}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakePG) cfg(t *testing.T) *pgx.ConnConfig {
	cfg, err := pgx.ParseConfig("postgres://u:p@" + f.ln.Addr().String() + "/appdb?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func (f *fakePG) note(s string) {
	f.mu.Lock()
	f.log = append(f.log, s)
	f.mu.Unlock()
}

func (f *fakePG) statements() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

type fakeErr struct{ code, msg string }

func (e *fakeErr) Error() string { return e.msg }

// fakeSession is one connection's server-side state.
type fakeSession struct {
	tx      byte           // 'I', 'T' or 'E'
	cursors map[string]int // name -> rows left
	stmts   map[string]string
	portals map[string]string
}

var (
	declareRE = regexp.MustCompile(`(?s)^DECLARE (\w+) NO SCROLL CURSOR FOR (.*)$`)
	fetchRE   = regexp.MustCompile(`^FETCH FORWARD (\d+) FROM (\w+)$`)
)

// run is one statement: its columns (nil for none), how many rows it sends,
// its tag, or an error.
func (f *fakePG) run(s *fakeSession, sql string, extended bool) (cols []string, n int, tag string, err error) {
	q := strings.TrimSpace(sql)
	f.note(q)
	if extended && strings.Contains(strings.TrimRight(q, "; \n"), ";") {
		return nil, 0, "", &fakeErr{"42601", "cannot insert multiple commands into a prepared statement"}
	}
	switch {
	case q == "BEGIN":
		s.tx = 'T'
		return nil, 0, "BEGIN", nil
	case q == "COMMIT":
		tag = "COMMIT"
		if s.tx == 'E' {
			tag = "ROLLBACK"
		}
		s.tx, s.cursors = 'I', map[string]int{}
		return nil, 0, tag, nil
	case q == "ROLLBACK":
		s.tx, s.cursors = 'I', map[string]int{}
		return nil, 0, "ROLLBACK", nil
	case strings.HasPrefix(q, "SAVEPOINT "):
		return nil, 0, "SAVEPOINT", nil
	case strings.HasPrefix(q, "ROLLBACK TO SAVEPOINT "):
		s.tx = 'T'
		return nil, 0, "ROLLBACK", nil
	case strings.HasPrefix(q, "RELEASE SAVEPOINT "):
		return nil, 0, "RELEASE", nil
	case q == "DISCARD ALL":
		f.mu.Lock()
		f.discards = append(f.discards, fmt.Sprintf("%c%d", s.tx, len(s.cursors)))
		f.mu.Unlock()
		s.cursors = map[string]int{}
		return nil, 0, "DISCARD ALL", nil
	case strings.EqualFold(q, "deallocate all"):
		return nil, 0, "DEALLOCATE ALL", nil
	case strings.HasPrefix(q, "CLOSE "):
		delete(s.cursors, strings.TrimPrefix(q, "CLOSE "))
		return nil, 0, "CLOSE CURSOR", nil
	}
	if m := declareRE.FindStringSubmatch(q); m != nil {
		if s.tx != 'T' {
			return nil, 0, "", &fakeErr{"25P01", "DECLARE CURSOR can only be used in transaction blocks"}
		}
		inner := strings.TrimRight(strings.TrimSpace(m[2]), ";")
		rows, ok := f.size[inner]
		if !ok {
			return nil, 0, "", &fakeErr{"0A000", "DECLARE CURSOR must not contain data-modifying statements in WITH"}
		}
		s.cursors[m[1]] = rows
		return nil, 0, "DECLARE CURSOR", nil
	}
	if m := fetchRE.FindStringSubmatch(q); m != nil {
		left, ok := s.cursors[m[2]]
		if !ok {
			return nil, 0, "", &fakeErr{"34000", "cursor does not exist"}
		}
		want, _ := strconv.Atoi(m[1])
		n = min(want, left)
		s.cursors[m[2]] = left - n
		return []string{"v"}, n, "FETCH " + strconv.Itoa(n), nil
	}
	if rows, ok := f.size[strings.TrimRight(q, ";")]; ok {
		return []string{"v"}, rows, "SELECT " + strconv.Itoa(rows), nil
	}
	if strings.HasPrefix(q, "INSERT") {
		return nil, 0, "INSERT 0 1", nil
	}
	return nil, 0, "", &fakeErr{"42601", "syntax error at or near " + strconv.Quote(q)}
}

func rowDesc(cols []string) *pgproto3.RowDescription {
	rd := &pgproto3.RowDescription{}
	for _, c := range cols {
		rd.Fields = append(rd.Fields, pgproto3.FieldDescription{Name: []byte(c), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1})
	}
	return rd
}

func (f *fakePG) sendRows(b *pgproto3.Backend, n int) {
	for i := 0; i < n; i++ {
		b.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("row-" + strconv.Itoa(i))}})
		if i%4096 == 0 {
			_ = b.Flush()
		}
	}
	f.mu.Lock()
	f.produced += n
	f.mu.Unlock()
}

func errResp(err error) *pgproto3.ErrorResponse {
	e := err.(*fakeErr)
	return &pgproto3.ErrorResponse{Severity: "ERROR", Code: e.code, Message: e.msg}
}

func (f *fakePG) serve(c net.Conn) {
	defer c.Close()
	b := pgproto3.NewBackend(c, c)
	if _, err := b.ReceiveStartupMessage(); err != nil {
		return
	}
	b.Send(&pgproto3.AuthenticationOk{})
	b.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "18.0"})
	b.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	b.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	b.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	_ = b.Flush()

	s := &fakeSession{tx: 'I', cursors: map[string]int{}, stmts: map[string]string{}, portals: map[string]string{}}
	failed := false // extended protocol: skip to Sync after an error
	fail := func(err error) {
		b.Send(errResp(err))
		if s.tx == 'T' {
			s.tx = 'E'
		}
	}
	// What a Describe of a statement or portal says, without running it:
	// FETCH's columns come from the cursor, everything else from size.
	describe := func(sql string) []string {
		q := strings.TrimSpace(sql)
		if fetchRE.MatchString(q) {
			return []string{"v"}
		}
		if _, ok := f.size[strings.TrimRight(q, ";")]; ok {
			return []string{"v"}
		}
		return nil
	}
	for {
		msg, err := b.Receive()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.Terminate:
			return
		case *pgproto3.Query:
			q := strings.TrimSpace(m.String)
			if q == "" || strings.HasPrefix(q, "--") || q == ";" {
				b.Send(&pgproto3.EmptyQueryResponse{})
			} else {
				for _, part := range strings.Split(strings.TrimRight(q, ";"), ";") {
					cols, n, tag, err := f.run(s, part, false)
					if err != nil {
						fail(err)
						break
					}
					if cols != nil {
						b.Send(rowDesc(cols))
						f.sendRows(b, n)
					}
					b.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})
				}
			}
			b.Send(&pgproto3.ReadyForQuery{TxStatus: s.tx})
			_ = b.Flush()
		case *pgproto3.Parse:
			if failed {
				continue
			}
			q := strings.TrimSpace(m.Query)
			if strings.Contains(strings.TrimRight(q, "; \n"), ";") {
				f.note(q)
				fail(&fakeErr{"42601", "cannot insert multiple commands into a prepared statement"})
				failed = true
				continue
			}
			s.stmts[m.Name] = m.Query
			b.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Describe:
			if failed {
				continue
			}
			sql := s.stmts[m.Name]
			if m.ObjectType == 'P' {
				sql = s.portals[m.Name]
			} else {
				b.Send(&pgproto3.ParameterDescription{})
			}
			if cols := describe(sql); cols != nil {
				b.Send(rowDesc(cols))
			} else {
				b.Send(&pgproto3.NoData{})
			}
		case *pgproto3.Bind:
			if failed {
				continue
			}
			s.portals[m.DestinationPortal] = s.stmts[m.PreparedStatement]
			b.Send(&pgproto3.BindComplete{})
		case *pgproto3.Execute:
			if failed {
				continue
			}
			cols, n, tag, err := f.run(s, s.portals[m.Portal], true)
			if err != nil {
				fail(err)
				failed = true
				continue
			}
			if cols != nil {
				f.sendRows(b, n)
			}
			b.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})
		case *pgproto3.Close:
			if !failed {
				b.Send(&pgproto3.CloseComplete{})
			}
		case *pgproto3.Sync:
			failed = false
			b.Send(&pgproto3.ReadyForQuery{TxStatus: s.tx})
			_ = b.Flush()
		case *pgproto3.Flush:
			_ = b.Flush()
		}
	}
}

const bigQuery = "SELECT v FROM big"

func connectFake(t *testing.T, f *fakePG) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, f.cfg(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// The cap stops the query: Postgres is asked for one row past it, through a
// cursor that is then closed, instead of sending every row so the statement
// can finish.
func TestConsoleCapStopsTheQuery(t *testing.T) {
	f := newFakePG(t, map[string]int{bigQuery: 2_000_000})
	conn := connectFake(t, f)
	out := runOn(context.Background(), conn, bigQuery)
	if e, bad := out["error"]; bad {
		t.Fatalf("error: %v (statements %q)", e, f.statements())
	}
	if n := len(out["rows"].([][]any)); n != consoleRowCap {
		t.Errorf("rows = %d, want %d", n, consoleRowCap)
	}
	if out["truncated"] != true || out["note"] == nil {
		t.Errorf("a capped result must say it was cut short: %v %v", out["truncated"], out["note"])
	}
	if out["command"] != "SELECT 1000" {
		t.Errorf("command = %v", out["command"])
	}
	res := out["results"].([]map[string]any)
	if len(res) != 1 || res[0]["truncated"] != true {
		t.Errorf("results = %v", res)
	}
	f.mu.Lock()
	produced := f.produced
	f.mu.Unlock()
	if produced != consoleRowCap+1 {
		t.Errorf("the server produced %d rows; the cap should have stopped it at %d", produced, consoleRowCap+1)
	}
	want := []string{"BEGIN", "DECLARE " + capCursor + " NO SCROLL CURSOR FOR " + bigQuery,
		"FETCH FORWARD 1001 FROM " + capCursor, "CLOSE " + capCursor, "COMMIT"}
	if got := f.statements(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("statements:\n got %q\nwant %q", got, want)
	}
	if st := conn.PgConn().TxStatus(); st != 'I' {
		t.Errorf("the session was left in transaction state %c", st)
	}
}

// A small result is not marked, and reads exactly as it did.
func TestConsoleCapLeavesSmallResults(t *testing.T) {
	f := newFakePG(t, map[string]int{"SELECT v FROM small": 3})
	out := runOn(context.Background(), connectFake(t, f), "SELECT v FROM small")
	if _, cut := out["truncated"]; cut {
		t.Error("a 3-row result was marked truncated")
	}
	if out["command"] != "SELECT 3" || len(out["rows"].([][]any)) != 3 {
		t.Errorf("got %v %v", out["command"], out["rows"])
	}
}

// Through the pool: the session goes back idle, with no transaction and no
// cursor, DISCARD ALL resets it, and the next request gets that same
// connection.
func TestConsoleCapReturnsACleanConnection(t *testing.T) {
	resetPools(t)
	f := newFakePG(t, map[string]int{bigQuery: 50_000, "SELECT v FROM small": 2})
	pool, err := poolFor("dev", f.cfg(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, q := range []string{bigQuery, "SELECT v FROM small"} {
		pc, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if out := runOn(ctx, pc.Conn(), q); out["error"] != nil {
			t.Fatalf("%s: %v", q, out["error"])
		}
		pc.Release()
	}
	// AfterRelease runs as the connection goes back; give it a moment.
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.discards)
		f.mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conns != 1 {
		t.Errorf("%d connections were made; the clean one should have been reused", f.conns)
	}
	if strings.Join(f.discards, ",") != "I0,I0" {
		t.Errorf("each DISCARD ALL should find an idle session with no cursor open, got %q", f.discards)
	}
}

// Inside an act_for transaction the cursor lives in a savepoint, and the
// transaction is left open for its caller to commit.
func TestConsoleCapInsideATransaction(t *testing.T) {
	f := newFakePG(t, map[string]int{bigQuery: 5000})
	conn := connectFake(t, f)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	out := runOn(ctx, conn, bigQuery)
	if out["error"] != nil || out["truncated"] != true {
		t.Fatalf("got %v", out)
	}
	got := strings.Join(f.statements(), "|")
	if !strings.Contains(got, "SAVEPOINT "+capCursor) || !strings.Contains(got, "RELEASE SAVEPOINT "+capCursor) ||
		strings.Contains(got, "COMMIT") {
		t.Errorf("statements: %s", got)
	}
	if conn.PgConn().TxStatus() != 'T' {
		t.Error("the caller's transaction should still be open")
	}
}

// A script is untouched: DECLARE refuses it before anything runs, and it is
// run as a script, every row of every statement read as before.
func TestConsoleCapLeavesScriptsAlone(t *testing.T) {
	f := newFakePG(t, map[string]int{"SELECT v FROM a": 1500, "SELECT v FROM b": 2})
	conn := connectFake(t, f)
	out := runOn(context.Background(), conn, "SELECT v FROM a; SELECT v FROM b")
	if out["error"] != nil {
		t.Fatalf("error: %v", out["error"])
	}
	res := out["results"].([]map[string]any)
	if len(res) != 2 || res[0]["command"] != "SELECT 1500" || len(res[0]["rows"].([][]any)) != consoleRowCap ||
		res[1]["command"] != "SELECT 2" {
		t.Errorf("results = %v", res)
	}
	if _, cut := out["truncated"]; cut {
		t.Error("a script result changed shape")
	}
	f.mu.Lock()
	produced := f.produced
	f.mu.Unlock()
	if produced != 1502 {
		t.Errorf("a script's statements run to the end as before; produced %d", produced)
	}
	if conn.PgConn().TxStatus() != 'I' {
		t.Error("a refused DECLARE left a transaction open")
	}
}

// A statement that is not a query never sees a cursor.
func TestConsoleCapLeavesWritesAlone(t *testing.T) {
	f := newFakePG(t, nil)
	out := runOn(context.Background(), connectFake(t, f), "INSERT INTO t VALUES (1)")
	if out["error"] != nil || out["command"] != "INSERT 0 1" {
		t.Fatalf("got %v", out)
	}
	for _, s := range f.statements() {
		if strings.HasPrefix(s, "DECLARE") || s == "BEGIN" {
			t.Errorf("a write went through the cursor path: %q", f.statements())
		}
	}
}

// A query a cursor cannot hold (here, a data-modifying WITH) is refused at
// DECLARE and then run as it always was.
func TestConsoleCapFallsBackWhenRefused(t *testing.T) {
	q := "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"
	f := newFakePG(t, nil)
	conn := connectFake(t, f)
	out := runOn(context.Background(), conn, q)
	got := f.statements()
	if len(got) < 3 || got[0] != "BEGIN" || got[2] != "ROLLBACK" || got[len(got)-1] != q {
		t.Errorf("statements: %q", got)
	}
	if out["error"] == nil {
		t.Error("the fake has no such table, so the plain path should report its error")
	}
	if conn.PgConn().TxStatus() != 'I' {
		t.Error("left in a transaction")
	}
}

func TestReadsRows(t *testing.T) {
	for sql, want := range map[string]bool{
		"SELECT 1":                             true,
		"  select * from t":                    true,
		"(SELECT 1) UNION (SELECT 2)":          true,
		"-- note\nSELECT 1":                    true,
		"/* a /* nested */ b */ VALUES (1)":    true,
		"TABLE t":                              true,
		"WITH x AS (SELECT 1) SELECT * FROM x": true,
		"INSERT INTO t VALUES (1)":             false,
		"EXPLAIN SELECT 1":                     false,
		"selected":                             false,
		"-- only a comment":                    false,
		"/* unterminated":                      false,
		"":                                     false,
	} {
		if got := readsRows(sql); got != want {
			t.Errorf("readsRows(%q) = %v, want %v", sql, got, want)
		}
	}
}

// The measurement behind the change, on the fake: the same 2,000,000-row
// result read to its end the old way, and stopped at the cap. Logged, not
// asserted, beyond the capped run being the faster.
func TestConsoleCapTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	f := newFakePG(t, map[string]int{bigQuery: 2_000_000})
	conn := connectFake(t, f)
	ctx := context.Background()
	start := time.Now()
	if out := runStreamed(ctx, conn, bigQuery); out["error"] != nil {
		t.Fatal(out["error"])
	}
	drained := time.Since(start)
	start = time.Now()
	if out := runOn(ctx, conn, bigQuery); out["error"] != nil {
		t.Fatal(out["error"])
	}
	capped := time.Since(start)
	t.Logf("2,000,000 rows, 1,000 shown: drained %s, capped %s", drained, capped)
	if capped >= drained {
		t.Errorf("the capped run (%s) was not faster than draining (%s)", capped, drained)
	}
}
