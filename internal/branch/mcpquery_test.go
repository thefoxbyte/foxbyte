// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// A result past the row cap shows the first rows and says, in so many words,
// that the rest were left out and how many there were.
func TestMCPResultTruncatedAtTheRowCap(t *testing.T) {
	c := newTextCollector(MCPRowCap, MCPByteCap)
	c.begin([]string{"id"})
	for i := range 5000 {
		c.row([][]byte{[]byte(fmt.Sprint(i))})
	}
	c.end("SELECT 5000", nil)
	out := c.String()
	if n := strings.Count(out, "\n"); n > MCPRowCap+5 {
		t.Fatalf("%d lines returned, want at most the cap and a few more", n)
	}
	if !strings.Contains(out, "5000 rows; truncated") || !strings.Contains(out, "first 1000") {
		t.Fatalf("the answer must say it was truncated, got the tail:\n%s", out[len(out)-200:])
	}
	if strings.Contains(out, " 1000\n") {
		t.Fatal("row 1000 (the 1001st) should not be shown")
	}
}

// Wide rows hit the byte cap first: the answer stays within it and says so.
func TestMCPResultTruncatedAtTheByteCap(t *testing.T) {
	c := newTextCollector(MCPRowCap, 4<<10)
	c.begin([]string{"doc"})
	wide := []byte(strings.Repeat("x", 1000))
	for range 100 {
		c.row([][]byte{wide})
	}
	c.end("SELECT 100", nil)
	out := c.String()
	if len(out) > 6<<10 {
		t.Fatalf("answer is %d bytes, want about the 4 KiB cap", len(out))
	}
	if !strings.Contains(out, "100 rows; truncated") {
		t.Fatalf("the answer must say it was truncated:\n%s", out)
	}
}

// One value larger than the whole cap is cut, not returned whole.
func TestMCPResultHugeValueCut(t *testing.T) {
	c := newTextCollector(MCPRowCap, 1<<10)
	c.begin([]string{"blob"})
	c.row([][]byte{[]byte(strings.Repeat("é", 10_000))})
	c.end("SELECT 1", nil)
	out := c.String()
	if len(out) > 2<<10 || !strings.Contains(out, "truncated: values were cut") {
		t.Fatalf("got %d bytes:\n%.300s", len(out), out)
	}
}

// Within the caps it reads like psql: a table, a row count, a command tag for
// a statement without rows, the notices, and an error with its detail.
func TestMCPResultLooksLikePsql(t *testing.T) {
	c := newTextCollector(MCPRowCap, MCPByteCap)
	c.notice(&pgconn.Notice{Severity: "NOTICE", Message: "relation already exists, skipping"})
	c.begin(nil)
	c.end("CREATE TABLE", nil)
	c.begin([]string{"id", "name"})
	c.row([][]byte{[]byte("1"), []byte("ann")})
	c.row([][]byte{[]byte("2"), nil})
	c.row([][]byte{[]byte("3"), []byte("two\nlines")})
	c.end("SELECT 3", nil)
	c.begin(nil)
	c.end("", &pgconn.PgError{Severity: "ERROR", Message: "destructive change blocked", Hint: "ask an admin"})
	c.fail(&pgconn.PgError{Severity: "ERROR", Message: "destructive change blocked", Hint: "ask an admin"})
	out := c.String()
	for _, want := range []string{
		"NOTICE:  relation already exists, skipping",
		"CREATE TABLE",
		" id |    name\n",
		"----+------------\n",
		" 1  | ann\n",
		" 2  |\n",
		` 3  | two\nlines`,
		"(3 rows)",
		"ERROR:  destructive change blocked\nHINT:  ask an admin",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "ERROR:") != 1 {
		t.Errorf("the error should be said once:\n%s", out)
	}
	if strings.Contains(out, "truncated") {
		t.Errorf("nothing was truncated:\n%s", out)
	}
}

func TestMCPStatementTimeoutSetting(t *testing.T) {
	t.Setenv("FOX_MCP_STATEMENT_TIMEOUT", "")
	if MCPStatementTimeout() != DefaultMCPStatementTimeout {
		t.Fatal("default")
	}
	t.Setenv("FOX_MCP_STATEMENT_TIMEOUT", "45s")
	if MCPStatementTimeout().Seconds() != 45 {
		t.Fatal("45s")
	}
}
