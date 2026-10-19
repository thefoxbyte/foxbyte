// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/thefoxbyte/foxbyte/internal/auth"
)

// fox history prints a statement on one line, newest first, and says when
// there is none.
func TestPrintHistory(t *testing.T) {
	var b bytes.Buffer
	printHistory(&b, nil, "cli:ada")
	if !strings.Contains(b.String(), "No query history for cli:ada") {
		t.Fatalf("%q", b.String())
	}
	b.Reset()
	at := time.Date(2026, 10, 19, 9, 30, 0, 0, time.Local).UnixMilli()
	printHistory(&b, []auth.HistoryEntry{
		{ID: 2, Branch: "dev", Source: "console", Kind: "export", SQL: "SELECT *\n  FROM orders", At: at, DurationMS: 12, Rows: 2500, OK: true},
		{ID: 1, Branch: "main", Source: "cli", Kind: "query", SQL: "SELECT nope", At: at, Rows: 0, Error: "no such column"},
	}, "cli:ada")
	out := b.String()
	for _, want := range []string{"ID", "SQL", "2026-10-19 09:30:00", "console export", "2500", "SELECT * FROM orders", "error"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Index(out, "dev") > strings.Index(out, "main") {
		t.Error("not newest first")
	}
	if got := oneLine(strings.Repeat("x", 100), 10); len([]rune(got)) != 10 || !strings.HasSuffix(got, "…") {
		t.Errorf("%q", got)
	}
}
