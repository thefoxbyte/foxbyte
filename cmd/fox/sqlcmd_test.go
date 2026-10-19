// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/controlplane"
	"github.com/thefoxbyte/foxbyte/internal/resultfmt"
)

func run(out controlplane.SQLOutput, format string, o resultfmt.Options) (string, string, int) {
	var w, ew bytes.Buffer
	code := printSQL(&w, &ew, out, format, o)
	return w.String(), ew.String(), code
}

func TestPrintSQLTable(t *testing.T) {
	out := controlplane.SQLOutput{Results: []controlplane.SQLResult{
		{Columns: []string{"id", "name"}, Rows: [][]any{{int64(1), "Ada"}, {int64(2), nil}}, Command: "SELECT 2"},
	}}
	got, _, code := run(out, "table", resultfmt.Options{})
	if code != 0 || !strings.Contains(got, "id  name") || !strings.Contains(got, "2   NULL") || !strings.Contains(got, "(2 rows)") {
		t.Errorf("code %d:\n%s", code, got)
	}
}

func TestPrintSQLFormats(t *testing.T) {
	out := controlplane.SQLOutput{Results: []controlplane.SQLResult{
		{Command: "CREATE TABLE"},
		{Columns: []string{"f"}, Rows: [][]any{{"=1+1"}}, Command: "SELECT 1"},
	}}
	got, _, code := run(out, "csv", resultfmt.Options{Header: true, Safe: true})
	if code != 0 || got != "f\n'=1+1\n" {
		t.Errorf("the last result with rows, safe: %q (%d)", got, code)
	}
	got, _, _ = run(out, "csv", resultfmt.Options{Header: false, Safe: false})
	if got != "=1+1\n" {
		t.Errorf("--no-header --raw: %q", got)
	}
	if _, ew, code := run(out, "insert", resultfmt.Options{}); code != 2 || !strings.Contains(ew, "table name") {
		t.Errorf("insert without --table: %q (%d)", ew, code)
	}
	if _, ew, code := run(out, "xml", resultfmt.Options{}); code != 2 || !strings.Contains(ew, "unknown format") {
		t.Errorf("unknown format: %q (%d)", ew, code)
	}
}

func TestPrintSQLFailures(t *testing.T) {
	out := controlplane.SQLOutput{Error: "syntax error at or near \"FORM\"", Hint: "a hint"}
	_, ew, code := run(out, "table", resultfmt.Options{})
	if code != 1 || !strings.Contains(ew, "ERROR: syntax error") || !strings.Contains(ew, "HINT: a hint") {
		t.Errorf("%q (%d)", ew, code)
	}
	script := controlplane.SQLOutput{
		Results: []controlplane.SQLResult{{Command: "INSERT 0 1"}},
		Error:   "relation \"nope\" does not exist",
		Note:    "nothing was applied",
	}
	_, ew, code = run(script, "csv", resultfmt.Options{})
	if code != 1 || !strings.Contains(ew, "nothing was applied") {
		t.Errorf("a failed script: %q (%d)", ew, code)
	}
}

func TestPositionals(t *testing.T) {
	got := positionals([]string{"--branch", "qa", "SELECT", "1", "--raw", "--format", "csv", "-"}, "--branch", "--format", "--table")
	if strings.Join(got, " ") != "SELECT 1 -" {
		t.Errorf("%v", got)
	}
}

// An Excel workbook is written as bytes: a zip whose sheet holds the result.
func TestPrintSQLXLSX(t *testing.T) {
	out := controlplane.SQLOutput{Results: []controlplane.SQLResult{
		{Columns: []string{"id"}, Rows: [][]any{{int64(7)}}, Command: "SELECT 1"},
	}}
	got, _, code := run(out, "xlsx", resultfmt.Options{})
	if code != 0 || !strings.HasPrefix(got, "PK\x03\x04") {
		t.Fatalf("code %d, starts %q", code, got[:min(4, len(got))])
	}
	z, err := zip.NewReader(strings.NewReader(got), int64(len(got)))
	if err != nil || len(z.File) != 5 {
		t.Fatalf("not a workbook: %v", err)
	}
}

// Point 9.2: fox sql says what was probably meant, once, under the error.
func TestPrintSQLSuggestion(t *testing.T) {
	sg := &controlplane.Suggestion{Kind: "table", Wrong: "custmers", Right: "Customers", Insert: `"Customers"`}
	var w, ew bytes.Buffer
	out := controlplane.SQLOutput{Error: "x", Suggestion: sg, Results: []controlplane.SQLResult{{Error: "x", Suggestion: sg}}}
	if code := printSQL(&w, &ew, out, "table", sqlOpts(nil)); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if n := strings.Count(ew.String(), `Did you mean "Customers"?`); n != 1 {
		t.Fatalf("printed %d times:\n%s", n, ew.String())
	}
}
