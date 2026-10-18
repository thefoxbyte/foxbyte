// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thefoxbyte/foxbyte/internal/resultfmt"
)

// A request that cannot be an export is refused before anything is started:
// no branch is woken and no session opened.
func TestHandleExportRefusesBadRequests(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"not json", `sql=SELECT 1`, "must be JSON"},
		{"no sql", `{"format":"csv"}`, "sql is required"},
		{"blank sql", `{"sql":"   "}`, "sql is required"},
		{"unknown format", `{"sql":"SELECT 1","format":"pdf"}`, `not "pdf"`},
		{"table is not a file format", `{"sql":"SELECT 1","format":"table"}`, `not "table"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/branches/main/export", strings.NewReader(c.body))
			r.SetPathValue("name", "main")
			w := httptest.NewRecorder()
			handleExport(w, r)
			if w.Code != 400 {
				t.Fatalf("status %d, want 400", w.Code)
			}
			var out struct{ Error string }
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatalf("the answer is not JSON: %q", w.Body.String())
			}
			if !strings.Contains(out.Error, c.want) {
				t.Fatalf("error %q, want it to say %q", out.Error, c.want)
			}
			if cd := w.Header().Get("Content-Disposition"); cd != "" {
				t.Fatalf("a refused export still named a file: %q", cd)
			}
		})
	}
}

func TestExportMIMECoversEveryStreamFormat(t *testing.T) {
	for _, f := range []string{"csv", "tsv", "json", "xlsx"} {
		m, ok := exportMIME[f]
		if !ok || m[0] == "" || m[1] != f {
			t.Errorf("%s: %v", f, m)
		}
	}
}

// The security log names a query without holding its text, which can carry
// personal data; the same query, however it is spaced at the ends, is the
// same fingerprint.
func TestExportDetailHoldsAFingerprintNotTheQuery(t *testing.T) {
	sql := "SELECT email FROM users WHERE email = 'ada@example.com'"
	fp := QueryFingerprint(sql)
	if len(fp) != 12 || strings.Trim(fp, "0123456789abcdef") != "" {
		t.Fatalf("fingerprint %q is not 12 hex digits", fp)
	}
	if QueryFingerprint("  "+sql+"\n") != fp {
		t.Fatal("surrounding space changed the fingerprint")
	}
	if QueryFingerprint(sql+" LIMIT 1") == fp {
		t.Fatal("two queries share a fingerprint")
	}
	d := ExportDetail("main", sql, "csv", 42, nil)
	if want := "branch main, csv, 42 row(s), query " + fp; d != want {
		t.Fatalf("detail %q, want %q", d, want)
	}
	if strings.Contains(d, "ada@") || strings.Contains(d, "SELECT") {
		t.Fatalf("the detail holds the query text: %q", d)
	}
	d = ExportDetail("b1", sql, "xlsx", 7, errors.New("conn reset"))
	if !strings.HasSuffix(d, "; stopped: conn reset") {
		t.Fatalf("an unfinished export does not say so: %q", d)
	}
	// Postgres's message can quote the query's values; only its code is kept.
	pe := &pgconn.PgError{Code: "22P02", Message: `invalid input syntax for type integer: "ada@example.com"`}
	if d := ExportDetail("main", sql, "csv", 0, fmt.Errorf("query: %w", pe)); !strings.HasSuffix(d, "; stopped: SQLSTATE 22P02") || strings.Contains(d, "ada@") {
		t.Fatalf("%q", d)
	}
	for err, want := range map[error]string{
		resultfmt.ErrExcelFull: "Excel's row limit",
		ErrMultipleStatements:  "more than one statement",
		context.Canceled:       "cancelled",
	} {
		if d := ExportDetail("main", sql, "csv", 1, err); !strings.HasSuffix(d, "; stopped: "+want) {
			t.Errorf("%v: %q", err, d)
		}
	}
}

func TestOneStatementTrimsOnlyTheEnd(t *testing.T) {
	for in, want := range map[string]string{
		"SELECT 1;":           "SELECT 1",
		"  SELECT 1 ;\n\t":    "SELECT 1",
		"SELECT ';'":          "SELECT ';'",
		"SELECT 1; SELECT 2;": "SELECT 1; SELECT 2", // Postgres refuses the second
		"SELECT 1":            "SELECT 1",
	} {
		if got := oneStatement(in); got != want {
			t.Errorf("oneStatement(%q) = %q, want %q", in, got, want)
		}
	}
}
