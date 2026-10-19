// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/resultfmt"
)

// Exporting a whole result (point 1.3): every row the query returns, not the
// 1,000 the console holds, written as it arrives so memory stays the same
// whatever the size. POST /api/branches/{name}/export and `fox export` share
// this.
//
//   - As the person asking: their own role, as a console query is, so row-level
//     security, grants and (later) masking decide what leaves.
//   - Read only: the statement runs in a READ ONLY transaction, so an export
//     can never change anything, even an UPDATE … RETURNING.
//   - One statement: COPY-like, it is one result.
//   - The same text as copying: the rows go through internal/resultfmt, so the
//     first rows of an export are exactly a copy of them.
//   - Recorded: every export, finished or not, is in the security log
//     (data.export): who, which branch, the format, how many rows, and a
//     fingerprint of the query rather than its text, which can hold personal
//     data.

// ExportOptions say how to write an export.
type ExportOptions struct {
	Format string // csv, tsv, json or xlsx
	Header bool
	Safe   bool // spreadsheet-safe text in CSV and TSV
}

// ErrMultipleStatements refuses a script: an export is one result.
var ErrMultipleStatements = errors.New("an export runs one statement: send the SELECT on its own")

// QueryFingerprint names a query in the security log without its text.
func QueryFingerprint(sql string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(sql)))
	return hex.EncodeToString(h[:6])
}

// oneStatement trims what follows the statement, and refuses a second one.
// Only a trailing semicolon is removed here: Postgres itself refuses more than
// one command in the protocol this speaks, which is the check that counts.
func oneStatement(sql string) string {
	return strings.TrimRight(strings.TrimSpace(sql), "; \t\r\n")
}

// exportRows runs sql on conn in a read-only transaction and writes every row
// through the writer begin returns. begin is called once the columns are
// known, before any byte is written, so a query that fails to start can still
// be answered as an error. It returns how many rows were written.
func exportRows(ctx context.Context, conn *pgx.Conn, sql string, o ExportOptions, begin func(cols []string) (io.Writer, error)) (int64, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) // read only: there is nothing to keep
	rows, err := tx.Query(ctx, oneStatement(sql))
	if err != nil {
		return 0, startErr(err)
	}
	defer rows.Close()
	// Ask for the first row before anything else: an error Postgres raises
	// while running the statement (a write refused in a read-only
	// transaction, say) arrives here, can still be an error answer, and must
	// not be mistaken for a statement with no columns, which is all pgx can
	// say of one that failed.
	more := rows.Next()
	if !more {
		if err := rows.Err(); err != nil {
			return 0, startErr(err)
		}
	}
	fds := rows.FieldDescriptions()
	if len(fds) == 0 {
		return 0, errors.New("the statement returns no rows to export")
	}
	cols := make([]string, len(fds))
	for i, f := range fds {
		cols[i] = f.Name
	}
	w, err := begin(cols)
	if err != nil {
		return 0, err
	}
	out, err := resultfmt.NewWriter(w, cols, resultfmt.Options{Format: o.Format, Header: o.Header, Safe: o.Safe})
	if err != nil {
		return 0, err
	}
	var n int64
	m := conn.TypeMap()
	for ; more; more = rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			_ = out.Close()
			return n, err
		}
		row := make([]any, len(vals))
		for i, v := range vals {
			row[i] = cell(v, fds[i].DataTypeOID, m)
		}
		if err := out.Row(row); err != nil {
			_ = out.Close()
			return n, err // ErrExcelFull: the workbook is closed with what fits
		}
		n++
	}
	if err := rows.Err(); err != nil {
		_ = out.Close()
		return n, err
	}
	return n, out.Close()
}

// startErr names a script as what it is: Postgres's own refusal of a second
// command is the check, and its words are about prepared statements.
func startErr(err error) error {
	if strings.Contains(err.Error(), "cannot insert multiple commands") {
		return ErrMultipleStatements
	}
	return err
}

// ExportDetail is the security log's line for an export, from the console or
// `fox export`. Why one stopped is its SQLSTATE, not Postgres's message, which
// can quote values from the query the fingerprint keeps out.
func ExportDetail(branchName, sql, format string, rows int64, err error) string {
	d := fmt.Sprintf("branch %s, %s, %d row(s), query %s", branchName, format, rows, QueryFingerprint(sql))
	if err != nil {
		d += "; stopped: " + stopReason(err)
	}
	return d
}

func stopReason(err error) string {
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &pe):
		return "SQLSTATE " + pe.Code
	case errors.Is(err, resultfmt.ErrExcelFull):
		return "Excel's row limit"
	case errors.Is(err, ErrMultipleStatements):
		return "more than one statement"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	return err.Error()
}

// ExportSQL is `fox export`: the whole result of sql on a branch, written to
// w, as the shared client role labelled for the Blackbox (as `fox sql` runs).
// The caller records it in the security log.
func ExportSQL(ctx context.Context, w io.Writer, branchName, sql, label string, o ExportOptions) (int64, error) {
	addr, err := branch.EnsureRunning(branchName)
	if err != nil {
		return 0, err
	}
	conn, err := openSession(ctx, addr, queryAs{Branch: branchName, Label: label, App: "fox export"})
	if err != nil {
		return 0, err
	}
	defer conn.Close(context.Background())
	return exportRows(ctx, conn, sql, o, func([]string) (io.Writer, error) { return w, nil })
}

// exportMIME is each format's media type and file extension.
var exportMIME = map[string][2]string{
	"csv":  {"text/csv; charset=utf-8", "csv"},
	"tsv":  {"text/tab-separated-values; charset=utf-8", "tsv"},
	"json": {"application/json", "json"},
	"xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"},
}

// handleExport is POST /api/branches/{name}/export: {"sql", "format", "header",
// "safe"}. The answer is the file, streamed; before it starts, a failure is an
// ordinary JSON error. A failure part way through cuts the connection, so the
// download is seen to have failed rather than saved short.
func handleExport(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	body := struct {
		SQL    string `json:"sql"`
		Format string `json:"format"`
		Header *bool  `json:"header"`
		Safe   *bool  `json:"safe"`
	}{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, fmt.Errorf("the body must be JSON: {\"sql\": …, \"format\": csv|tsv|json|xlsx}"))
		return
	}
	if strings.TrimSpace(body.SQL) == "" {
		writeErr(w, 400, fmt.Errorf("sql is required"))
		return
	}
	if body.Format == "" {
		body.Format = "csv"
	}
	mime, ok := exportMIME[body.Format]
	if !ok {
		writeErr(w, 400, fmt.Errorf("format must be csv, tsv, json or xlsx, not %q", body.Format))
		return
	}
	o := ExportOptions{Format: body.Format, Header: body.Header == nil || *body.Header, Safe: body.Safe == nil || *body.Safe}
	addr, err := branch.EnsureRunning(name)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	conn, err := openSession(r.Context(), addr, queryAs{Branch: name, Actor: u.Email})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	defer conn.Close(context.Background())

	started := false
	start := time.Now()
	n, err := exportRows(r.Context(), conn, body.SQL, o, func(cols []string) (io.Writer, error) {
		w.Header().Set("Content-Type", mime[0])
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-export.%s"`, name, mime[1]))
		w.Header().Set("X-Fox-Export-Columns", fmt.Sprint(len(cols)))
		w.WriteHeader(200)
		started = true
		return w, nil
	})
	if secLog != nil {
		secLog.Audit(auth.EvDataExport, u.Email, name, remoteIP(r), ExportDetail(name, body.SQL, o.Format, n, err))
	}
	h := auth.HistoryEntry{Actor: u.Email, Branch: name, Source: auth.RequestSource(r), Kind: "export", SQL: body.SQL,
		At: start.UnixMilli(), DurationMS: time.Since(start).Milliseconds(), Rows: n,
		OK: err == nil || errors.Is(err, resultfmt.ErrExcelFull)}
	if !h.OK {
		h.Error = err.Error()
	}
	recordQuery(h)
	if err == nil || errors.Is(err, resultfmt.ErrExcelFull) {
		if err != nil {
			log.Printf("export on %s for %s: %v", name, u.Email, err)
		}
		return
	}
	if !started {
		out := queryErr(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	// Part way through: the status is already sent, so the only honest signal
	// left is to end the connection without finishing the file.
	log.Printf("export on %s for %s stopped after %d rows: %v", name, u.Email, n, err)
	panic(http.ErrAbortHandler)
}
