//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thefoxbyte/foxbyte/enterprise/schema"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Review (point 4.6): a finding starts suggested, and a person decides what it
// is, from masked samples, with every decision kept.

func init() { branch.SetPIIReviewer(mark, samples) }

const (
	reviewTimeout = 30 * time.Second
	// sampleRead is how many values are read to choose the shown ones from:
	// enough that the ones that look like the category can be put first.
	sampleRead  = 200
	sampleLimit = "10s"
)

// mark records a decision: the finding carries the latest, and
// bb.pii_decisions keeps every one.
func mark(name string, id int64, state, note, actor string) error {
	ctx, cancel := context.WithTimeout(context.Background(), reviewTimeout)
	defer cancel()
	// A branch scanned before review existed gains its columns here, not only
	// at the next start.
	if err := schema.EnsurePII(name); err != nil {
		return err
	}
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	tag, err := tx.Exec(ctx, `UPDATE bb.pii_findings
		SET state = $1, decided_by = $2, decided_at = now(), note = $3 WHERE id = $4`, state, actor, note, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return branch.ErrNoFinding
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bb.pii_decisions (finding_id, state, actor, note) VALUES ($1, $2, $3, $4)`,
		id, state, actor, note); err != nil {
		return err
	}
	if err := followInventory(ctx, tx, id, state, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// followInventory keeps a new place's status in step with its findings (4.7).
// Deciding the last undecided finding at a place that appeared after the
// baseline reviews the place; reopening one puts it back to unclassified. A
// place from the baseline is reviewed as its findings, and stays known.
func followInventory(ctx context.Context, tx pgx.Tx, finding int64, state, actor string) error {
	var have bool
	if err := tx.QueryRow(ctx, "SELECT to_regclass('bb.pii_columns') IS NOT NULL").Scan(&have); err != nil || !have {
		return err
	}
	var col int64
	var err error
	if state == branch.PIISuggested {
		err = tx.QueryRow(ctx, `UPDATE bb.pii_columns c SET status = 'unclassified', reviewed_by = '', reviewed_at = NULL, note = ''
			FROM bb.pii_findings f
			WHERE f.id = $1 AND (c.schema_name, c.table_name, c.column_name, c.json_path) = (f.schema_name, f.table_name, f.column_name, f.json_path)
			  AND c.status = 'reviewed'
			RETURNING c.id`, finding).Scan(&col)
	} else {
		err = tx.QueryRow(ctx, `UPDATE bb.pii_columns c SET status = 'reviewed', reviewed_by = $2, reviewed_at = now(), note = 'every finding here decided'
			FROM bb.pii_findings f
			WHERE f.id = $1 AND (c.schema_name, c.table_name, c.column_name, c.json_path) = (f.schema_name, f.table_name, f.column_name, f.json_path)
			  AND c.status = 'unclassified'
			  AND NOT EXISTS (SELECT 1 FROM bb.pii_findings o
			                  WHERE (o.schema_name, o.table_name, o.column_name, o.json_path) = (c.schema_name, c.table_name, c.column_name, c.json_path)
			                    AND o.state = 'suggested')
			RETURNING c.id`, finding, actor).Scan(&col)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // nothing to follow: a baseline place, or findings still undecided
	}
	if err != nil {
		return err
	}
	status, note := branch.PIIReviewed, "every finding here decided"
	if state == branch.PIISuggested {
		status, note = branch.PIIUnclassified, "a finding here was reopened"
	}
	_, err = tx.Exec(ctx, `INSERT INTO bb.pii_column_reviews (column_id, status, actor, note) VALUES ($1, $2, $3, $4)`, col, status, actor, note)
	return err
}

// samples reads values from a finding's location as the reviewer's own role,
// and masks them before they leave this process.
//
// The location is looked up as the superuser (bb.pii_findings is not
// granted to anyone else); the values are read as the reviewer, so a person
// shown samples is never shown more than they could select themselves.
func samples(name string, id int64, n int, account string) (branch.PIISamples, error) {
	d, err := branch.PersonalDataFinding(name, id)
	if err != nil {
		return branch.PIISamples{}, err
	}
	f := d.Finding
	out := branch.PIISamples{Finding: f, Samples: []branch.PIISample{}, As: account}
	if out.As == "" {
		out.As = "the operator (superuser)"
	}

	ctx, cancel := context.WithTimeout(context.Background(), reviewTimeout)
	defer cancel()
	conn, err := branch.OpenAs(ctx, name, account)
	if err != nil {
		return out, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '"+sampleLimit+"'"); err != nil {
		return out, err
	}

	rel := branch.QuoteIdent(f.Schema) + "." + branch.QuoteIdent(f.Table)
	col := branch.QuoteIdent(f.Column)
	var rows pgx.Rows
	if f.Path == "" {
		rows, err = tx.Query(ctx, fmt.Sprintf("SELECT %s::text FROM %s WHERE %s IS NOT NULL LIMIT %d", col, rel, col, sampleRead))
	} else {
		// The scan writes paths in SQL/JSON path syntax, so Postgres can
		// follow one itself: $.orders[*].email, $."odd key".
		rows, err = tx.Query(ctx, fmt.Sprintf(`SELECT v #>> '{}' FROM %s, jsonb_path_query(%s::jsonb, $1::jsonpath) AS v
			WHERE jsonb_typeof(v) IN ('string', 'number') LIMIT %d`, rel, col, sampleRead), f.Path)
	}
	if err != nil {
		return out, readError(err, f)
	}
	var vals []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return out, err
		}
		vals = append(vals, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, readError(err, f)
	}
	out.Read = len(vals)

	// The ones that look like the category first: a reviewer deciding
	// whether a column holds Aadhaar should see the values that made the
	// scan say so, and then whether the rest are like them.
	is := recogniserFor(Category(f.Category))
	var yes, no []branch.PIISample
	for _, v := range vals {
		s := branch.PIISample{Masked: Mask(Category(f.Category), v), Matches: is(v)}
		if s.Matches {
			yes = append(yes, s)
		} else {
			no = append(no, s)
		}
	}
	for i := range vals {
		vals[i] = ""
	}
	for _, s := range append(yes, no...) {
		if len(out.Samples) == n {
			break
		}
		out.Samples = append(out.Samples, s)
	}
	return out, nil
}

// readError turns a failed read into what a reviewer can act on, without
// repeating Postgres's message, which can quote a value.
func readError(err error, f branch.PIIFinding) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "42501": // insufficient_privilege, from a grant or a policy
			return fmt.Errorf("%w: %s (permission denied)", branch.ErrCannotReadLocation, f.Where())
		case "42P01", "42703": // the table or the column has gone since the scan
			return fmt.Errorf("%w: %s is no longer there; scan again", branch.ErrNoFinding, f.Where())
		}
		return fmt.Errorf("reading %s failed (SQLSTATE %s)", f.Where(), pe.Code)
	}
	return fmt.Errorf("reading %s failed", f.Where())
}

// recogniserFor is the test a category's values are judged by.
func recogniserFor(c Category) func(string) bool {
	if c == Child {
		return minor
	}
	for _, r := range recognisers {
		if r.cat == c {
			return func(v string) bool { return len(v) <= longest && r.value(v) }
		}
	}
	return func(string) bool { return false }
}

// Mask hides a value so a reviewer can tell what kind of thing it is without
// learning it: the last four letters and digits stay, the rest become X, and
// the separators stay where they were (XXXX XXXX 0124). An email keeps its
// first letter and its domain, a date of birth its year, an IP address its
// network. A value with four letters and digits or fewer is masked whole.
func Mask(c Category, v string) string {
	if len([]rune(v)) > longest {
		v = string([]rune(v)[:longest]) + "…"
	}
	switch c {
	case Email, UPI:
		if at := strings.LastIndexByte(v, '@'); at > 0 {
			first := []rune(v[:at])[0]
			return string(first) + "***" + v[at:]
		}
	case Birth, Child:
		if d, ok := birthDate(v); ok {
			return d.Format("2006") + "-XX-XX"
		}
	case IP:
		t := v
		if i := strings.IndexByte(t, '/'); i > 0 {
			t = t[:i]
		}
		if ip := net.ParseIP(t); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return fmt.Sprintf("%d.%d.X.X", v4[0], v4[1])
			}
			if i := strings.IndexByte(t, ':'); i > 0 {
				return t[:i] + ":X:X:X"
			}
		}
	}
	return keepLast(v, 4)
}

// keepLast masks every letter and digit but the last n, keeping the rest of
// the characters (spaces, hyphens, +) as they were.
func keepLast(v string, n int) string {
	rs := []rune(v)
	alnum := 0
	for _, r := range rs {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			alnum++
		}
	}
	if alnum <= n {
		n = 0 // too short to show any of it
	}
	seen := 0
	for i, r := range rs {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			seen++
			if seen <= alnum-n {
				rs[i] = 'X'
			}
		}
	}
	return string(rs)
}
