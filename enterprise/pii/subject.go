//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pii

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Finding a data principal (finding PRIV-7): where one person's email, phone
// number, Aadhaar number and so on appear, across main and every branch, so
// an operator answering an access or erasure request knows which rows to look
// at. Read-only: it counts rows and changes nothing, and it never returns a
// row or a value, only where and how many.
//
// It looks only where a reviewer has confirmed personal data (point 4.6).
// Searching every column of every table for a value would be a scan of the
// whole install for one person, slow and, worse, a way to find anybody
// anywhere; the confirmed findings are the inventory the operator already
// stands behind. What that leaves out is said in the report's limits.

// SubjectSource is what a search reads. The real one is Postgres; tests use a
// fake.
type SubjectSource interface {
	// Branches are the branches to search, main first.
	Branches() ([]string, error)
	// Findings are a branch's personal-data findings, any state.
	Findings(name string) ([]branch.PIIFinding, error)
	// Count is how many rows of a finding's table hold m's value in the
	// finding's column (or JSON path).
	Count(name string, f branch.PIIFinding, m SubjectMatch) (int64, error)
}

// SubjectMatch is one way of reading the value: a category, and the value in
// the form the column is compared in.
type SubjectMatch struct {
	Category Category
	Value    string
}

// SubjectPlace is one column, on one branch, that holds the value.
type SubjectPlace struct {
	Branch   string `json:"branch"`
	Schema   string `json:"schema"`
	Table    string `json:"table"`
	Column   string `json:"column"`
	Path     string `json:"path,omitempty"`
	Category string `json:"category"`
	Rows     int64  `json:"rows"`
}

// SubjectReport is where the value was found, and what the search could not
// cover.
type SubjectReport struct {
	Categories []string       `json:"categories"`
	Branches   int            `json:"branches"`
	Columns    int            `json:"columns"` // confirmed columns searched
	Places     []SubjectPlace `json:"places"`
	Limits     []string       `json:"limits"`
}

// Summary is the report in a sentence, for the security log: counts, never
// the value or a place.
func (r SubjectReport) Summary() string {
	rows := int64(0)
	for _, p := range r.Places {
		rows += p.Rows
	}
	return fmt.Sprintf("as %s: %d columns searched on %d branches, found in %d, %d rows",
		strings.Join(r.Categories, "/"), r.Columns, r.Branches, len(r.Places), rows)
}

// subjectMatches reads a value as every category it could be. A value can be
// more than one (a UPI ID can look like an email to a person, a number can be
// a mobile and part of a card), and each is searched in its own columns.
func subjectMatches(value string, only Category) []SubjectMatch {
	value = strings.TrimSpace(value)
	var out []SubjectMatch
	for _, r := range recognisers {
		if only != "" && r.cat != only {
			continue
		}
		if only == "" && !r.value(value) {
			continue
		}
		out = append(out, SubjectMatch{Category: r.cat, Value: normaliseSubject(r.cat, value)})
	}
	return out
}

// normaliseSubject is a value in the form subjectSQL compares columns in, so
// "+91 98765 43210" finds 9876543210 and "Asha@Example.com" finds
// asha@example.com.
func normaliseSubject(c Category, v string) string {
	switch c {
	case Email, UPI:
		return strings.ToLower(strings.TrimSpace(v))
	case Aadhaar, Card:
		return onlyDigits(v)
	case Mobile:
		d := onlyDigits(v)
		if len(d) > 10 {
			d = d[len(d)-10:]
		}
		return d
	case PAN, GSTIN, IFSC, Passport, VoterID, Vehicle:
		return strings.ToUpper(strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				return r
			}
			return -1
		}, v))
	}
	return strings.TrimSpace(v)
}

func onlyDigits(v string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, v)
}

// subjectSQL is the expression a stored value x is compared in, the SQL twin
// of normaliseSubject.
func subjectSQL(c Category, x string) string {
	switch c {
	case Email, UPI:
		return "lower(btrim(" + x + "))"
	case Aadhaar, Card:
		return "regexp_replace(" + x + ", '[^0-9]', '', 'g')"
	case Mobile:
		return "right(regexp_replace(" + x + ", '[^0-9]', '', 'g'), 10)"
	case PAN, GSTIN, IFSC, Passport, VoterID, Vehicle:
		return "upper(regexp_replace(" + x + ", '[^A-Za-z0-9]', '', 'g'))"
	}
	return "btrim(" + x + ")"
}

// FindSubject searches for a value. only, when not empty, says which category
// it is rather than guessing from its shape.
func FindSubject(value string, only Category, src SubjectSource) (SubjectReport, error) {
	rep := SubjectReport{Categories: []string{}, Places: []SubjectPlace{}, Limits: []string{}}
	matches := subjectMatches(value, only)
	if len(matches) == 0 {
		return rep, fmt.Errorf("%w: the value does not look like any kind of personal data this recognises; say which with --category",
			branch.ErrInvalidRequest)
	}
	cats := map[Category]SubjectMatch{}
	for _, m := range matches {
		cats[m.Category] = m
		rep.Categories = append(rep.Categories, string(m.Category))
	}
	names, err := src.Branches()
	if err != nil {
		return rep, err
	}
	rep.Branches = len(names)
	for _, name := range names {
		fs, err := src.Findings(name)
		if err != nil {
			rep.Limits = append(rep.Limits, fmt.Sprintf("%s: its findings could not be read, so it was not searched", name))
			continue
		}
		confirmed, waiting := 0, 0
		seen := map[string]bool{}
		for _, f := range fs {
			m, ok := cats[Category(f.Category)]
			if !ok {
				continue
			}
			if f.State != branch.PIIConfirmed {
				waiting++
				continue
			}
			key := f.Schema + "\x00" + f.Table + "\x00" + f.Column + "\x00" + f.Path + "\x00" + f.Category
			if seen[key] {
				continue
			}
			seen[key] = true
			confirmed++
			n, err := src.Count(name, f, m)
			if err != nil {
				rep.Limits = append(rep.Limits, fmt.Sprintf("%s: %s could not be read (%v)", name, f.Where(), err))
				continue
			}
			if n > 0 {
				rep.Places = append(rep.Places, SubjectPlace{Branch: name, Schema: f.Schema, Table: f.Table,
					Column: f.Column, Path: f.Path, Category: f.Category, Rows: n})
			}
		}
		rep.Columns += confirmed
		if waiting > 0 {
			rep.Limits = append(rep.Limits, fmt.Sprintf("%s: %d findings of this kind are not confirmed yet and were not searched (fox pii --branch %s --state suggested)",
				name, waiting, name))
		}
		if confirmed == 0 && len(fs) == 0 {
			rep.Limits = append(rep.Limits, fmt.Sprintf("%s: never scanned for personal data, so not searched", name))
		}
	}
	sort.SliceStable(rep.Places, func(i, j int) bool {
		a, b := rep.Places[i], rep.Places[j]
		if a.Branch != b.Branch {
			return a.Branch < b.Branch
		}
		return a.Schema+"."+a.Table+"."+a.Column < b.Schema+"."+b.Table+"."+b.Column
	})
	rep.Limits = append(rep.Limits,
		"Only columns a reviewer confirmed were searched; a column no scan found, or free text that mentions the person, is not covered.",
		"Values are compared whole, after normalising case and separators; a value stored inside a longer string is not found.",
		"Stopped branches, the ledgers, the audit log and backups are not searched.")
	return rep, nil
}

// PostgresSubjects is the real source: running branches, their findings, and
// counts read in a read-only transaction.
type PostgresSubjects struct{}

// Branches are the running branches, main first.
func (PostgresSubjects) Branches() ([]string, error) { return branch.RunningBranches() }

// Findings are what scans found on a branch.
func (PostgresSubjects) Findings(name string) ([]branch.PIIFinding, error) {
	rep, err := branch.PersonalDataFindings(name)
	return rep.Findings, err
}

const subjectTimeout = 60 * time.Second

// Count counts the rows of a finding's table that hold the value.
func (PostgresSubjects) Count(name string, f branch.PIIFinding, m SubjectMatch) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), subjectTimeout)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return 0, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '50s'"); err != nil {
		return 0, err
	}
	rel := branch.QuoteIdent(f.Schema) + "." + branch.QuoteIdent(f.Table)
	col := branch.QuoteIdent(f.Column)
	var n int64
	if f.Path == "" {
		err = tx.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s WHERE %s = $1", rel, subjectSQL(m.Category, col+"::text")), m.Value).Scan(&n)
	} else {
		err = tx.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE EXISTS (
			SELECT 1 FROM jsonb_path_query(%s::jsonb, $2::jsonpath) AS v
			WHERE jsonb_typeof(v) IN ('string', 'number') AND %s = $1)`, rel, col, subjectSQL(m.Category, "(v #>> '{}')")),
			m.Value, f.Path).Scan(&n)
	}
	if err != nil {
		// Postgres's message can quote a value; say where instead.
		return 0, readError(err, f)
	}
	return n, nil
}
