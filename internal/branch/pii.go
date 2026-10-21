// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Personal-data discovery (point 4.1): where a branch holds personal data,
// found from column names and sampled values.
//
// Scanning is Enterprise; enterprise/pii supplies it. Reading what a scan
// found is free, by the rule in edition.go, so the report types and the read
// are here. Findings live in the branch (bb.pii_scans, bb.pii_findings), so a
// branch's findings travel with it when it is cloned. They never hold a value:
// only where, what, and how much of the sample matched.

// DefaultPIISample is how many rows of each table a scan reads when not told.
const (
	DefaultPIISample = 1000
	MaxPIISample     = 100000
)

// PIIScanOptions is what a scan is asked to do.
type PIIScanOptions struct {
	Sample int    // rows read per table; DefaultPIISample when 0
	Actor  string // who asked, kept with the scan
}

// PIIScan is one scan: when, by whom, and how much it covered.
type PIIScan struct {
	ID       int64     `json:"id"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Actor    string    `json:"actor"`
	Sample   int       `json:"sample"`
	Tables   int       `json:"tables"`
	Columns  int       `json:"columns"`
	Skipped  []PIISkip `json:"skipped"`
	// Limits are what the scan could not see or cannot claim, in sentences.
	// Every result carries them: a scan that found nothing has not shown a
	// branch holds nothing.
	Limits []string `json:"limits"`
}

// PIISkip is a table or column the scan did not read, and why.
type PIISkip struct {
	Object string `json:"object"`
	Reason string `json:"reason"`
}

// PIIFinding is one category of personal data in one place.
type PIIFinding struct {
	ID         int64     `json:"id"`
	Schema     string    `json:"schema"`
	Table      string    `json:"table"`
	Column     string    `json:"column"`
	Path       string    `json:"path"` // a JSON path inside the column; "" for the column itself
	Category   string    `json:"category"`
	Rule       string    `json:"rule"`       // name, value, or name+value
	Confidence string    `json:"confidence"` // high, medium, low
	Why        string    `json:"why"`
	Matched    int       `json:"matched"`
	Sampled    int       `json:"sampled"`
	State      string    `json:"state"` // suggested until a reviewer decides (step 4.6)
	FirstScan  int64     `json:"firstScan"`
	LastScan   int64     `json:"lastScan"`
	LastSeen   time.Time `json:"lastSeen"`
}

// PIIReport is what a branch's findings look like now: the latest scan, and
// every finding any scan has made.
type PIIReport struct {
	Branch   string       `json:"branch"`
	Scan     *PIIScan     `json:"scan"` // nil before the first scan
	Findings []PIIFinding `json:"findings"`
}

// scanPII is the scan, supplied by enterprise/pii in an Enterprise build and nil
// in a Standard one.
var scanPII func(name string, o PIIScanOptions) (PIIScan, error)

// SetPIIScanner installs the scan. Called from enterprise/pii's init, and from
// nowhere else.
func SetPIIScanner(fn func(name string, o PIIScanOptions) (PIIScan, error)) { scanPII = fn }

// CheckPIIScanOptions fills in the defaults and refuses what cannot be right.
func CheckPIIScanOptions(o PIIScanOptions) (PIIScanOptions, error) {
	if o.Sample == 0 {
		o.Sample = DefaultPIISample
	}
	if o.Sample < 1 || o.Sample > MaxPIISample {
		return o, fmt.Errorf("%w: the sample is 1 to %d rows per table, not %d", ErrInvalidRequest, MaxPIISample, o.Sample)
	}
	return o, nil
}

// ScanPersonalData scans a branch and returns its findings afterwards.
func ScanPersonalData(name string, o PIIScanOptions) (PIIReport, error) {
	if err := requireFeature(edition.PersonalData); err != nil {
		return PIIReport{}, err
	}
	if scanPII == nil {
		return PIIReport{}, ErrPersonalDataNotLicensed
	}
	o, err := CheckPIIScanOptions(o)
	if err != nil {
		return PIIReport{}, err
	}
	if _, err := scanPII(name, o); err != nil {
		return PIIReport{}, err
	}
	return PersonalDataFindings(name)
}

// PersonalDataFindings reads what scans have found on a branch. Free in every
// edition: a branch scanned before an install changed edition keeps its
// findings, and reading them is not the thing a licence switches off.
func PersonalDataFindings(name string) (PIIReport, error) {
	if name == "" {
		name = "main"
	}
	rep := PIIReport{Branch: name, Findings: []PIIFinding{}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := OpenSuper(ctx, name)
	if err != nil {
		return rep, err
	}
	defer conn.Close(context.Background())

	// A branch no scan has touched has no tables to read: that is "nothing
	// yet", not an error.
	var have bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('bb.pii_findings') IS NOT NULL AND to_regclass('bb.pii_scans') IS NOT NULL").Scan(&have); err != nil {
		return rep, err
	}
	if !have {
		return rep, nil
	}

	var s PIIScan
	var skipped, limits []byte
	err = conn.QueryRow(ctx, `SELECT id, started_at, finished_at, actor, sample_size, tables_scanned, columns_scanned, skipped, limits
		FROM bb.pii_scans ORDER BY id DESC LIMIT 1`).
		Scan(&s.ID, &s.Started, &s.Finished, &s.Actor, &s.Sample, &s.Tables, &s.Columns, &skipped, &limits)
	switch {
	case err == nil:
		if err := json.Unmarshal(skipped, &s.Skipped); err != nil {
			return rep, err
		}
		if err := json.Unmarshal(limits, &s.Limits); err != nil {
			return rep, err
		}
		rep.Scan = &s
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return rep, err
	}

	rows, err := conn.Query(ctx, `SELECT id, schema_name, table_name, column_name, json_path, category, rule, confidence, why,
			matched, sampled, state, first_scan, last_scan, last_seen
		FROM bb.pii_findings
		ORDER BY CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
			schema_name, table_name, column_name, json_path, category`)
	if err != nil {
		return rep, err
	}
	defer rows.Close()
	for rows.Next() {
		var f PIIFinding
		if err := rows.Scan(&f.ID, &f.Schema, &f.Table, &f.Column, &f.Path, &f.Category, &f.Rule, &f.Confidence, &f.Why,
			&f.Matched, &f.Sampled, &f.State, &f.FirstScan, &f.LastScan, &f.LastSeen); err != nil {
			return rep, err
		}
		rep.Findings = append(rep.Findings, f)
	}
	return rep, rows.Err()
}

// Summary is what the security log keeps of a scan: its coverage and how much
// it found, never a value or a column.
func (r PIIReport) Summary() string {
	if r.Scan == nil {
		return "scanned"
	}
	s := r.Scan
	return fmt.Sprintf("scan %d: %d table(s), %d column(s), %d skipped, sample %d; %d finding(s) in all",
		s.ID, s.Tables, s.Columns, len(s.Skipped), s.Sample, len(r.Findings))
}
