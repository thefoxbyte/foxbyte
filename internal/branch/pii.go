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
	// NewOnly reads only the tables with a column no scan has seen, and every
	// JSON column (its new paths can only be found by reading it). Point 4.7:
	// a quick look for what has changed, not a re-check of what was there.
	NewOnly bool
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
	NewOnly  bool      `json:"newOnly"`
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
	// The latest decision, if any: who, when, and what they wrote.
	DecidedBy string     `json:"decidedBy"`
	DecidedAt *time.Time `json:"decidedAt"`
	Note      string     `json:"note"`
}

// PIIReport is what a branch's findings look like now: the latest scan, and
// every finding any scan has made.
type PIIReport struct {
	Branch   string       `json:"branch"`
	Scan     *PIIScan     `json:"scan"` // nil before the first scan
	Findings []PIIFinding `json:"findings"`
	// FullScan is the latest scan that read every table. A finding last seen
	// before it was not found again; one only a NewOnly scan skipped was not
	// looked for, and is not "not seen".
	FullScan int64 `json:"fullScan"`
	// Unclassified counts the columns and paths that appeared after the
	// branch's first scan and that no one has reviewed yet (4.7).
	Unclassified int `json:"unclassified"`
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

	// new_only and the inventory came with 4.7; a branch whose tables predate
	// them, on an install that has not started since, reads without them.
	newOnly, err := hasColumn(ctx, conn, "bb.pii_scans", "new_only")
	if err != nil {
		return rep, err
	}
	newOnlyCol := "false"
	if newOnly {
		newOnlyCol = "new_only"
	}
	var s PIIScan
	var skipped, limits []byte
	err = conn.QueryRow(ctx, `SELECT id, started_at, finished_at, actor, sample_size, tables_scanned, columns_scanned, `+newOnlyCol+`,
			skipped, limits, coalesce((SELECT max(id) FROM bb.pii_scans WHERE NOT `+newOnlyCol+`), 0)
		FROM bb.pii_scans ORDER BY id DESC LIMIT 1`).
		Scan(&s.ID, &s.Started, &s.Finished, &s.Actor, &s.Sample, &s.Tables, &s.Columns, &s.NewOnly, &skipped, &limits, &rep.FullScan)
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

	rep.Findings, err = readFindings(ctx, conn, "")
	if err != nil {
		return rep, err
	}
	if rep.Scan != nil {
		var have bool
		if err := conn.QueryRow(ctx, "SELECT to_regclass('bb.pii_columns') IS NOT NULL").Scan(&have); err != nil || !have {
			return rep, err
		}
		err = conn.QueryRow(ctx, `SELECT count(*) FROM bb.pii_columns WHERE status = 'unclassified' AND last_scan = $1`, rep.Scan.ID).
			Scan(&rep.Unclassified)
	}
	return rep, err
}

// hasColumn reports whether a table has a column, for reading a branch whose
// Blackbox tables are older than the code reading them.
func hasColumn(ctx context.Context, conn *pgx.Conn, table, column string) (bool, error) {
	var have bool
	err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_attribute
		WHERE attrelid = to_regclass($1) AND attname = $2 AND NOT attisdropped)`, table, column).Scan(&have)
	return have, err
}

// readFindings reads findings, all of them or those matching where (a SQL
// condition on bb.pii_findings with $1 as its one parameter).
//
// The decision columns came with review (4.6). A branch whose findings were
// made before that, on an install that has not started since, does not have
// them yet, and reading must not fail on it: they read as undecided.
func readFindings(ctx context.Context, conn *pgx.Conn, where string, args ...any) ([]PIIFinding, error) {
	decided := "'' AS decided_by, NULL::timestamptz AS decided_at, '' AS note"
	have, err := hasColumn(ctx, conn, "bb.pii_findings", "decided_by")
	if err != nil {
		return nil, err
	}
	if have {
		decided = "decided_by, decided_at, note"
	}
	q := `SELECT id, schema_name, table_name, column_name, json_path, category, rule, confidence, why,
			matched, sampled, state, first_scan, last_scan, last_seen, ` + decided + `
		FROM bb.pii_findings`
	if where != "" {
		q += " WHERE " + where
	}
	q += ` ORDER BY CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
			schema_name, table_name, column_name, json_path, category`
	rows, err := conn.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PIIFinding{}
	for rows.Next() {
		var f PIIFinding
		if err := rows.Scan(&f.ID, &f.Schema, &f.Table, &f.Column, &f.Path, &f.Category, &f.Rule, &f.Confidence, &f.Why,
			&f.Matched, &f.Sampled, &f.State, &f.FirstScan, &f.LastScan, &f.LastSeen,
			&f.DecidedBy, &f.DecidedAt, &f.Note); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// --- review (point 4.6) -------------------------------------------------------

// The states a finding can be in. Every finding starts suggested; a reviewer
// confirms or rejects it, and can reopen it (back to suggested).
const (
	PIISuggested = "suggested"
	PIIConfirmed = "confirmed"
	PIIRejected  = "rejected"
)

// PIIDecision is one decision on a finding, kept for good: bb.pii_decisions is
// append-only.
type PIIDecision struct {
	ID    int64     `json:"id"`
	State string    `json:"state"`
	Actor string    `json:"actor"`
	Note  string    `json:"note"`
	At    time.Time `json:"at"`
}

// PIIFindingDetail is one finding and every decision made on it, newest last.
type PIIFindingDetail struct {
	Finding   PIIFinding    `json:"finding"`
	Decisions []PIIDecision `json:"decisions"`
}

// PIISample is one value from a finding's location, masked before it left
// the engine.
type PIISample struct {
	Masked  string `json:"masked"`
	Matches bool   `json:"matches"` // whether the value looks like the finding's category
}

// PIISamples is what a reviewer is shown to decide by.
type PIISamples struct {
	Finding PIIFinding  `json:"finding"`
	Samples []PIISample `json:"samples"`
	Read    int         `json:"read"` // values read to choose them from
	As      string      `json:"as"`   // the role they were read as
}

// ErrNoFinding is a finding id the branch does not have.
var ErrNoFinding = errors.New("no such finding on this branch")

// ErrCannotReadLocation is a reviewer whose own role may not read the place a
// finding points at. Samples are read as the reviewer, so the grants and
// row-level security that would stop them anywhere else stop them here too.
var ErrCannotReadLocation = errors.New("your role cannot read this location")

// MaxPIISamples is the most masked samples a reviewer is shown at once.
const MaxPIISamples = 20

var (
	markPII   func(name string, id int64, state, note, actor string) error
	samplePII func(name string, id int64, n int, account string) (PIISamples, error)
)

// SetPIIReviewer installs review: recording a decision, and reading masked
// samples. Called from enterprise/pii's init, and from nowhere else.
func SetPIIReviewer(mark func(name string, id int64, state, note, actor string) error,
	sample func(name string, id int64, n int, account string) (PIISamples, error)) {
	markPII, samplePII = mark, sample
}

// MarkPersonalData records a reviewer's decision on a finding, and returns it
// with its history.
func MarkPersonalData(name string, id int64, state, note, actor string) (PIIFindingDetail, error) {
	if err := requireFeature(edition.PersonalData); err != nil {
		return PIIFindingDetail{}, err
	}
	if markPII == nil {
		return PIIFindingDetail{}, ErrPersonalDataNotLicensed
	}
	switch state {
	case PIIConfirmed, PIIRejected, PIISuggested:
	default:
		return PIIFindingDetail{}, fmt.Errorf("%w: a finding is confirmed, rejected, or reopened (suggested), not %q", ErrInvalidRequest, state)
	}
	if len(note) > 1000 {
		return PIIFindingDetail{}, fmt.Errorf("%w: a note is at most 1000 characters", ErrInvalidRequest)
	}
	if err := markPII(name, id, state, note, actor); err != nil {
		return PIIFindingDetail{}, err
	}
	return PersonalDataFinding(name, id)
}

// PersonalDataSamples reads up to n masked values from a finding's location,
// as account's own role ("" for the operator at the machine, who is the
// superuser anyway). Enterprise: it reads data, which is doing, not reading the
// record.
func PersonalDataSamples(name string, id int64, n int, account string) (PIISamples, error) {
	if err := requireFeature(edition.PersonalData); err != nil {
		return PIISamples{}, err
	}
	if samplePII == nil {
		return PIISamples{}, ErrPersonalDataNotLicensed
	}
	if n == 0 {
		n = 5
	}
	if n < 1 || n > MaxPIISamples {
		return PIISamples{}, fmt.Errorf("%w: 1 to %d samples, not %d", ErrInvalidRequest, MaxPIISamples, n)
	}
	return samplePII(name, id, n, account)
}

// PersonalDataFinding reads one finding and its decisions. Free, as reading
// the record always is.
func PersonalDataFinding(name string, id int64) (PIIFindingDetail, error) {
	if name == "" {
		name = "main"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := OpenSuper(ctx, name)
	if err != nil {
		return PIIFindingDetail{}, err
	}
	defer conn.Close(context.Background())
	var have bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('bb.pii_findings') IS NOT NULL").Scan(&have); err != nil {
		return PIIFindingDetail{}, err
	}
	if !have {
		return PIIFindingDetail{}, ErrNoFinding
	}
	fs, err := readFindings(ctx, conn, "id = $1", id)
	if err != nil {
		return PIIFindingDetail{}, err
	}
	if len(fs) == 0 {
		return PIIFindingDetail{}, ErrNoFinding
	}
	d := PIIFindingDetail{Finding: fs[0], Decisions: []PIIDecision{}}
	if err := conn.QueryRow(ctx, "SELECT to_regclass('bb.pii_decisions') IS NOT NULL").Scan(&have); err != nil || !have {
		return d, err
	}
	rows, err := conn.Query(ctx, `SELECT id, state, actor, note, decided_at FROM bb.pii_decisions WHERE finding_id = $1 ORDER BY id`, id)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var x PIIDecision
		if err := rows.Scan(&x.ID, &x.State, &x.Actor, &x.Note, &x.At); err != nil {
			return d, err
		}
		d.Decisions = append(d.Decisions, x)
	}
	return d, rows.Err()
}

// Where is a finding's location as a reader writes it: schema.table.column,
// and the JSON path inside it when there is one.
func (f PIIFinding) Where() string {
	w := f.Schema + "." + f.Table + "." + f.Column
	if f.Path != "" {
		w += " " + f.Path
	}
	return w
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

// MarkSummary is the security log's line for a decision: which finding, where
// and what kind, and what was decided. A location and a category, never a value.
func (f PIIFinding) MarkSummary() string {
	s := fmt.Sprintf("finding %d (%s, %s): %s", f.ID, f.Where(), f.Category, f.State)
	if f.Note != "" {
		s += " with a note"
	}
	return s
}

// Summary is the security log's line for samples shown: how many, of which
// finding, and as whom. Never the samples, masked or not.
func (s PIISamples) Summary() string {
	return fmt.Sprintf("finding %d (%s, %s): %d masked sample(s) shown, read as %s",
		s.Finding.ID, s.Finding.Where(), s.Finding.Category, len(s.Samples), s.As)
}

// --- keeping it current (point 4.7) -------------------------------------------

// The statuses of a column or path in the inventory.
const (
	PIIKnown        = "known"        // there at the branch's first scan: its findings are reviewed as findings
	PIIUnclassified = "unclassified" // appeared since, and no one has looked yet
	PIIReviewed     = "reviewed"     // appeared since, and someone has
)

// PIIColumn is one column, or one JSON path inside a column, that scans have
// seen: names only.
type PIIColumn struct {
	ID         int64      `json:"id"`
	Schema     string     `json:"schema"`
	Table      string     `json:"table"`
	Column     string     `json:"column"`
	Path       string     `json:"path"`
	Status     string     `json:"status"`
	FirstScan  int64      `json:"firstScan"`
	LastScan   int64      `json:"lastScan"`
	FirstSeen  time.Time  `json:"firstSeen"`
	ReviewedBy string     `json:"reviewedBy"`
	ReviewedAt *time.Time `json:"reviewedAt"`
	Note       string     `json:"note"`
	Findings   int        `json:"findings"`  // findings at this place
	Undecided  int        `json:"undecided"` // of which still suggested
}

// Where is the column's location as a reader writes it.
func (c PIIColumn) Where() string {
	return PIIFinding{Schema: c.Schema, Table: c.Table, Column: c.Column, Path: c.Path}.Where()
}

var acceptPII func(name string, id int64, note, actor string) error

// SetPIIInventory installs accepting a column. Called from enterprise/pii's
// init, and from nowhere else.
func SetPIIInventory(accept func(name string, id int64, note, actor string) error) {
	acceptPII = accept
}

// ErrNoColumn is an inventory id the branch does not have.
var ErrNoColumn = errors.New("no such column in this branch's inventory")

// ErrUndecided is accepting a column whose findings are not all decided: those
// are decided one by one, with the evidence in front of whoever decides.
var ErrUndecided = errors.New("decide its findings first")

// PersonalDataUnclassified lists what has appeared since the branch's first
// scan and is not reviewed yet: columns and paths the latest scan still saw.
// Free, as reading always is.
func PersonalDataUnclassified(name string) ([]PIIColumn, error) {
	if name == "" {
		name = "main"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := OpenSuper(ctx, name)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	var have bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('bb.pii_columns') IS NOT NULL").Scan(&have); err != nil || !have {
		return []PIIColumn{}, err
	}
	return readColumns(ctx, conn, `c.status = 'unclassified' AND c.last_scan = (SELECT max(id) FROM bb.pii_scans)`)
}

// PersonalDataColumn reads one inventory entry.
func PersonalDataColumn(name string, id int64) (PIIColumn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := OpenSuper(ctx, name)
	if err != nil {
		return PIIColumn{}, err
	}
	defer conn.Close(context.Background())
	var have bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('bb.pii_columns') IS NOT NULL").Scan(&have); err != nil {
		return PIIColumn{}, err
	}
	if !have {
		return PIIColumn{}, ErrNoColumn
	}
	cs, err := readColumns(ctx, conn, "c.id = $1", id)
	if err != nil {
		return PIIColumn{}, err
	}
	if len(cs) == 0 {
		return PIIColumn{}, ErrNoColumn
	}
	return cs[0], nil
}

func readColumns(ctx context.Context, conn *pgx.Conn, where string, args ...any) ([]PIIColumn, error) {
	rows, err := conn.Query(ctx, `SELECT c.id, c.schema_name, c.table_name, c.column_name, c.json_path, c.status,
			c.first_scan, c.last_scan, c.first_seen, c.reviewed_by, c.reviewed_at, c.note,
			count(f.id)::int, count(f.id) FILTER (WHERE f.state = 'suggested')::int
		FROM bb.pii_columns c
		LEFT JOIN bb.pii_findings f ON (f.schema_name, f.table_name, f.column_name, f.json_path)
		                             = (c.schema_name, c.table_name, c.column_name, c.json_path)
		WHERE `+where+`
		GROUP BY c.id
		ORDER BY c.schema_name, c.table_name, c.column_name, c.json_path`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PIIColumn{}
	for rows.Next() {
		var c PIIColumn
		if err := rows.Scan(&c.ID, &c.Schema, &c.Table, &c.Column, &c.Path, &c.Status, &c.FirstScan, &c.LastScan,
			&c.FirstSeen, &c.ReviewedBy, &c.ReviewedAt, &c.Note, &c.Findings, &c.Undecided); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AcceptPersonalData records that a person has looked at an unclassified
// column or path and it holds nothing to classify. Refused while any of its
// findings are undecided: those are decided one by one (MarkPersonalData),
// which reviews the column too once the last is.
func AcceptPersonalData(name string, id int64, note, actor string) (PIIColumn, error) {
	if err := requireFeature(edition.PersonalData); err != nil {
		return PIIColumn{}, err
	}
	if acceptPII == nil {
		return PIIColumn{}, ErrPersonalDataNotLicensed
	}
	if len(note) > 1000 {
		return PIIColumn{}, fmt.Errorf("%w: a note is at most 1000 characters", ErrInvalidRequest)
	}
	if err := acceptPII(name, id, note, actor); err != nil {
		return PIIColumn{}, err
	}
	return PersonalDataColumn(name, id)
}

// AcceptSummary is the security log's line for accepting a column.
func (c PIIColumn) AcceptSummary() string {
	s := fmt.Sprintf("column %d (%s): %s", c.ID, c.Where(), c.Status)
	if c.Note != "" {
		s += " with a note"
	}
	return s
}
