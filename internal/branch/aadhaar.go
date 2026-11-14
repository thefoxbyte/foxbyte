// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// The Aadhaar exposure report (point 4.5): which person's Aadhaar is exposed
// in a branch, where, and since when.
//
// A run reads every row of every text, number and JSON column, and keeps each
// place a number sits as its column (or JSON path), the row's primary key and
// the number's last four digits. Never the number and never a hash of it
// (UIDAI forbids hashes of Aadhaar as reference keys, and twelve digits with a
// check digit are few enough to be found from any hash). Places of the same
// number are grouped as one person by the run that saw them, holding the
// numbers in memory and nowhere else.
//
// Running it is Enterprise (enterprise/pii supplies it), under the
// personal-data licence feature; reading what runs found is free, as the
// scan's findings are. The tables are the branch's (bb.aadhaar_*), so a
// branch's report travels with it.
//
// The logs part (4.5b) reads, in the same run, the query history entries made
// on the branch, the audit log's forensic statement text for it and its
// Blackbox's statements, so a number in a table and in a log is one person.
// What it finds is kept in the install's store (internal/auth/aadhaarlog.go),
// never in the branch, and only admins and the machine's operator run or read
// it: it says who typed whose number.

// AadhaarRunOptions is what a run is asked to do.
type AadhaarRunOptions struct {
	Actor string // who asked, kept with the run
	// TableTimeout bounds one table's read; DefaultAadhaarTableTimeout when 0.
	TableTimeout time.Duration
	// Logs reads the branch's logs too (4.5b), and needs Store.
	Logs bool
	// Store is the install's store. Given, the report returned includes the
	// logs part: the caller is an admin or the machine's operator.
	Store *auth.Store `json:"-"`
}

// DefaultAadhaarTableTimeout is how long one table's read may take, unless told.
const (
	DefaultAadhaarTableTimeout = 5 * time.Minute
	MaxAadhaarTableTimeout     = time.Hour
)

// AadhaarRun is one run: when, by whom, what it read and what it found.
type AadhaarRun struct {
	ID       int64     `json:"id"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Actor    string    `json:"actor"`
	Tables   int       `json:"tables"`
	Columns  int       `json:"columns"`
	Rows     int64     `json:"rows"`    // rows the database's filter passed on: twelve digits in Aadhaar's shape
	Numbers  int64     `json:"numbers"` // numbers found, place by place
	People   int       `json:"people"`  // distinct numbers
	Listed   int       `json:"listed"`  // places kept
	Skipped  []PIISkip `json:"skipped"`
	// Limits are what the run could not read or cannot claim, in sentences.
	Limits []string `json:"limits"`
}

// AadhaarColumn is what a run found in one column, or one JSON path in one.
type AadhaarColumn struct {
	Schema  string `json:"schema"`
	Table   string `json:"table"`
	Column  string `json:"column"`
	Path    string `json:"path"`
	Numbers int64  `json:"numbers"`
	Rows    int64  `json:"rows"`
	Listed  int    `json:"listed"`
	// Capped says only the first Listed places were kept: the column holds
	// more numbers than one report lists.
	Capped bool `json:"capped"`
	// Since is the earliest any of its kept places has been exposed.
	Since *time.Time `json:"since"`
}

// Where is the column's location as a reader writes it.
func (c AadhaarColumn) Where() string {
	return PIIFinding{Schema: c.Schema, Table: c.Table, Column: c.Column, Path: c.Path}.Where()
}

// AadhaarPlace is one number in one place.
type AadhaarPlace struct {
	ID     int64  `json:"id"`
	Schema string `json:"schema"`
	Table  string `json:"table"`
	Column string `json:"column"`
	Path   string `json:"path"`
	Row    string `json:"row"`    // the row's primary key: id=42
	Last4  string `json:"last4"`  // the number's last four digits
	Masked string `json:"masked"` // XXXX XXXX 1234
	// Person is the run's number for whose Aadhaar this is: places with the
	// same person hold the same number. 0 when the run held too many numbers
	// to group them all.
	Person     int        `json:"person"`
	FirstSeen  time.Time  `json:"firstSeen"`
	LastSeen   time.Time  `json:"lastSeen"`
	RowCreated *time.Time `json:"rowCreated"` // the row's created_at, on a tracked table
	// Since is the earliest the number is known to have been here: the row's
	// creation if it is tracked and earlier, else the first run that saw it.
	Since time.Time `json:"since"`
	// Gone says the latest run read this place's table in full and did not
	// find the number there again.
	Gone bool `json:"gone"`
}

// Where is the place as a reader writes it: schema.table.column [path] row.
func (p AadhaarPlace) Where() string {
	return PIIFinding{Schema: p.Schema, Table: p.Table, Column: p.Column, Path: p.Path}.Where() + " " + p.Row
}

// AadhaarPerson is one number, by its masked form, and where it is.
type AadhaarPerson struct {
	Person int       `json:"person"`
	Masked string    `json:"masked"`
	Places int       `json:"places"` // places kept for it
	Since  time.Time `json:"since"`
	// Where are its columns (schema.table.column [path]), each once, and
	// then the logs it is in (query history, audit log, Blackbox).
	Where []string `json:"where"`
	// Logs counts its places in each log source, in a report with the logs
	// part (4.5b); Places includes them.
	Logs map[string]int `json:"logs,omitempty"`
}

// AadhaarReport is a branch's exposure now: the latest run, what it found
// column by column, and the people whose numbers it found.
type AadhaarReport struct {
	Branch  string          `json:"branch"`
	Run     *AadhaarRun     `json:"run"` // nil before the first run
	Columns []AadhaarColumn `json:"columns"`
	// People are the numbers found, those in the most places first, up to
	// MaxAadhaarPeople; PeopleListed is how many have a kept place.
	People       []AadhaarPerson `json:"people"`
	PeopleListed int             `json:"peopleListed"`
	// Gone counts places earlier runs found that the latest no longer does.
	Gone int `json:"gone"`
	// Logs is the logs part (4.5b): only for an admin or the machine's
	// operator, and only once a run has read them.
	Logs *AadhaarLogsReport `json:"logs,omitempty"`
}

// AadhaarLogsReport is a branch's latest logs part.
type AadhaarLogsReport struct {
	Run *auth.AadhaarLogRun `json:"run"`
	// Linked says the logs were read with the latest run of the tables, so its
	// people are the report's: a logs run read with an earlier run of the
	// tables numbered its people its own way, and they are listed apart.
	Linked  bool                         `json:"linked"`
	Sources []auth.AadhaarLogSourceCount `json:"sources"`
	// People are the logs' people, the most places first.
	People []AadhaarPerson `json:"people"`
	// Gone counts places in the logs earlier runs found that this one did not:
	// an entry deleted or past its retention.
	Gone int `json:"gone"`
}

// MaxAadhaarPeople is the most people a report returns; the places are read
// with AadhaarPlaces.
const MaxAadhaarPeople = 500

// MaskAadhaar is UIDAI's masked form of a number: its last four digits only.
func MaskAadhaar(last4 string) string { return "XXXX XXXX " + last4 }

var runAadhaar func(name string, o AadhaarRunOptions) (AadhaarRun, error)

// SetAadhaarReporter installs the run. Called from enterprise/pii's init, and
// from nowhere else.
func SetAadhaarReporter(fn func(name string, o AadhaarRunOptions) (AadhaarRun, error)) {
	runAadhaar = fn
}

// CheckAadhaarRunOptions fills in the defaults and refuses what cannot be right.
func CheckAadhaarRunOptions(o AadhaarRunOptions) (AadhaarRunOptions, error) {
	if o.TableTimeout == 0 {
		o.TableTimeout = DefaultAadhaarTableTimeout
	}
	if o.TableTimeout < time.Second || o.TableTimeout > MaxAadhaarTableTimeout {
		return o, fmt.Errorf("%w: a table's read may take 1s to %s, not %s", ErrInvalidRequest, MaxAadhaarTableTimeout, o.TableTimeout)
	}
	return o, nil
}

// RunAadhaarExposure reads a branch for Aadhaar numbers and returns its
// report afterwards.
func RunAadhaarExposure(name string, o AadhaarRunOptions) (AadhaarReport, error) {
	if err := requireFeature(edition.PersonalData); err != nil {
		return AadhaarReport{}, err
	}
	if runAadhaar == nil {
		return AadhaarReport{}, ErrPersonalDataNotLicensed
	}
	o, err := CheckAadhaarRunOptions(o)
	if err != nil {
		return AadhaarReport{}, err
	}
	if o.Logs && o.Store == nil {
		return AadhaarReport{}, errors.New("reading the logs needs the install's store, which could not be opened")
	}
	if _, err := runAadhaar(name, o); err != nil {
		return AadhaarReport{}, err
	}
	return AadhaarExposureFor(name, o.Store)
}

// latestAadhaarRun opens a branch and reads its latest run; nil, with no
// error, when it has none or no report tables yet.
func latestAadhaarRun(ctx context.Context, name string) (*pgx.Conn, *AadhaarRun, error) {
	conn, err := OpenSuper(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	var have bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('bb.aadhaar_runs') IS NOT NULL AND to_regclass('bb.aadhaar_places') IS NOT NULL
			AND to_regclass('bb.aadhaar_columns') IS NOT NULL`).Scan(&have); err != nil {
		conn.Close(context.Background())
		return nil, nil, err
	}
	if !have {
		return conn, nil, nil
	}
	var r AadhaarRun
	var skipped, limits []byte
	err = conn.QueryRow(ctx, `SELECT id, started_at, finished_at, actor, tables_read, columns_read, rows_read,
			numbers, people, listed, skipped, limits
		FROM bb.aadhaar_runs ORDER BY id DESC LIMIT 1`).
		Scan(&r.ID, &r.Started, &r.Finished, &r.Actor, &r.Tables, &r.Columns, &r.Rows, &r.Numbers, &r.People, &r.Listed, &skipped, &limits)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return conn, nil, nil
	case err != nil:
		conn.Close(context.Background())
		return nil, nil, err
	}
	if err := json.Unmarshal(skipped, &r.Skipped); err != nil {
		conn.Close(context.Background())
		return nil, nil, err
	}
	if err := json.Unmarshal(limits, &r.Limits); err != nil {
		conn.Close(context.Background())
		return nil, nil, err
	}
	return conn, &r, nil
}

// AadhaarExposure reads a branch's report as its latest run left it. Free in
// every edition, as reading a scan's findings is.
func AadhaarExposure(name string) (AadhaarReport, error) {
	return AadhaarExposureFor(name, nil)
}

// AadhaarExposureFor is AadhaarExposure with the logs part, when st (the
// install's store) is given: for an admin or the machine's operator.
func AadhaarExposureFor(name string, st *auth.Store) (AadhaarReport, error) {
	if name == "" {
		name = "main"
	}
	rep := AadhaarReport{Branch: name, Columns: []AadhaarColumn{}, People: []AadhaarPerson{}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, run, err := latestAadhaarRun(ctx, name)
	if err != nil {
		return rep, err
	}
	defer conn.Close(context.Background())
	if run == nil {
		return rep, nil
	}
	rep.Run = run

	rows, err := conn.Query(ctx, `SELECT c.schema_name, c.table_name, c.column_name, c.json_path, c.numbers, c.rows_with, c.listed, c.capped,
			(SELECT min(least(p.first_seen, coalesce(p.row_created, p.first_seen))) FROM bb.aadhaar_places p
			 WHERE p.last_run = c.run_id AND (p.schema_name, p.table_name, p.column_name, p.json_path)
			                                = (c.schema_name, c.table_name, c.column_name, c.json_path))
		FROM bb.aadhaar_columns c WHERE c.run_id = $1
		ORDER BY c.numbers DESC, c.schema_name, c.table_name, c.column_name, c.json_path`, run.ID)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var c AadhaarColumn
		if err := rows.Scan(&c.Schema, &c.Table, &c.Column, &c.Path, &c.Numbers, &c.Rows, &c.Listed, &c.Capped, &c.Since); err != nil {
			rows.Close()
			return rep, err
		}
		rep.Columns = append(rep.Columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return rep, err
	}

	// People, from the places the latest run kept: one row each, its columns
	// each once.
	rows, err = conn.Query(ctx, `SELECT person, min(last4), count(*)::int,
			min(least(first_seen, coalesce(row_created, first_seen))),
			array_agg(DISTINCT schema_name || '.' || table_name || '.' || column_name || CASE WHEN json_path <> '' THEN ' ' || json_path ELSE '' END),
			count(*) OVER ()::int
		FROM bb.aadhaar_places WHERE last_run = $1 AND person > 0
		GROUP BY person
		ORDER BY count(*) DESC, 4, person
		LIMIT $2`, run.ID, MaxAadhaarPeople)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var p AadhaarPerson
		var last4 string
		if err := rows.Scan(&p.Person, &last4, &p.Places, &p.Since, &p.Where, &rep.PeopleListed); err != nil {
			rows.Close()
			return rep, err
		}
		sort.Strings(p.Where)
		p.Masked = MaskAadhaar(last4)
		rep.People = append(rep.People, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return rep, err
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM bb.aadhaar_places p WHERE `+goneSQL, run.ID).Scan(&rep.Gone); err != nil {
		return rep, err
	}
	if st == nil {
		return rep, nil
	}
	return rep, withAadhaarLogs(ctx, conn, st, &rep)
}

// withAadhaarLogs adds the logs part to a report: the branch's latest logs
// run, and, when it was read with the latest run of the tables, its people
// merged into the report's.
func withAadhaarLogs(ctx context.Context, conn *pgx.Conn, st *auth.Store, rep *AadhaarReport) error {
	lr, err := st.LatestAadhaarLogRun(rep.Branch)
	if err != nil || lr == nil {
		return err
	}
	// The run of the tables it was read with, and read just after it: a
	// branch deleted and made again numbers its runs from 1, and an old logs
	// run of the same name is not this one's.
	linked := lr.BranchRun == rep.Run.ID && !lr.Started.Add(time.Second).Before(rep.Run.Finished)
	logs := &AadhaarLogsReport{Run: lr, Linked: linked, People: []AadhaarPerson{}}
	if logs.Sources, logs.Gone, err = st.AadhaarLogCounts(lr); err != nil {
		return err
	}
	people, err := st.AadhaarLogPeople(lr)
	if err != nil {
		return err
	}
	for _, lp := range people {
		p := AadhaarPerson{Person: lp.Person, Masked: MaskAadhaar(lp.Last4), Places: lp.Places, Since: lp.Since, Logs: lp.Sources}
		p.Where = aadhaarLogWhere(lp.Sources)
		logs.People = append(logs.People, p)
	}
	if len(logs.People) > MaxAadhaarPeople {
		logs.People = logs.People[:MaxAadhaarPeople]
	}
	rep.Logs = logs
	if !logs.Linked || len(people) == 0 {
		return nil
	}

	// One list of people: the tables' and the logs', a person in both once.
	// The tables' places of the logs' people, which may be past the report's
	// first MaxAadhaarPeople.
	ids := make([]int32, len(people))
	for i, p := range people {
		ids[i] = int32(p.Person)
	}
	rows, err := conn.Query(ctx, `SELECT person, min(last4), count(*)::int,
			min(least(first_seen, coalesce(row_created, first_seen))),
			array_agg(DISTINCT schema_name || '.' || table_name || '.' || column_name || CASE WHEN json_path <> '' THEN ' ' || json_path ELSE '' END)
		FROM bb.aadhaar_places WHERE last_run = $1 AND person = ANY($2) GROUP BY person`, rep.Run.ID, ids)
	if err != nil {
		return err
	}
	byPerson := map[int]*AadhaarPerson{}
	for i := range rep.People {
		byPerson[rep.People[i].Person] = &rep.People[i]
	}
	inTables := map[int]AadhaarPerson{}
	for rows.Next() {
		var p AadhaarPerson
		var last4 string
		if err := rows.Scan(&p.Person, &last4, &p.Places, &p.Since, &p.Where); err != nil {
			rows.Close()
			return err
		}
		sort.Strings(p.Where)
		p.Masked = MaskAadhaar(last4)
		inTables[p.Person] = p
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// Those already listed first, through pointers into rep.People, before
	// any append can move it.
	var rest []auth.AadhaarLogPerson
	for _, lp := range people {
		if cur, ok := byPerson[lp.Person]; ok {
			addAadhaarLogs(cur, lp)
		} else {
			rest = append(rest, lp)
		}
	}
	merged := rep.People
	for _, lp := range rest {
		p, ok := inTables[lp.Person]
		if !ok {
			// In the logs only.
			p = AadhaarPerson{Person: lp.Person, Masked: MaskAadhaar(lp.Last4), Since: lp.Since, Where: []string{}}
			rep.PeopleListed++
		}
		addAadhaarLogs(&p, lp)
		merged = append(merged, p)
	}
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].Places != merged[j].Places {
			return merged[i].Places > merged[j].Places
		}
		if !merged[i].Since.Equal(merged[j].Since) {
			return merged[i].Since.Before(merged[j].Since)
		}
		return merged[i].Person < merged[j].Person
	})
	if len(merged) > MaxAadhaarPeople {
		merged = merged[:MaxAadhaarPeople]
	}
	rep.People = merged
	return nil
}

// addAadhaarLogs adds a person's places in the logs to their places in the
// tables.
func addAadhaarLogs(p *AadhaarPerson, lp auth.AadhaarLogPerson) {
	p.Places += lp.Places
	if lp.Since.Before(p.Since) || p.Since.IsZero() {
		p.Since = lp.Since
	}
	p.Logs = lp.Sources
	p.Where = append(p.Where, aadhaarLogWhere(lp.Sources)...)
}

// aadhaarLogWhere names the log sources a person is in, in the report's order.
func aadhaarLogWhere(by map[string]int) []string {
	out := []string{}
	for _, src := range auth.AadhaarLogSources {
		if by[src] > 0 {
			out = append(out, auth.AadhaarLogSourceName(src))
		}
	}
	return out
}

// AadhaarLogPlaces lists the log places of a branch's latest logs run, or
// those it no longer found: for an admin or the machine's operator.
func AadhaarLogPlaces(name string, st *auth.Store, f auth.AadhaarLogFilter) ([]auth.AadhaarLogPlace, error) {
	if name == "" {
		name = "main"
	}
	if f.Limit == 0 {
		f.Limit = DefaultAadhaarPlaces
	}
	if f.Limit < 1 || f.Limit > MaxAadhaarPlaces {
		return nil, fmt.Errorf("%w: a list is 1 to %d places, not %d", ErrInvalidRequest, MaxAadhaarPlaces, f.Limit)
	}
	if f.Source != "" && !auth.ValidAadhaarLogSource(f.Source) {
		return nil, fmt.Errorf("%w: a log is %s, not %q", ErrInvalidRequest, strings.Join(auth.AadhaarLogSources, ", "), f.Source)
	}
	f.Source = strings.ToLower(f.Source)
	out := []auth.AadhaarLogPlace{}
	lr, err := st.LatestAadhaarLogRun(name)
	if err != nil || lr == nil {
		return out, err
	}
	ps, err := st.AadhaarLogPlaces(lr, f)
	if err != nil {
		return nil, err
	}
	for i := range ps {
		ps[i].Masked = MaskAadhaar(ps[i].Last4)
	}
	return ps, nil
}

// goneSQL is the condition, on bb.aadhaar_places p, for a place the latest
// run ($1) no longer found: one an earlier run kept, in a table the latest
// read in full (not skipped), in a column it was not capped in. A place in a
// table the latest run could not read was not looked for, which is not gone.
const goneSQL = `p.last_run < $1
	AND NOT EXISTS (SELECT 1 FROM bb.aadhaar_runs r, jsonb_array_elements(r.skipped) s
	                WHERE r.id = $1 AND s->>'object' = p.schema_name || '.' || p.table_name)
	AND NOT EXISTS (SELECT 1 FROM bb.aadhaar_columns c
	                WHERE c.run_id = $1 AND c.capped AND (c.schema_name, c.table_name, c.column_name, c.json_path)
	                                                  = (p.schema_name, p.table_name, p.column_name, p.json_path))`

// AadhaarPlaceFilter narrows a list of places.
type AadhaarPlaceFilter struct {
	Person int    // one person's places; 0 for every person
	Where  string // one column: schema.table.column, or with " $.path"
	Gone   bool   // places no longer found, rather than those found now
	Limit  int    // at most this many; DefaultAadhaarPlaces when 0
}

// The most places one list returns, unless told.
const (
	DefaultAadhaarPlaces = 200
	MaxAadhaarPlaces     = 10000
)

// AadhaarPlaces lists the places of a branch's latest run, or those it no
// longer found. Free, as reading always is.
func AadhaarPlaces(name string, f AadhaarPlaceFilter) ([]AadhaarPlace, error) {
	if name == "" {
		name = "main"
	}
	if f.Limit == 0 {
		f.Limit = DefaultAadhaarPlaces
	}
	if f.Limit < 1 || f.Limit > MaxAadhaarPlaces {
		return nil, fmt.Errorf("%w: a list is 1 to %d places, not %d", ErrInvalidRequest, MaxAadhaarPlaces, f.Limit)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, run, err := latestAadhaarRun(ctx, name)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	out := []AadhaarPlace{}
	if run == nil {
		return out, nil
	}
	cond, args := "p.last_run = $1", []any{run.ID}
	if f.Gone {
		cond = goneSQL
	}
	if f.Person != 0 {
		args = append(args, f.Person)
		cond += fmt.Sprintf(" AND p.last_run = $1 AND p.person = $%d", len(args))
	}
	if f.Where != "" {
		args = append(args, f.Where)
		cond += fmt.Sprintf(` AND p.schema_name || '.' || p.table_name || '.' || p.column_name
			|| CASE WHEN p.json_path <> '' THEN ' ' || p.json_path ELSE '' END = $%d`, len(args))
	}
	args = append(args, f.Limit)
	rows, err := conn.Query(ctx, `SELECT p.id, p.schema_name, p.table_name, p.column_name, p.json_path, p.row_key, p.last4,
			CASE WHEN p.last_run = $1 THEN p.person ELSE 0 END, p.first_seen, p.last_seen, p.row_created
		FROM bb.aadhaar_places p WHERE `+cond+fmt.Sprintf(`
		ORDER BY p.person, p.schema_name, p.table_name, p.column_name, p.json_path, p.id LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p AadhaarPlace
		if err := rows.Scan(&p.ID, &p.Schema, &p.Table, &p.Column, &p.Path, &p.Row, &p.Last4,
			&p.Person, &p.FirstSeen, &p.LastSeen, &p.RowCreated); err != nil {
			return nil, err
		}
		p.Masked = MaskAadhaar(p.Last4)
		p.Since = p.FirstSeen
		if p.RowCreated != nil && p.RowCreated.Before(p.Since) {
			p.Since = *p.RowCreated
		}
		p.Gone = f.Gone
		out = append(out, p)
	}
	return out, rows.Err()
}

// Summary is what the security log keeps of a run: its coverage and how much
// it found. Counts only: never a place, a row or a digit.
func (r AadhaarReport) Summary() string {
	if r.Run == nil {
		return "read"
	}
	x := r.Run
	s := fmt.Sprintf("run %d: %d table(s), %d column(s), %d skipped; %d number(s) in %d place(s) kept, %d distinct",
		x.ID, x.Tables, x.Columns, len(x.Skipped), x.Numbers, x.Listed, x.People)
	if r.Logs != nil && r.Logs.Linked {
		l := r.Logs.Run
		read := 0
		for _, n := range l.Read {
			read += n
		}
		s += fmt.Sprintf("; logs: %d entr(ies) read, %d skipped; %d number(s) in %d place(s) kept, %d distinct, %d also in the tables",
			read, len(l.Skipped), l.Numbers, l.Listed, l.People, l.Linked)
	}
	return s
}

// ParseAadhaarWhere checks a column as a filter names it: schema.table.column,
// optionally followed by a space and a JSON path.
func ParseAadhaarWhere(s string) (string, error) {
	col, _, _ := strings.Cut(s, " ")
	if strings.Count(col, ".") < 2 {
		return "", fmt.Errorf("%w: a column is schema.table.column, not %q", ErrInvalidRequest, s)
	}
	return s, nil
}
