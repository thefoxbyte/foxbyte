// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The Aadhaar exposure report's logs part (point 4.5b): where a branch's logs
// hold an Aadhaar number. A run reads the query history entries made on a
// branch, the audit log's forensic statement text and the branch's Blackbox
// statements, in the same run as the branch's tables, so a number in a table
// and in a log is one person. What it finds is kept here, in the install's
// store, never in the branch: a table in the branch would be copied into
// every branch made from it, carrying who typed whose number with it, which is
// why query history lives here too (history.go).
//
// A place is a log entry and the number's last four digits: which source,
// which entry, who made it, when. Never the number and never a hash of it, as
// the table part keeps none (internal/branch/aadhaar.go). Only admins and the
// machine's operator read it: it says who typed whose number.

const aadhaarLogSchema = `
CREATE TABLE IF NOT EXISTS aadhaar_log_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch TEXT NOT NULL,
  branch_run INTEGER NOT NULL,
  started INTEGER NOT NULL, finished INTEGER NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  read TEXT NOT NULL DEFAULT '{}',
  numbers INTEGER NOT NULL DEFAULT 0, people INTEGER NOT NULL DEFAULT 0,
  linked INTEGER NOT NULL DEFAULT 0, listed INTEGER NOT NULL DEFAULT 0,
  skipped TEXT NOT NULL DEFAULT '[]', limits TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS aadhaar_log_runs_branch ON aadhaar_log_runs(branch, id);
CREATE TABLE IF NOT EXISTS aadhaar_log_places (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  branch TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('history', 'audit', 'blackbox')),
  entry INTEGER NOT NULL,
  field TEXT NOT NULL DEFAULT '',
  last4 TEXT NOT NULL CHECK (length(last4) = 4 AND last4 NOT GLOB '*[^0-9]*'),
  actor TEXT NOT NULL DEFAULT '',
  at INTEGER NOT NULL,
  person INTEGER NOT NULL DEFAULT 0,
  first_run INTEGER NOT NULL, last_run INTEGER NOT NULL,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  UNIQUE (branch, source, entry, field, last4)
);
CREATE INDEX IF NOT EXISTS aadhaar_log_places_run ON aadhaar_log_places(branch, last_run, person);`

// The log sources a run reads.
const (
	AadhaarLogHistory  = "history"  // query history: the SQL people ran, and its errors
	AadhaarLogAudit    = "audit"    // the audit log's forensic statement text
	AadhaarLogBlackbox = "blackbox" // the branch's Blackbox: its statements
)

// AadhaarLogSources are the sources, in the order a report lists them.
var AadhaarLogSources = []string{AadhaarLogHistory, AadhaarLogAudit, AadhaarLogBlackbox}

// AadhaarLogSourceName is a source as a reader names it.
func AadhaarLogSourceName(source string) string {
	switch source {
	case AadhaarLogHistory:
		return "query history"
	case AadhaarLogAudit:
		return "audit log"
	case AadhaarLogBlackbox:
		return "Blackbox"
	}
	return source
}

// AadhaarLogSkip is a source a run could not read, and why.
type AadhaarLogSkip struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// AadhaarLogRun is one run's logs part.
type AadhaarLogRun struct {
	ID     int64  `json:"id"`
	Branch string `json:"branch"`
	// BranchRun is the run of the branch's tables it was read with: places
	// with the same person in both hold the same number.
	BranchRun int64     `json:"branchRun"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`
	Actor     string    `json:"actor"`
	// Read is how many entries each source had, read whole.
	Read    map[string]int `json:"read"`
	Numbers int64          `json:"numbers"` // numbers found, place by place
	People  int            `json:"people"`  // distinct numbers in the logs
	// Linked is how many of People are also in the branch's tables.
	Linked  int              `json:"linked"`
	Listed  int              `json:"listed"` // places kept
	Skipped []AadhaarLogSkip `json:"skipped"`
	Limits  []string         `json:"limits"`
}

// AadhaarLogPlace is one number in one log entry.
type AadhaarLogPlace struct {
	ID     int64  `json:"id"`
	Source string `json:"source"`
	// Entry is the entry's number in its source: the history entry's id, the
	// audit record's sequence number, the Blackbox entry's id.
	Entry int64 `json:"entry"`
	// Field is the part of a history entry: sql, or error. "" elsewhere.
	Field string `json:"field"`
	Last4 string `json:"last4"`
	// Masked is filled in by the reader (internal/branch), as UIDAI masks it.
	Masked string `json:"masked"`
	// Actor is who made the entry: who ran the statement.
	Actor string `json:"actor"`
	// At is when the entry was made; the number has been there since then.
	At        time.Time `json:"at"`
	Person    int       `json:"person"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Gone      bool      `json:"gone"`
}

// AadhaarLogPerson is one person's places in the logs of one run.
type AadhaarLogPerson struct {
	Person  int            `json:"person"`
	Last4   string         `json:"last4"`
	Places  int            `json:"places"`
	Since   time.Time      `json:"since"`
	Sources map[string]int `json:"sources"` // places by source
}

// EachHistoryEntry hands fn every history entry made on a branch, within the
// retention, whoever ran it, oldest first. For the logs part only: the
// console and the API read the caller's own history (History).
func (s *Store) EachHistoryEntry(branch string, fn func(HistoryEntry) error) (int, error) {
	set, err := s.HistorySettings()
	if err != nil {
		return 0, err
	}
	rows, err := s.db.Query(`SELECT id, actor, branch, source, kind, sql, truncated, at, ok, error
		FROM query_history WHERE branch=? AND at>=? ORDER BY id`, branch, retentionCutoff(set))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var e HistoryEntry
		var trunc, ok int
		if err := rows.Scan(&e.ID, &e.Actor, &e.Branch, &e.Source, &e.Kind, &e.SQL, &trunc, &e.At, &ok, &e.Error); err != nil {
			return n, err
		}
		e.Truncated, e.OK = trunc != 0, ok != 0
		n++
		if err := fn(e); err != nil {
			return n, err
		}
	}
	return n, rows.Err()
}

// RecordAadhaarLogs keeps a run's logs part: the run, and its places, a place
// found before keeping when it was first seen. One transaction.
func (s *Store) RecordAadhaarLogs(r *AadhaarLogRun, places []AadhaarLogPlace) error {
	if r.Branch == "" || r.BranchRun == 0 {
		return errors.New("a logs run needs its branch and the run of its tables")
	}
	read, _ := json.Marshal(r.Read)
	skipped, _ := json.Marshal(r.Skipped)
	limits, _ := json.Marshal(r.Limits)
	return retryBusy(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		res, err := tx.Exec(`INSERT INTO aadhaar_log_runs
			(branch, branch_run, started, finished, actor, read, numbers, people, linked, listed, skipped, limits)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.Branch, r.BranchRun, r.Started.UnixMilli(), r.Finished.UnixMilli(), r.Actor, string(read),
			r.Numbers, r.People, r.Linked, r.Listed, string(skipped), string(limits))
		if err != nil {
			return fmt.Errorf("recording the logs run: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		st, err := tx.Prepare(`INSERT INTO aadhaar_log_places
			(branch, source, entry, field, last4, actor, at, person, first_run, last_run, first_seen, last_seen)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT (branch, source, entry, field, last4) DO UPDATE SET
			  person = excluded.person, last_run = excluded.last_run, last_seen = excluded.last_seen,
			  actor = excluded.actor, at = excluded.at`)
		if err != nil {
			return err
		}
		defer st.Close()
		seen := r.Started.UnixMilli()
		for _, p := range places {
			if _, err := st.Exec(r.Branch, p.Source, p.Entry, p.Field, p.Last4, p.Actor, p.At.UnixMilli(),
				p.Person, id, id, seen, seen); err != nil {
				return fmt.Errorf("recording the log places: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		r.ID = id
		return nil
	})
}

// LatestAadhaarLogRun is a branch's latest logs run; nil before the first.
func (s *Store) LatestAadhaarLogRun(branch string) (*AadhaarLogRun, error) {
	var r AadhaarLogRun
	var started, finished int64
	var read, skipped, limits string
	err := s.db.QueryRow(`SELECT id, branch, branch_run, started, finished, actor, read, numbers, people, linked, listed, skipped, limits
		FROM aadhaar_log_runs WHERE branch=? ORDER BY id DESC LIMIT 1`, branch).Scan(
		&r.ID, &r.Branch, &r.BranchRun, &started, &finished, &r.Actor, &read, &r.Numbers, &r.People, &r.Linked, &r.Listed, &skipped, &limits)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Started, r.Finished = time.UnixMilli(started).UTC(), time.UnixMilli(finished).UTC()
	if err := json.Unmarshal([]byte(read), &r.Read); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(skipped), &r.Skipped); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(limits), &r.Limits); err != nil {
		return nil, err
	}
	return &r, nil
}

// aadhaarLogGone is the condition for a place the run (the first argument)
// no longer found: one an earlier run kept, in a source the run read whole.
// A source the run could not read was not looked in, which is not gone.
const aadhaarLogGone = `p.last_run < ? AND p.source NOT IN (SELECT value ->> 'source' FROM aadhaar_log_runs r, json_each(r.skipped) WHERE r.id = ?)`

// AadhaarLogPeople are the people in a run's log places, the most places
// first, every one: a run keeps at most a bounded number of log places.
func (s *Store) AadhaarLogPeople(r *AadhaarLogRun) ([]AadhaarLogPerson, error) {
	rows, err := s.db.Query(`SELECT person, last4, source, count(*), min(at) FROM aadhaar_log_places
		WHERE branch=? AND last_run=? AND person > 0 GROUP BY person, last4, source`, r.Branch, r.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[int]*AadhaarLogPerson{}
	for rows.Next() {
		var person, n int
		var last4, source string
		var at int64
		if err := rows.Scan(&person, &last4, &source, &n, &at); err != nil {
			return nil, err
		}
		p := by[person]
		if p == nil {
			p = &AadhaarLogPerson{Person: person, Last4: last4, Sources: map[string]int{}, Since: time.UnixMilli(at).UTC()}
			by[person] = p
		}
		p.Places += n
		p.Sources[source] += n
		if t := time.UnixMilli(at).UTC(); t.Before(p.Since) {
			p.Since = t
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]AadhaarLogPerson, 0, len(by))
	for _, p := range by {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Places != out[j].Places {
			return out[i].Places > out[j].Places
		}
		return out[i].Person < out[j].Person
	})
	return out, nil
}

// AadhaarLogSourceCount is what a run found in one source.
type AadhaarLogSourceCount struct {
	Source  string     `json:"source"`
	Entries int        `json:"entries"` // entries holding a number
	Places  int        `json:"places"`
	Since   *time.Time `json:"since"`
}

// AadhaarLogCounts are a run's places counted by source, and how many places
// earlier runs found that it no longer does.
func (s *Store) AadhaarLogCounts(r *AadhaarLogRun) ([]AadhaarLogSourceCount, int, error) {
	rows, err := s.db.Query(`SELECT source, count(DISTINCT entry), count(*), min(at) FROM aadhaar_log_places
		WHERE branch=? AND last_run=? GROUP BY source`, r.Branch, r.ID)
	if err != nil {
		return nil, 0, err
	}
	by := map[string]AadhaarLogSourceCount{}
	for rows.Next() {
		var c AadhaarLogSourceCount
		var at int64
		if err := rows.Scan(&c.Source, &c.Entries, &c.Places, &at); err != nil {
			rows.Close()
			return nil, 0, err
		}
		t := time.UnixMilli(at).UTC()
		c.Since = &t
		by[c.Source] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	out := []AadhaarLogSourceCount{}
	for _, src := range AadhaarLogSources {
		if c, ok := by[src]; ok {
			out = append(out, c)
		}
	}
	var gone int
	err = s.db.QueryRow(`SELECT count(*) FROM aadhaar_log_places p WHERE p.branch=? AND `+aadhaarLogGone,
		r.Branch, r.ID, r.ID).Scan(&gone)
	return out, gone, err
}

// AadhaarLogFilter narrows a list of log places.
type AadhaarLogFilter struct {
	Person int    // one person's places; 0 for every person
	Source string // one source; "" for every one
	Gone   bool   // places no longer found, rather than those found now
	Limit  int
}

// AadhaarLogPlaces lists a run's log places, or those it no longer found.
func (s *Store) AadhaarLogPlaces(r *AadhaarLogRun, f AadhaarLogFilter) ([]AadhaarLogPlace, error) {
	cond, args := "p.branch=? AND p.last_run=?", []any{r.Branch, r.ID}
	if f.Gone {
		cond, args = "p.branch=? AND "+aadhaarLogGone, []any{r.Branch, r.ID, r.ID}
	}
	if f.Person != 0 {
		cond += " AND p.last_run=? AND p.person=?"
		args = append(args, r.ID, f.Person)
	}
	if f.Source != "" {
		cond += " AND p.source=?"
		args = append(args, f.Source)
	}
	if f.Limit <= 0 {
		f.Limit = 200
	}
	args = append(args, r.ID, f.Limit)
	rows, err := s.db.Query(`SELECT p.id, p.source, p.entry, p.field, p.last4, p.actor, p.at,
			p.person, p.first_seen, p.last_seen, p.last_run
		FROM aadhaar_log_places p WHERE `+cond+`
		ORDER BY CASE WHEN p.last_run = ? THEN p.person ELSE 0 END, p.source, p.entry, p.id LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AadhaarLogPlace{}
	for rows.Next() {
		var p AadhaarLogPlace
		var at, first, last, lastRun int64
		if err := rows.Scan(&p.ID, &p.Source, &p.Entry, &p.Field, &p.Last4, &p.Actor, &at,
			&p.Person, &first, &last, &lastRun); err != nil {
			return nil, err
		}
		p.At, p.FirstSeen, p.LastSeen = time.UnixMilli(at).UTC(), time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		if lastRun != r.ID {
			p.Person, p.Gone = 0, true
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ValidAadhaarLogSource reports whether s names a source.
func ValidAadhaarLogSource(s string) bool {
	for _, x := range AadhaarLogSources {
		if strings.EqualFold(s, x) {
			return true
		}
	}
	return false
}
