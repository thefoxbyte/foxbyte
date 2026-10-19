// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Query history (points 8.1 and 8.3): the SQL each person ran, so they can find
// it again. What it is for decides what it keeps:
//
//   - The statement, the branch, when, how long, how many rows and whether it
//     worked. Never a result: a row of somebody's data is not history, and a
//     copy of it here would outlive every control on the table it came from.
//   - Your own only. The console and the API read the caller's history and
//     nothing else, admins included. A person's history can be listed and
//     deleted for them only by whoever runs the machine (`fox history --user`,
//     `fox history purge --user`), for a request about their own data, and
//     that is recorded in the security log.
//   - For a while. 90 days by default (`fox history retention`); older entries
//     are not shown and are deleted. At most 10,000 entries per person, the
//     oldest going first, so the file that also holds everyone's sessions stays
//     small.
//   - Optional. The install can turn it off (`fox history off`), and anyone can
//     turn their own off; an entry that is not recorded is not recorded
//     anywhere.
//
// It is not an audit log, and must not be read as one: a client can ask for a
// query not to be kept (the console's own reads of a table do), the gateway's
// connections (psql, an application) pass through as bytes and are never seen
// here, and anyone can delete their own. The security log and the Blackbox are
// the records that cannot be edited.
//
// It lives in the install's own store, beside the security log, and not in a
// branch: a branch is a copy of main, so a table there would be copied into
// every branch made from it, and any role that can read the database could
// read everybody's SQL. Nor is it carried to a second node (shared.go): it is
// an append-only log, and the SQL people type is the last thing to replicate.

// DefaultHistoryRetentionDays is how long history is kept unless the install
// says otherwise.
const DefaultHistoryRetentionDays = 90

const (
	maxHistorySQL      = 64 << 10 // longer statements are kept cut, and marked so
	maxHistoryError    = 500
	maxHistoryPerActor = 10000
	historyTrimEvery   = time.Minute
)

const historySchema = `
CREATE TABLE IF NOT EXISTS query_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL, branch TEXT NOT NULL,
  source TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'query',
  sql TEXT NOT NULL, truncated INTEGER NOT NULL DEFAULT 0,
  at INTEGER NOT NULL, duration_ms INTEGER NOT NULL DEFAULT 0,
  rows INTEGER NOT NULL DEFAULT 0, ok INTEGER NOT NULL, error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS query_history_actor ON query_history(actor, id);
CREATE INDEX IF NOT EXISTS query_history_at ON query_history(at);
CREATE TABLE IF NOT EXISTS history_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS history_optout (actor TEXT PRIMARY KEY, since INTEGER NOT NULL);`

// HistoryEntry is one statement someone ran.
type HistoryEntry struct {
	ID     int64  `json:"id"`
	Actor  string `json:"actor"`
	Branch string `json:"branch"`
	// Source is where it was run: console, api or cli.
	Source string `json:"source"`
	// Kind is query, or export for a whole result exported (point 1.3).
	Kind      string `json:"kind"`
	SQL       string `json:"sql"`
	Truncated bool   `json:"truncated,omitempty"`
	// At is when it started, in Unix milliseconds.
	At         int64  `json:"at"`
	DurationMS int64  `json:"duration_ms"`
	Rows       int64  `json:"rows"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

// HistorySettings is the install's choice.
type HistorySettings struct {
	Enabled       bool `json:"enabled"`
	RetentionDays int  `json:"retention_days"`
}

// HistoryQuery narrows a listing.
type HistoryQuery struct {
	Branch string
	Limit  int
	Before int64 // entries older than this id, for the next page
}

// HistorySettings returns the install's settings, defaults filled in.
func (s *Store) HistorySettings() (HistorySettings, error) {
	h := HistorySettings{Enabled: true, RetentionDays: DefaultHistoryRetentionDays}
	rows, err := s.db.Query(`SELECT key, value FROM history_settings`)
	if err != nil {
		return h, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return h, err
		}
		switch k {
		case "enabled":
			h.Enabled = v != "0"
		case "retention_days":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				h.RetentionDays = n
			}
		}
	}
	return h, rows.Err()
}

func (s *Store) setHistorySetting(k, v string) error {
	return retryBusy(func() error {
		_, err := s.db.Exec(`INSERT INTO history_settings(key, value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, v)
		return err
	})
}

// SetHistoryEnabled turns recording on or off for the whole install. Off stops
// new entries; those already kept still expire as usual.
func (s *Store) SetHistoryEnabled(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return s.setHistorySetting("enabled", v)
}

// SetHistoryRetention sets how many days history is kept, from 1 to 3650.
// Shortening it deletes what is now too old at once, rather than leaving it
// for the next trim.
func (s *Store) SetHistoryRetention(days int) error {
	if days < 1 || days > 3650 {
		return fmt.Errorf("retention must be 1 to 3650 days, not %d", days)
	}
	if err := s.setHistorySetting("retention_days", strconv.Itoa(days)); err != nil {
		return err
	}
	_, err := s.TrimHistory()
	return err
}

// HistoryOptedOut reports whether a person has turned their own history off.
func (s *Store) HistoryOptedOut(actor string) bool {
	var since int64
	return s.db.QueryRow(`SELECT since FROM history_optout WHERE actor=?`, actor).Scan(&since) == nil
}

// SetHistoryOptOut turns a person's own history off (out) or back on. Turning
// it off keeps what was recorded until they delete it or it expires.
func (s *Store) SetHistoryOptOut(actor string, out bool) error {
	return retryBusy(func() error {
		var err error
		if out {
			_, err = s.db.Exec(`INSERT INTO history_optout(actor, since) VALUES(?,?) ON CONFLICT(actor) DO NOTHING`,
				actor, time.Now().Unix())
		} else {
			_, err = s.db.Exec(`DELETE FROM history_optout WHERE actor=?`, actor)
		}
		return err
	})
}

// RecordQuery keeps one statement, unless the install or the person has turned
// history off. It reports whether it was kept.
func (s *Store) RecordQuery(e HistoryEntry) (bool, error) {
	if e.Actor == "" || e.Branch == "" || strings.TrimSpace(e.SQL) == "" {
		return false, errors.New("a history entry needs who, which branch and the SQL")
	}
	set, err := s.HistorySettings()
	if err != nil {
		return false, err
	}
	if !set.Enabled || s.HistoryOptedOut(e.Actor) {
		return false, nil
	}
	if e.At == 0 {
		e.At = time.Now().UnixMilli()
	}
	if e.Kind == "" {
		e.Kind = "query"
	}
	e.SQL, e.Truncated = cutText(e.SQL, maxHistorySQL)
	e.Error, _ = cutText(e.Error, maxHistoryError)
	err = retryBusy(func() error {
		if _, err := s.db.Exec(`INSERT INTO query_history
			(actor, branch, source, kind, sql, truncated, at, duration_ms, rows, ok, error)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			e.Actor, e.Branch, e.Source, e.Kind, e.SQL, boolInt(e.Truncated), e.At,
			e.DurationMS, e.Rows, boolInt(e.OK), e.Error); err != nil {
			return err
		}
		// The per-person cap: everything past the newest maxHistoryPerActor.
		// The subquery is empty until there are that many, and then this is
		// one indexed delete.
		_, err := s.db.Exec(`DELETE FROM query_history WHERE actor=? AND id <=
			(SELECT id FROM query_history WHERE actor=? ORDER BY id DESC LIMIT 1 OFFSET ?)`,
			e.Actor, e.Actor, maxHistoryPerActor)
		return err
	})
	if err != nil {
		return false, err
	}
	// Retention, at most once a minute per process rather than per statement.
	if last := s.historyTrimmed.Load(); time.Since(time.Unix(0, last)) > historyTrimEvery {
		s.historyTrimmed.Store(time.Now().UnixNano())
		_, _ = s.TrimHistory()
	}
	return true, nil
}

// TrimHistory deletes what is older than the retention, and reports how many.
func (s *Store) TrimHistory() (int64, error) {
	set, err := s.HistorySettings()
	if err != nil {
		return 0, err
	}
	var n int64
	err = retryBusy(func() error {
		res, err := s.db.Exec(`DELETE FROM query_history WHERE at < ?`, retentionCutoff(set))
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// retentionCutoff is the oldest moment still kept, in Unix milliseconds.
func retentionCutoff(set HistorySettings) int64 {
	return time.Now().Add(-time.Duration(set.RetentionDays) * 24 * time.Hour).UnixMilli()
}

// History lists a person's entries, newest first. Entries past the retention
// are never returned, even before the trim has deleted them.
func (s *Store) History(actor string, q HistoryQuery) ([]HistoryEntry, error) {
	set, err := s.HistorySettings()
	if err != nil {
		return nil, err
	}
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	where, args := `actor=? AND at>=?`, []any{actor, retentionCutoff(set)}
	if q.Branch != "" {
		where += ` AND branch=?`
		args = append(args, q.Branch)
	}
	if q.Before > 0 {
		where += ` AND id<?`
		args = append(args, q.Before)
	}
	rows, err := s.db.Query(`SELECT id, actor, branch, source, kind, sql, truncated, at, duration_ms, rows, ok, error
		FROM query_history WHERE `+where+` ORDER BY id DESC LIMIT ?`, append(args, q.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HistoryEntry{}
	for rows.Next() {
		var e HistoryEntry
		var trunc, ok int
		if err := rows.Scan(&e.ID, &e.Actor, &e.Branch, &e.Source, &e.Kind, &e.SQL, &trunc, &e.At,
			&e.DurationMS, &e.Rows, &ok, &e.Error); err != nil {
			return nil, err
		}
		e.Truncated, e.OK = trunc != 0, ok != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// HistoryCount is how many entries a person has, within the retention.
func (s *Store) HistoryCount(actor string) (int, error) {
	set, err := s.HistorySettings()
	if err != nil {
		return 0, err
	}
	var n int
	err = s.db.QueryRow(`SELECT count(*) FROM query_history WHERE actor=? AND at>=?`,
		actor, retentionCutoff(set)).Scan(&n)
	return n, err
}

// HistoryActors lists who has history, with how many entries each, for the
// person running the machine to find someone's (`fox history --people`).
func (s *Store) HistoryActors() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT actor, count(*) FROM query_history GROUP BY actor ORDER BY actor`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var a string
		var n int
		if err := rows.Scan(&a, &n); err != nil {
			return nil, err
		}
		out[a] = n
	}
	return out, rows.Err()
}

// PurgeHistory deletes all of a person's history, and reports how much.
func (s *Store) PurgeHistory(actor string) (int64, error) {
	return s.deleteHistory(`DELETE FROM query_history WHERE actor=?`, actor)
}

// PurgeAllHistory deletes everyone's history.
func (s *Store) PurgeAllHistory() (int64, error) {
	return s.deleteHistory(`DELETE FROM query_history`)
}

// DeleteHistoryEntry deletes one of a person's own entries. It reports false
// for an entry that is not theirs, so one person cannot learn which ids exist.
func (s *Store) DeleteHistoryEntry(actor string, id int64) (bool, error) {
	n, err := s.deleteHistory(`DELETE FROM query_history WHERE actor=? AND id=?`, actor, id)
	return n > 0, err
}

func (s *Store) deleteHistory(q string, args ...any) (int64, error) {
	var n int64
	err := retryBusy(func() error {
		res, err := s.db.Exec(q, args...)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// cutText keeps at most max bytes of s, on a character boundary.
func cutText(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max], true
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
