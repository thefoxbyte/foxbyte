// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"fmt"
	"time"
)

// Readings of what a warm branch has cost, kept so the question can be asked
// about a period rather than only about this instant.
//
// A single reading of pg_stat_database says almost nothing: the counters are
// cumulative since the statistics were last reset, which is usually never. Two
// readings say everything — how much work happened between them, and over how
// long. So the engine keeps a series.
//
// It lives in the install's own store, beside pipelines and change requests,
// for the dull reason that the hard parts are already solved there: one file,
// opened by three services at once, with SQLITE_BUSY retried and the
// concurrent-first-open race already fixed. A second database would reopen all
// of it.
//
// Not in the branch's own bb schema, deliberately. A branch is a ZFS clone, so
// a table there would be copied into every branch made from it, and a new
// branch would be born claiming to have been warm for a fortnight.

// ActivitySample is one reading for one branch.
type ActivitySample struct {
	Branch string `json:"branch"`
	At     int64  `json:"at"`
	// WarmSince is when the container that served this reading started, or 0
	// when the branch was not running. A change in this value between two
	// samples means the branch was suspended and resumed in between, so the
	// counters may have restarted too.
	WarmSince    int64 `json:"warm_since"`
	Transactions int64 `json:"transactions"`
	RowsReturned int64 `json:"rows_returned"`
	// StatsReset is pg_stat_database's own reset time, carried so a meter can
	// tell a counter that went backwards from one that was zeroed.
	StatsReset  int64 `json:"stats_reset,omitempty"`
	Subscribers int   `json:"subscribers"`
	// Events is how many change events the feed has delivered on this branch
	// since the control plane started. It restarts with the process, which is
	// why it is recorded alongside a timestamp rather than trusted as a total.
	Events  int64 `json:"events"`
	WALHeld int64 `json:"wal_held"`
}

// RecordActivity stores one reading.
func (s *Store) RecordActivity(a ActivitySample) error {
	if a.Branch == "" {
		return fmt.Errorf("a reading needs a branch")
	}
	if a.At == 0 {
		a.At = time.Now().Unix()
	}
	return retryBusy(func() error {
		_, err := s.db.Exec(`INSERT INTO realtime_activity
			(branch,at,warm_since,transactions,rows_returned,stats_reset,subscribers,events,wal_held)
			VALUES(?,?,?,?,?,?,?,?,?)`,
			a.Branch, a.At, a.WarmSince, a.Transactions, a.RowsReturned, a.StatsReset,
			a.Subscribers, a.Events, a.WALHeld)
		return err
	})
}

// ActivitySince returns a branch's readings from at or after `since`, oldest
// first, at most limit of them.
//
// Oldest first because every useful question here is a subtraction between the
// ends of a range, and a caller should not have to reverse a list to do it.
func (s *Store) ActivitySince(branchName string, since int64, limit int) ([]ActivitySample, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	rows, err := s.db.Query(`SELECT branch,at,warm_since,transactions,rows_returned,stats_reset,subscribers,events,wal_held
		FROM realtime_activity WHERE branch=? AND at>=? ORDER BY at LIMIT ?`,
		branchName, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActivitySample{}
	for rows.Next() {
		var a ActivitySample
		if err := rows.Scan(&a.Branch, &a.At, &a.WarmSince, &a.Transactions, &a.RowsReturned,
			&a.StatsReset, &a.Subscribers, &a.Events, &a.WALHeld); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// TrimActivity deletes readings older than `before`, and reports how many went.
//
// Kept bounded on purpose: this table grows on a timer whether anybody reads it
// or not, and an install left running for a year should not be storing a year
// of five-minute samples in the file that also holds everyone's sessions.
func (s *Store) TrimActivity(before int64) (int64, error) {
	var n int64
	err := retryBusy(func() error {
		res, err := s.db.Exec(`DELETE FROM realtime_activity WHERE at < ?`, before)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// ForgetActivity removes a branch's readings, for when the branch goes.
func (s *Store) ForgetActivity(branchName string) error {
	return retryBusy(func() error {
		_, err := s.db.Exec(`DELETE FROM realtime_activity WHERE branch=?`, branchName)
		return err
	})
}
