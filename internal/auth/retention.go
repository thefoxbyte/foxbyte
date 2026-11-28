// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"errors"
	"time"
)

// Retention acted on (point 11.3; docs/dpdp-inventory.md). A table's period
// is its DPDP inventory entry's, kept in its branch; what the install adds
// is here: which column dates each row's period, whether an admin armed the
// table (only an armed table is erased from; decided 28 Nov 2026), and each
// notice sent before an erasure (Rule 8(2)). A notice names a row by its key,
// never by a value.

const retentionSchema = `
CREATE TABLE IF NOT EXISTS retention_tables (
  schema_name TEXT NOT NULL,
  table_name  TEXT NOT NULL,
  date_column TEXT NOT NULL DEFAULT '',
  armed       INTEGER NOT NULL DEFAULT 0,
  by          TEXT NOT NULL DEFAULT '',
  at          INTEGER NOT NULL,
  reason      TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (schema_name, table_name)
);
CREATE TABLE IF NOT EXISTS retention_notices (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_name TEXT NOT NULL,
  table_name  TEXT NOT NULL,
  row_key     TEXT NOT NULL,
  since       INTEGER NOT NULL,
  noticed     INTEGER NOT NULL,
  erase_after INTEGER NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('noticed', 'erased', 'renewed', 'failed')),
  request_id  INTEGER,
  error       TEXT NOT NULL DEFAULT '',
  updated     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS retention_notices_open ON retention_notices(schema_name, table_name, state);
CREATE UNIQUE INDEX IF NOT EXISTS retention_notices_one_open ON retention_notices(schema_name, table_name, row_key) WHERE state = 'noticed';
`

// The states of a notice.
const (
	NoticeSent    = "noticed" // sent; the row is erased once its time is up, if still due
	NoticeErased  = "erased"
	NoticeRenewed = "renewed" // no longer due when its time came: the person came back
	NoticeFailed  = "failed"  // the erasure failed; the row is noticed again
)

// RetentionTable is a table retention is set up for.
type RetentionTable struct {
	Schema string    `json:"schema"`
	Table  string    `json:"table"`
	Column string    `json:"column"` // the date each row's period runs from; "" for none yet
	Armed  bool      `json:"armed"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Reason string    `json:"reason,omitempty"`
}

// RetentionNotice is one notice sent before an erasure.
type RetentionNotice struct {
	ID         int64     `json:"id"`
	Schema     string    `json:"schema"`
	Table      string    `json:"table"`
	Key        string    `json:"key"`   // the row's key, a JSON array
	Since      time.Time `json:"since"` // the date its period ran from
	Noticed    time.Time `json:"noticed"`
	EraseAfter time.Time `json:"eraseAfter"`
	State      string    `json:"state"`
	Request    int64     `json:"request,omitempty"` // the erasure request that erased it
	Error      string    `json:"error,omitempty"`
	Updated    time.Time `json:"updated"`
}

// SetRetentionTable records a table's date column, or its arming, or both:
// an empty column keeps the one recorded.
func (s *Store) SetRetentionTable(t RetentionTable) error {
	if t.Schema == "" || t.Table == "" || t.By == "" {
		return errors.New("a retention table needs its schema, table and who set it")
	}
	return retryBusy(func() error {
		_, err := s.db.Exec(`INSERT INTO retention_tables (schema_name, table_name, date_column, armed, by, at, reason) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (schema_name, table_name) DO UPDATE SET
			  date_column = CASE WHEN excluded.date_column = '' THEN retention_tables.date_column ELSE excluded.date_column END,
			  armed = excluded.armed, by = excluded.by, at = excluded.at, reason = excluded.reason`,
			t.Schema, t.Table, t.Column, boolInt(t.Armed), t.By, time.Now().UnixMilli(), t.Reason)
		return err
	})
}

// RetentionTables lists the tables retention is set up for.
func (s *Store) RetentionTables() ([]RetentionTable, error) {
	rows, err := s.db.Query(`SELECT schema_name, table_name, date_column, armed, by, at, reason FROM retention_tables ORDER BY schema_name, table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RetentionTable{}
	for rows.Next() {
		var t RetentionTable
		var armed int
		var at int64
		if err := rows.Scan(&t.Schema, &t.Table, &t.Column, &armed, &t.By, &at, &t.Reason); err != nil {
			return nil, err
		}
		t.Armed, t.At = armed == 1, time.UnixMilli(at).UTC()
		out = append(out, t)
	}
	return out, rows.Err()
}

// AddRetentionNotice records a notice sent. A row with a notice open keeps
// it: the second is refused by the index, and not an error.
func (s *Store) AddRetentionNotice(n RetentionNotice) (bool, error) {
	added := false
	err := retryBusy(func() error {
		res, err := s.db.Exec(`INSERT INTO retention_notices (schema_name, table_name, row_key, since, noticed, erase_after, state, updated)
			VALUES (?, ?, ?, ?, ?, ?, 'noticed', ?) ON CONFLICT DO NOTHING`,
			n.Schema, n.Table, n.Key, n.Since.UnixMilli(), n.Noticed.UnixMilli(), n.EraseAfter.UnixMilli(), time.Now().UnixMilli())
		if err != nil {
			return err
		}
		k, _ := res.RowsAffected()
		added = k == 1
		return nil
	})
	return added, err
}

// CloseRetentionNotice ends an open notice: erased (by a request), renewed,
// or failed (with why).
func (s *Store) CloseRetentionNotice(id int64, state string, request int64, errText string) error {
	if state != NoticeErased && state != NoticeRenewed && state != NoticeFailed {
		return errors.New("a notice closes erased, renewed or failed")
	}
	return retryBusy(func() error {
		var req any
		if request > 0 {
			req = request
		}
		_, err := s.db.Exec(`UPDATE retention_notices SET state = ?, request_id = ?, error = ?, updated = ? WHERE id = ? AND state = 'noticed'`,
			state, req, errText, time.Now().UnixMilli(), id)
		return err
	})
}

// RetentionNotices lists the notices of a table ("" for every table), the
// newest first; open only lists the ones still to be acted on.
func (s *Store) RetentionNotices(schema, table string, open bool, limit int) ([]RetentionNotice, error) {
	if limit <= 0 {
		limit = 500
	}
	q := `SELECT id, schema_name, table_name, row_key, since, noticed, erase_after, state, request_id, error, updated FROM retention_notices WHERE 1 = 1`
	var args []any
	if table != "" {
		q += ` AND schema_name = ? AND table_name = ?`
		args = append(args, schema, table)
	}
	if open {
		q += ` AND state = 'noticed'`
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RetentionNotice{}
	for rows.Next() {
		var n RetentionNotice
		var since, noticed, after, updated int64
		var req sql.NullInt64
		if err := rows.Scan(&n.ID, &n.Schema, &n.Table, &n.Key, &since, &noticed, &after, &n.State, &req, &n.Error, &updated); err != nil {
			return nil, err
		}
		n.Since, n.Noticed, n.EraseAfter, n.Updated = time.UnixMilli(since).UTC(), time.UnixMilli(noticed).UTC(), time.UnixMilli(after).UTC(), time.UnixMilli(updated).UTC()
		n.Request = req.Int64
		out = append(out, n)
	}
	return out, rows.Err()
}
