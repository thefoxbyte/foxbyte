// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"errors"
	"time"
)

// Restores and erasure requests (F4, Gate 1 step 4; design, section 12). A
// restore to a point before an applied erasure would bring the person back,
// so it is refused unless an admin records a decision; the erasure is then
// applied again, by the row keys the request kept, before the copy opens.
// Each decision is a row here, one per request it touches, so the request
// shows every restore that touched it, who decided, why, and how the
// re-apply went. Like the request, it keeps no value.

const erasureRestoreSchema = `
CREATE TABLE IF NOT EXISTS erasure_restores (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id INTEGER NOT NULL,
  door       TEXT NOT NULL,
  source     TEXT NOT NULL,
  target     TEXT NOT NULL,
  point      TEXT NOT NULL,
  by         TEXT NOT NULL,
  reason     TEXT NOT NULL,
  at         INTEGER NOT NULL,
  state      TEXT NOT NULL CHECK (state IN ('reapplying', 'done', 'failed')),
  detail     TEXT NOT NULL DEFAULT '{}',
  error      TEXT NOT NULL DEFAULT '',
  done_at    INTEGER
);
CREATE INDEX IF NOT EXISTS erasure_restores_request ON erasure_restores(request_id, id);
`

// The states of a restore's re-apply.
const (
	RestoreReapplying = "reapplying"
	RestoreDone       = "done"
	RestoreFailed     = "failed"
)

// ErasureRestore is one restore that would have undone a request, as the
// admin decided it. Door is the command (restore, branch-before, backup
// restore, pg rollback); Source the branch whose earlier copy it is; Target
// where the copy went (the restore copy, or a branch); Point the moment it
// is a copy of, as the door names it.
type ErasureRestore struct {
	ID        int64      `json:"id"`
	RequestID int64      `json:"request"`
	Door      string     `json:"door"`
	Source    string     `json:"source"`
	Target    string     `json:"target"`
	Point     string     `json:"point"`
	By        string     `json:"by"`
	Reason    string     `json:"reason"`
	At        time.Time  `json:"at"`
	State     string     `json:"state"`
	Detail    string     `json:"detail"` // the engine's JSON: what the re-apply did
	Error     string     `json:"error,omitempty"`
	DoneAt    *time.Time `json:"done,omitempty"`
}

// AddErasureRestore records an admin's decision to restore past a request,
// before the copy is made.
func (s *Store) AddErasureRestore(r ErasureRestore) (int64, error) {
	if r.RequestID <= 0 || r.Door == "" || r.Target == "" || r.By == "" || r.Reason == "" {
		return 0, errors.New("a restore past an erasure needs its request, door, target, who decided and why")
	}
	var id int64
	err := retryBusy(func() error {
		res, err := s.db.Exec(`INSERT INTO erasure_restores (request_id, door, source, target, point, by, reason, at, state)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.RequestID, r.Door, r.Source, r.Target, r.Point, r.By, r.Reason, time.Now().UnixMilli(), RestoreReapplying)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// FinishErasureRestore records how a re-apply ended: done, with what it did,
// or failed, with why.
func (s *Store) FinishErasureRestore(id int64, state, detail, errText string) error {
	if state != RestoreDone && state != RestoreFailed {
		return errors.New("a restore's re-apply ends done or failed")
	}
	if detail == "" {
		detail = "{}"
	}
	return retryBusy(func() error {
		_, err := s.db.Exec(`UPDATE erasure_restores SET state = ?, detail = ?, error = ?, done_at = ? WHERE id = ?`,
			state, detail, errText, time.Now().UnixMilli(), id)
		return err
	})
}

// ErasureRestores lists the restores that touched a request, oldest first.
func (s *Store) ErasureRestores(requestID int64) ([]ErasureRestore, error) {
	rows, err := s.db.Query(`SELECT id, request_id, door, source, target, point, by, reason, at, state, detail, error, done_at
		FROM erasure_restores WHERE request_id = ? ORDER BY id`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ErasureRestore{}
	for rows.Next() {
		var r ErasureRestore
		var at int64
		var done sql.NullInt64
		if err := rows.Scan(&r.ID, &r.RequestID, &r.Door, &r.Source, &r.Target, &r.Point, &r.By, &r.Reason, &at,
			&r.State, &r.Detail, &r.Error, &done); err != nil {
			return nil, err
		}
		r.At = time.UnixMilli(at).UTC()
		if done.Valid {
			t := time.UnixMilli(done.Int64).UTC()
			r.DoneAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
