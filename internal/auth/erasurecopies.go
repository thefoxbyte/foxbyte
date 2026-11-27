// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"strings"
)

// What an erasure request (F4, Gate 1 step 3b; design, section 9) finds and
// removes of a person in this store, by value: query history, for every
// actor (decision 8); saved queries, listed for their owners and never
// deleted; decided change requests' text; and the Aadhaar log report's places
// in the entries an erasure removed. A value is matched case-blind, as the
// Blackbox's redaction matches it.

// holdingSQL is a WHERE clause true when any of cols holds any of forms,
// case-blind, and its arguments.
func holdingSQL(cols []string, forms []string) (string, []any) {
	var ors []string
	var args []any
	for _, f := range forms {
		if len([]rune(f)) < 4 {
			continue
		}
		for _, c := range cols {
			ors = append(ors, "instr(lower("+c+"), lower(?)) > 0")
			args = append(args, f)
		}
	}
	if len(ors) == 0 {
		return "0", nil
	}
	return "(" + strings.Join(ors, " OR ") + ")", args
}

// HistoryHolding counts the query history entries, any actor's, whose
// statement or error holds one of forms.
func (s *Store) HistoryHolding(forms []string) (int, error) {
	where, args := holdingSQL([]string{"sql", "error"}, forms)
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM query_history WHERE `+where, args...).Scan(&n)
	return n, err
}

// DeleteHistoryHolding deletes them, and returns their ids.
func (s *Store) DeleteHistoryHolding(forms []string) ([]int64, error) {
	where, args := holdingSQL([]string{"sql", "error"}, forms)
	var ids []int64
	err := retryBusy(func() error {
		ids = nil
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		rows, err := tx.Query(`SELECT id FROM query_history WHERE `+where, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM query_history WHERE `+where, args...); err != nil {
			return err
		}
		return tx.Commit()
	})
	return ids, err
}

// SavedHeld is a saved query holding one of the values: listed for its
// owner, who decides; never deleted by an erasure (decision 8).
type SavedHeld struct {
	ID    int64  `json:"id"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// SavedHolding lists the saved queries whose name or text holds one of forms.
func (s *Store) SavedHolding(forms []string) ([]SavedHeld, error) {
	where, args := holdingSQL([]string{"name", "sql"}, forms)
	rows, err := s.db.Query(`SELECT id, actor, name FROM saved_queries WHERE `+where+` ORDER BY actor, name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SavedHeld{}
	for rows.Next() {
		var h SavedHeld
		if err := rows.Scan(&h.ID, &h.Owner, &h.Name); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RewriteChangeRequestText replaces a decided request's entries and note, as
// an erasure rewrites them. An open request is never changed here: what it
// shows is what its approver approves.
func (s *Store) RewriteChangeRequestText(id int64, entries, note string) error {
	_, err := s.erasureUpdateRequest(id, entries, note)
	return err
}

func (s *Store) erasureUpdateRequest(id int64, entries, note string) (int64, error) {
	var n int64
	err := retryBusy(func() error {
		res, err := s.db.Exec(`UPDATE change_requests SET entries = ?, note = ? WHERE id = ? AND status <> ?`, entries, note, id, RequestOpen)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n, err
}

// DeleteAadhaarLogPlaces removes the Aadhaar log report's places in entries an
// erasure removed: history entries and audit records by id, which are unique
// in this store, and a branch's Blackbox entries.
func (s *Store) DeleteAadhaarLogPlaces(source, branch string, entries []int64) (int64, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(entries)), ",")
	args := []any{source}
	q := `DELETE FROM aadhaar_log_places WHERE source = ?`
	if branch != "" {
		q += ` AND branch = ?`
		args = append(args, branch)
	}
	q += ` AND entry IN (` + marks + `)`
	for _, e := range entries {
		args = append(args, e)
	}
	var n int64
	err := retryBusy(func() error {
		res, err := s.db.Exec(q, args...)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n, err
}

// AllChangeRequests is every request, oldest first, with no limit: an erasure
// must read them all, where the console's list shows the newest 500.
func (s *Store) AllChangeRequests() ([]ChangeRequest, error) {
	rows, err := s.db.Query(`SELECT ` + requestColumns + requestFrom + ` ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChangeRequest{}
	for rows.Next() {
		c, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
