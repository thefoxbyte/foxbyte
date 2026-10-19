// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Saved queries (point 8.2): a statement someone chose to keep, under a name.
// The same rules as history (history.go), except the one that defines it:
//
//   - Kept until you delete it. Retention is for what was recorded on its own;
//     a saved query is one somebody asked for, and expiring it would be losing
//     their work.
//   - Your own only, read and changed by you; the machine's operator can delete
//     a person's with their history (`fox history purge --user`), which is
//     what a request to erase someone's data needs.
//   - Kept exactly or not at all: a statement past 64 KB is refused rather than
//     cut, because a saved query that does not run as saved is worse than none.
//   - At most 1,000 per person, names up to 100 characters, unique per person.
//   - Gone with the account, like its history.
//
// Not carried to a second node, like history: it is SQL people typed.

const (
	maxSavedQueries   = 1000
	maxSavedQueryName = 100
)

const savedSchema = `
CREATE TABLE IF NOT EXISTS saved_queries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL, name TEXT NOT NULL, sql TEXT NOT NULL,
  created INTEGER NOT NULL, updated INTEGER NOT NULL,
  UNIQUE (actor, name)
);`

// SavedQuery is one statement kept under a name.
type SavedQuery struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	SQL     string `json:"sql"`
	Created int64  `json:"created"` // Unix milliseconds
	Updated int64  `json:"updated"`
}

// ErrSavedNameTaken means the person already has a saved query by that name.
var ErrSavedNameTaken = errors.New("you already have a saved query with that name")

// ErrNoSavedQuery means no saved query of the person's has that id.
var ErrNoSavedQuery = errors.New("no such saved query")

func checkSaved(name, sql string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", errors.New("a saved query needs a name")
	case utf8.RuneCountInString(name) > maxSavedQueryName:
		return "", fmt.Errorf("a name is at most %d characters", maxSavedQueryName)
	case strings.TrimSpace(sql) == "":
		return "", errors.New("a saved query needs its SQL")
	case len(sql) > maxHistorySQL:
		return "", fmt.Errorf("a saved query is at most %d KB", maxHistorySQL>>10)
	}
	return name, nil
}

func savedErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrSavedNameTaken
	}
	return err
}

// SaveQuery keeps sql under name for a person.
func (s *Store) SaveQuery(actor, name, sql string) (SavedQuery, error) {
	name, err := checkSaved(name, sql)
	if err != nil {
		return SavedQuery{}, err
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM saved_queries WHERE actor=?`, actor).Scan(&n); err != nil {
		return SavedQuery{}, err
	}
	if n >= maxSavedQueries {
		return SavedQuery{}, fmt.Errorf("you have %d saved queries, the most there can be: delete one first", n)
	}
	now := time.Now().UnixMilli()
	q := SavedQuery{Name: name, SQL: sql, Created: now, Updated: now}
	err = retryBusy(func() error {
		res, err := s.db.Exec(`INSERT INTO saved_queries(actor, name, sql, created, updated) VALUES(?,?,?,?,?)`,
			actor, name, sql, now, now)
		if err != nil {
			return err
		}
		q.ID, err = res.LastInsertId()
		return err
	})
	return q, savedErr(err)
}

// SavedQueries lists a person's saved queries by name, those whose name or SQL
// contains search when it is given.
func (s *Store) SavedQueries(actor, search string) ([]SavedQuery, error) {
	where, args := `actor=?`, []any{actor}
	if search != "" {
		p := likeContains(search)
		where += ` AND (name LIKE ? ESCAPE '\' OR sql LIKE ? ESCAPE '\')`
		args = append(args, p, p)
	}
	rows, err := s.db.Query(`SELECT id, name, sql, created, updated FROM saved_queries WHERE `+where+
		` ORDER BY name COLLATE NOCASE`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SavedQuery{}
	for rows.Next() {
		var q SavedQuery
		if err := rows.Scan(&q.ID, &q.Name, &q.SQL, &q.Created, &q.Updated); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// SavedQueryByName finds one of a person's saved queries by its name.
func (s *Store) SavedQueryByName(actor, name string) (SavedQuery, error) {
	var q SavedQuery
	err := s.db.QueryRow(`SELECT id, name, sql, created, updated FROM saved_queries WHERE actor=? AND name=?`,
		actor, strings.TrimSpace(name)).Scan(&q.ID, &q.Name, &q.SQL, &q.Created, &q.Updated)
	if err != nil {
		return q, ErrNoSavedQuery
	}
	return q, nil
}

// UpdateSavedQuery renames a person's saved query or changes its SQL; an empty
// argument leaves that part as it was.
func (s *Store) UpdateSavedQuery(actor string, id int64, name, sql string) (SavedQuery, error) {
	var q SavedQuery
	if err := s.db.QueryRow(`SELECT id, name, sql, created, updated FROM saved_queries WHERE actor=? AND id=?`,
		actor, id).Scan(&q.ID, &q.Name, &q.SQL, &q.Created, &q.Updated); err != nil {
		return q, ErrNoSavedQuery
	}
	if name != "" {
		q.Name = name
	}
	if sql != "" {
		q.SQL = sql
	}
	var err error
	if q.Name, err = checkSaved(q.Name, q.SQL); err != nil {
		return q, err
	}
	q.Updated = time.Now().UnixMilli()
	err = retryBusy(func() error {
		_, err := s.db.Exec(`UPDATE saved_queries SET name=?, sql=?, updated=? WHERE actor=? AND id=?`,
			q.Name, q.SQL, q.Updated, actor, id)
		return err
	})
	return q, savedErr(err)
}

// DeleteSavedQuery deletes one of a person's saved queries.
func (s *Store) DeleteSavedQuery(actor string, id int64) error {
	n, err := s.deleteHistory(`DELETE FROM saved_queries WHERE actor=? AND id=?`, actor, id)
	if err == nil && n == 0 {
		return ErrNoSavedQuery
	}
	return err
}

// PurgeSavedQueries deletes all of a person's saved queries, and reports how
// many: with their history, for a request to erase their data.
func (s *Store) PurgeSavedQueries(actor string) (int64, error) {
	return s.deleteHistory(`DELETE FROM saved_queries WHERE actor=?`, actor)
}
