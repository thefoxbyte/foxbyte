// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"time"
)

// Reads for the access review report (point 4.8): every key with its owner,
// who owns which branch, and when each person last did anything. Nothing here
// returns a secret: a key is its id, name and prefix, never its hash.

// KeyRecord is one API key with the account it belongs to.
type KeyRecord struct {
	ID       string
	Name     string
	Prefix   string
	Scope    string
	Kind     string
	UserID   int64
	Email    string
	Created  time.Time
	LastUsed time.Time // zero if never used
}

// AllKeys lists every API key on the install, oldest first.
func (s *Store) AllKeys() ([]KeyRecord, error) {
	rows, err := s.db.Query(`SELECT k.id, k.name, k.prefix, k.scope, k.kind, k.user_id, coalesce(u.email, ''), k.created, k.last_used
		FROM api_keys k LEFT JOIN users u ON u.id = k.user_id ORDER BY k.created, k.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyRecord
	for rows.Next() {
		var k KeyRecord
		var created int64
		var last sql.NullInt64
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scope, &k.Kind, &k.UserID, &k.Email, &created, &last); err != nil {
			return nil, err
		}
		k.Created = time.Unix(created, 0).UTC()
		if last.Valid && last.Int64 > 0 {
			k.LastUsed = time.Unix(last.Int64, 0).UTC()
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// BranchOwners maps each owned branch to the account that owns it.
func (s *Store) BranchOwners() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT branch, user_id FROM branch_owners`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var b string
		var id int64
		if err := rows.Scan(&b, &id); err != nil {
			return nil, err
		}
		out[b] = id
	}
	return out, rows.Err()
}

// LastSignIns is each person's most recent sign-in to the console, from the
// security log. By id rather than by time: the log is append-only, so the
// highest id is the newest, and its times are text that does not sort as times
// (see HasRecentEvent).
func (s *Store) LastSignIns() (map[string]time.Time, error) {
	rows, err := s.db.Query(`SELECT actor, at FROM security_events
		WHERE id IN (SELECT max(id) FROM security_events WHERE kind = ? AND actor <> '' GROUP BY actor)`, EvLoginOK)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var actor, at string
		if err := rows.Scan(&actor, &at); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, at); err == nil {
			out[actor] = t.UTC()
		}
	}
	return out, rows.Err()
}

// LastQueries is when each person last ran SQL that query history kept: the
// console, the API, `fox sql`. Empty for someone who turned history off, which
// is why it is one signal among several.
func (s *Store) LastQueries() (map[string]time.Time, error) {
	rows, err := s.db.Query(`SELECT actor, max(at) FROM query_history GROUP BY actor`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var actor string
		var ms int64
		if err := rows.Scan(&actor, &ms); err != nil {
			return nil, err
		}
		out[actor] = time.UnixMilli(ms).UTC()
	}
	return out, rows.Err()
}
