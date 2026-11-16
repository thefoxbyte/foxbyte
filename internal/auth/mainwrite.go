// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Who may change main (audit LIVE-1).
//
// Every account could use main, and Postgres let every account's role write
// there: insert, update, delete and create tables. Only DROP and TRUNCATE were
// stopped, by the Blackbox guardrail. main is the shared copy everybody
// branches from, so one ordinary account could change what all the others see.
//
// So an install has a "main write" mode:
//
//   - "all": every account may change main, as before. An install that already
//     had accounts when this code first ran is recorded as this, so an upgrade
//     takes nobody's access away until an admin decides to.
//   - "granted": only admins, and accounts an admin has granted write, may
//     change main. Everybody else still reads it. A new install starts here.
//
// The mode and the grants live here, in the accounts store, because every
// process that logs somebody in to main reads them. The rights themselves are
// enforced by Postgres (internal/branch/mainwrite.go): this is what decides
// them, not what enforces them.
//
// Two tables of their own rather than columns on users: the HA standby is sent
// users with a fixed set of columns (shared.go), and a new column there would
// make an older node refuse the whole document mid-upgrade. A new table rides
// along as an optional one.

const (
	MainWriteAll     = "all"
	MainWriteGranted = "granted"
)

// ErrMainWriteMode is a mode that is neither.
var ErrMainWriteMode = errors.New(`the main write mode is "all" or "granted"`)

const mainWriteKey = "main_write"

const mainWriteSchema = `
CREATE TABLE IF NOT EXISTS install_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS main_writers (
  user_id INTEGER PRIMARY KEY, granted INTEGER NOT NULL, granted_by TEXT NOT NULL DEFAULT ''
);`

// migrateMainWrite makes the tables and records the mode the first time this
// code opens a store. Recorded rather than worked out on each read, so the
// answer is stable: counting accounts later would turn an install with none
// into a different install the moment the first one signs up.
//
// It runs inside initSchema's BEGIN IMMEDIATE, so two processes opening a new
// store at once cannot record different modes.
func migrateMainWrite(ctx context.Context, db *sql.Conn) error {
	if _, err := db.ExecContext(ctx, mainWriteSchema); err != nil {
		return err
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM install_settings WHERE key = ?`, mainWriteKey).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	var users int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		return err
	}
	mode := MainWriteGranted
	if users > 0 {
		mode = MainWriteAll // an upgrade: today's behaviour until an admin switches
	}
	_, err := db.ExecContext(ctx, `INSERT INTO install_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING`,
		mainWriteKey, mode)
	return err
}

// MainWriteMode is the install's mode. A store whose row has gone (it can only
// be removed by hand) reads as "granted": the mode that takes nothing from an
// admin and gives nothing to anybody else.
func (s *Store) MainWriteMode() (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM install_settings WHERE key = ?`, mainWriteKey).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return MainWriteGranted, nil
	}
	if err != nil {
		return "", err
	}
	if v != MainWriteAll {
		return MainWriteGranted, nil
	}
	return MainWriteAll, nil
}

// SetMainWriteMode records the mode. The caller applies it to main's roles.
func (s *Store) SetMainWriteMode(mode string) error {
	if mode != MainWriteAll && mode != MainWriteGranted {
		return fmt.Errorf("%w, not %q", ErrMainWriteMode, mode)
	}
	_, err := s.db.Exec(`INSERT INTO install_settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, mainWriteKey, mode)
	return err
}

// MainWriter is an account an admin has granted write on main.
type MainWriter struct {
	UserID    int64     `json:"user_id"`
	Email     string    `json:"email"`
	Granted   time.Time `json:"granted"`
	GrantedBy string    `json:"granted_by"`
}

// GrantMainWrite lets an account change main when the mode is "granted".
// Granting it twice keeps the first grant's time and grantor.
func (s *Store) GrantMainWrite(userID int64, by string) error {
	if _, err := s.userByID(userID); err != nil {
		return errors.New("no such account")
	}
	_, err := s.db.Exec(`INSERT INTO main_writers(user_id, granted, granted_by) VALUES(?, ?, ?)
		ON CONFLICT(user_id) DO NOTHING`, userID, time.Now().Unix(), by)
	return err
}

// RevokeMainWrite takes the grant away, reporting whether there was one.
func (s *Store) RevokeMainWrite(userID int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM main_writers WHERE user_id = ?`, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// HasMainWriteGrant reports whether an admin has granted the account write on
// main. It says nothing about the mode or about admins.
func (s *Store) HasMainWriteGrant(userID int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM main_writers WHERE user_id = ?`, userID).Scan(&n)
	return n > 0, err
}

// MainWriters lists the granted accounts, by email.
func (s *Store) MainWriters() ([]MainWriter, error) {
	rows, err := s.db.Query(`SELECT w.user_id, u.email, w.granted, w.granted_by
		FROM main_writers w JOIN users u ON u.id = w.user_id ORDER BY u.email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MainWriter{}
	for rows.Next() {
		var w MainWriter
		var at int64
		if err := rows.Scan(&w.UserID, &w.Email, &at, &w.GrantedBy); err != nil {
			return nil, err
		}
		w.Granted = time.Unix(at, 0).UTC()
		out = append(out, w)
	}
	return out, rows.Err()
}

// MainWriteState is the mode and the granted accounts' emails (lower case),
// what the engine needs to shape a role on main.
func (s *Store) MainWriteState() (mode string, writers []string, err error) {
	mode, err = s.MainWriteMode()
	if err != nil {
		return "", nil, err
	}
	ws, err := s.MainWriters()
	if err != nil {
		return "", nil, err
	}
	for _, w := range ws {
		writers = append(writers, strings.ToLower(w.Email))
	}
	return mode, writers, nil
}
