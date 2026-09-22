// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---- account lifecycle ----

// maxEmailBytes is the longest email an account may have. Every account logs
// in to Postgres as a role named after its email, and Postgres cuts role names
// at 63 bytes — so two longer emails that shared their first 63 bytes would
// have shared one role, and with it one identity in the Blackbox and one set
// of grants.
const maxEmailBytes = 63

// ErrBadEmail is returned for an address an account cannot have.
var ErrBadEmail = errors.New("enter a plain email address (name@example.com), at most 63 characters")

// normalizeEmail lower-cases and trims an address and checks it is a bare
// address that fits a Postgres role name.
func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", errors.New("email required")
	}
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || a.Name != "" || len(email) > maxEmailBytes {
		return "", ErrBadEmail
	}
	return email, nil
}

// ChangePassword replaces an account's password after checking the current
// one, and ends every other session of that account: whoever else was signed
// in with the old password is signed out. keepSession, if not empty, is the
// session that made the change and stays signed in.
func (s *Store) ChangePassword(userID int64, current, next, keepSession string) error {
	if len(next) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	var hash string
	if err := s.db.QueryRow(`SELECT pw_hash FROM users WHERE id=?`, userID).Scan(&hash); err != nil {
		return errors.New("no such account")
	}
	// An OAuth-only account has no password to check, and sets its first one.
	if hash != "" && bcrypt.CompareHashAndPassword([]byte(hash), []byte(current)) != nil {
		return errors.New("the current password is wrong")
	}
	return s.setPassword(userID, next, keepSession)
}

// ResetPassword sets an account's password without the current one — for an
// admin at the command line — and ends all of its sessions.
func (s *Store) ResetPassword(email, next string) error {
	if len(next) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	u, ok := s.UserByEmail(email)
	if !ok {
		return fmt.Errorf("no such user: %s", email)
	}
	return s.setPassword(u.ID, next, "")
}

func (s *Store) setPassword(userID int64, next, keepSession string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE users SET pw_hash=? WHERE id=?`, string(h), userID); err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM sessions WHERE user_id=? AND token<>?`, userID, keepSession)
	return err
}

// EndSessions signs an account out everywhere.
func (s *Store) EndSessions(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

// Account is an account as an admin sees it.
type Account struct {
	ID       int64  `json:"id"`
	Email    string `json:"email"`
	Created  int64  `json:"created"`
	Keys     int    `json:"keys"`
	Branches int    `json:"branches"`
}

// ListAccounts lists every account, oldest first.
func (s *Store) ListAccounts() ([]Account, error) {
	rows, err := s.db.Query(`SELECT u.id, u.email, u.created,
		(SELECT COUNT(*) FROM api_keys k WHERE k.user_id=u.id),
		(SELECT COUNT(*) FROM branch_owners b WHERE b.user_id=u.id)
		FROM users u ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		var a Account
		if err := rows.Scan(&a.ID, &a.Email, &a.Created, &a.Keys, &a.Branches); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAccount removes an account and everything that lets it in: its
// sessions, its API keys (agent keys it owned included), its OAuth sign-ins
// and its pipelines. The branches it owned stay, with no owner, so only an
// admin can reach them; nothing in a database is deleted.
func (s *Store) DeleteAccount(userID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM sessions WHERE user_id=?`,
		`DELETE FROM api_keys WHERE user_id=?`,
		`DELETE FROM oauth_identities WHERE user_id=?`,
		`DELETE FROM pipelines WHERE user_id=?`,
		`DELETE FROM branch_owners WHERE user_id=?`,
	} {
		if _, err := tx.Exec(q, userID); err != nil {
			return err
		}
	}
	res, err := tx.Exec(`DELETE FROM users WHERE id=?`, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such account")
	}
	return tx.Commit()
}

// ---- branch ownership ----

// Every branch made through the API, the Agent API or MCP records the account
// that made it. The owner may use and manage it; an admin may do anything; and
// main is everyone's to use. A branch with no owner — made at the command line,
// or before owners were recorded, or whose owner was deleted — is an admin's.

// SetBranchOwner records who owns a branch, replacing any earlier owner: a
// branch name that is used again belongs to whoever made it this time.
func (s *Store) SetBranchOwner(branch string, userID int64) error {
	_, err := s.db.Exec(`INSERT INTO branch_owners(branch, user_id, created) VALUES(?,?,?)
		ON CONFLICT(branch) DO UPDATE SET user_id=excluded.user_id, created=excluded.created`,
		branch, userID, time.Now().Unix())
	return err
}

// BranchOwner returns a branch's owner, if it has one.
func (s *Store) BranchOwner(branch string) (int64, bool) {
	var uid int64
	err := s.db.QueryRow(`SELECT user_id FROM branch_owners WHERE branch=?`, branch).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) || err != nil {
		return 0, false
	}
	return uid, true
}

// ForgetBranch drops a branch's owner, when the branch is deleted.
func (s *Store) ForgetBranch(branch string) error {
	_, err := s.db.Exec(`DELETE FROM branch_owners WHERE branch=?`, branch)
	return err
}
