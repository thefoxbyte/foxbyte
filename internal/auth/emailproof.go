// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Whether an account's email was ever proven.
//
// FoxByte sends no mail, so an address typed into the open sign-up form is
// only a claim. A GitHub or Google sign-in with a verified email joins the
// account that has that address, which is what people expect when they used a
// password first. Put together, that let one person register someone else's
// address while sign-up was open and keep a working password after the real
// owner had signed in with their provider and started using the account.
//
// So an account made by open sign-up is recorded as unproven (a row in
// unproven_emails). Every other way to make an account proves the address: an
// admin's `fox user create`, the first account with the setup token, and a
// provider sign-in with a verified email. When a provider sign-in joins an
// unproven account, the provider has just proven the address, and what the
// earlier claimant set up is removed: the password, every session and every
// API key. The provider's user then owns an account nobody else can enter.
// That is linkOAuth, in one transaction with its security-log event, so the
// account is never joined without being cleaned, nor cleaned without a record.
//
// What the account holds — branches, pipelines, saved queries — stays: the
// address's owner may well be the one who made them, and only the ways in are
// suspect.

// insertUser adds the users row, and the unproven_emails row when the email is
// not proven, in one transaction.
func (s *Store) insertUser(email, hash string, proven bool) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().Unix()
	res, err := tx.Exec(`INSERT INTO users(email, pw_hash, created) VALUES(?,?,?)`, email, hash, now)
	if err != nil {
		return 0, fmt.Errorf("email already registered")
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if !proven {
		if _, err := tx.Exec(`INSERT INTO unproven_emails(user_id, since) VALUES(?,?)`, id, now); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

// EmailProven reports whether an account's email has been proven. An account
// that does not exist is reported as proven: there is nothing to take over.
func (s *Store) EmailProven(userID int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM unproven_emails WHERE user_id=?`, userID).Scan(&n)
	return n == 0, err
}

// linkOAuth joins a provider identity to the account with this (verified)
// email. ok is false when there is no such account. If the account's email
// was never proven, its password, sessions and API keys go and the email
// becomes proven, all with the security-log event in one transaction.
func (s *Store) linkOAuth(provider, subject, email, ip string) (u User, ok bool, err error) {
	err = retryBusy(func() error {
		u, ok, err = s.linkOAuthOnce(provider, subject, email, ip)
		return err
	})
	return u, ok, err
}

func (s *Store) linkOAuthOnce(provider, subject, email, ip string) (User, bool, error) {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return User{}, false, err
	}
	defer conn.Close()
	// IMMEDIATE because the security-log event chains onto the log's head,
	// which must not move between reading it and writing after it.
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return User{}, false, err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	var u User
	switch err := conn.QueryRowContext(ctx, `SELECT id, email FROM users WHERE email=?`, email).Scan(&u.ID, &u.Email); {
	case errors.Is(err, sql.ErrNoRows):
		return User{}, false, nil
	case err != nil:
		return User{}, false, err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO oauth_identities(provider,subject,user_id) VALUES(?,?,?)
		ON CONFLICT DO NOTHING`, provider, subject, u.ID); err != nil {
		return User{}, false, err
	}
	res, err := conn.ExecContext(ctx, `DELETE FROM unproven_emails WHERE user_id=?`, u.ID)
	if err != nil {
		return User{}, false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if _, err := conn.ExecContext(ctx, `UPDATE users SET pw_hash='' WHERE id=?`, u.ID); err != nil {
			return User{}, false, err
		}
		sess, err := conn.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, u.ID)
		if err != nil {
			return User{}, false, err
		}
		keys, err := conn.ExecContext(ctx, `DELETE FROM api_keys WHERE user_id=?`, u.ID)
		if err != nil {
			return User{}, false, err
		}
		ns, _ := sess.RowsAffected()
		nk, _ := keys.RowsAffected()
		detail := fmt.Sprintf("%s proved an email that open sign-up had not; removed the password, %d session(s) and %d API key(s)",
			provider, ns, nk)
		if err := appendEventIn(ctx, conn, EvAccountClaimed, u.Email, u.Email, ip, detail); err != nil {
			return User{}, false, err
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return User{}, false, err
	}
	commit = true
	return u, true, nil
}
