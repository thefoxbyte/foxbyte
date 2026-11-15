// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// What an account holder can do about their own data without an admin
// (finding PRIV-7): take a copy of it, and delete the account.

// EvSubjectSearched: an operator searched the branches for one person's data
// (`fox subject find`). Detail is counts; the value searched for is never
// recorded.
const EvSubjectSearched = "personal-data.subject_searched"

// AccountExport is everything the store keeps about one account, for the
// account holder. Secrets are never in it: no password hash, no key or
// session token, not even their hashes. Those prove nothing to the holder and
// would be one more copy to lose.
type AccountExport struct {
	Exported string          `json:"exported"` // RFC 3339, UTC
	Profile  ExportProfile   `json:"profile"`
	OAuth    []ExportOAuth   `json:"oauth"`
	Keys     []ExportKey     `json:"apiKeys"`
	Branches []ExportBranch  `json:"branches"`
	Sessions []ExportSession `json:"sessions"`
	Events   []SecurityEvent `json:"securityEvents"`
	Notes    []string        `json:"notes"`
}

// ExportProfile is the account itself.
type ExportProfile struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	Created     string `json:"created"`
	HasPassword bool   `json:"hasPassword"`
	// EmailProven is false for an account made by open sign-up whose email no
	// provider has confirmed (emailproof.go).
	EmailProven bool `json:"emailProven"`
}

// ExportOAuth is a provider sign-in linked to the account: the provider, and
// the id it knows the person by.
type ExportOAuth struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

// ExportKey is an API key's description.
type ExportKey struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Prefix   string `json:"prefix"`
	Created  string `json:"created"`
	LastUsed string `json:"lastUsed,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Kind     string `json:"kind,omitempty"`
}

// ExportBranch is a branch the account owns.
type ExportBranch struct {
	Name    string `json:"name"`
	Created string `json:"created"`
}

// ExportSession is a signed-in browser session: when it began and ends.
type ExportSession struct {
	Started string `json:"started"`
	Expires string `json:"expires"`
}

func unixText(n int64) string { return time.Unix(n, 0).UTC().Format(time.RFC3339) }

// ExportAccount gathers an account's own data.
//
// Its security-log events are the ones where it acted, or was what was acted
// on. An address on such an event is shown only when it was this person's
// (they acted, or nobody was signed in and this was the account being tried):
// the address an admin acted from is the admin's.
func (s *Store) ExportAccount(userID int64) (AccountExport, error) {
	out := AccountExport{Exported: time.Now().UTC().Format(time.RFC3339),
		OAuth: []ExportOAuth{}, Keys: []ExportKey{}, Branches: []ExportBranch{},
		Sessions: []ExportSession{}, Events: []SecurityEvent{}}
	var hash string
	var created int64
	err := s.db.QueryRow(`SELECT id, email, created, pw_hash FROM users WHERE id=?`, userID).
		Scan(&out.Profile.ID, &out.Profile.Email, &created, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return out, errors.New("no such account")
	}
	if err != nil {
		return out, err
	}
	out.Profile.Created, out.Profile.HasPassword = unixText(created), hash != ""
	var unproven int
	if err := s.db.QueryRow(`SELECT count(*) FROM unproven_emails WHERE user_id=?`, userID).Scan(&unproven); err != nil {
		return out, err
	}
	out.Profile.EmailProven = unproven == 0

	if err := s.each(`SELECT provider, subject FROM oauth_identities WHERE user_id=? ORDER BY provider, subject`, []any{userID},
		func(r *sql.Rows) error {
			var o ExportOAuth
			if err := r.Scan(&o.Provider, &o.Subject); err != nil {
				return err
			}
			out.OAuth = append(out.OAuth, o)
			return nil
		}); err != nil {
		return out, err
	}
	if err := s.each(`SELECT id, name, prefix, created, last_used, scope, kind FROM api_keys WHERE user_id=? ORDER BY created, id`, []any{userID},
		func(r *sql.Rows) error {
			var k ExportKey
			var c int64
			var used sql.NullInt64
			if err := r.Scan(&k.ID, &k.Name, &k.Prefix, &c, &used, &k.Scope, &k.Kind); err != nil {
				return err
			}
			k.Created = unixText(c)
			if used.Valid {
				k.LastUsed = unixText(used.Int64)
			}
			out.Keys = append(out.Keys, k)
			return nil
		}); err != nil {
		return out, err
	}
	if err := s.each(`SELECT branch, created FROM branch_owners WHERE user_id=? ORDER BY branch`, []any{userID},
		func(r *sql.Rows) error {
			var b ExportBranch
			var c int64
			if err := r.Scan(&b.Name, &c); err != nil {
				return err
			}
			b.Created = unixText(c)
			out.Branches = append(out.Branches, b)
			return nil
		}); err != nil {
		return out, err
	}
	if err := s.each(`SELECT expires FROM sessions WHERE user_id=? AND expires > ? ORDER BY expires`, []any{userID, time.Now().Unix()},
		func(r *sql.Rows) error {
			var exp int64
			if err := r.Scan(&exp); err != nil {
				return err
			}
			out.Sessions = append(out.Sessions, ExportSession{
				Started: unixText(exp - int64(sessionTTL/time.Second)), Expires: unixText(exp)})
			return nil
		}); err != nil {
		return out, err
	}
	email := strings.ToLower(out.Profile.Email)
	if err := s.each(`SELECT id,at,kind,actor,subject,ip,detail FROM security_events
		WHERE lower(actor)=? OR lower(subject)=? ORDER BY id`, []any{email, email},
		func(r *sql.Rows) error {
			var e SecurityEvent
			if err := r.Scan(&e.ID, &e.At, &e.Kind, &e.Actor, &e.Subject, &e.IP, &e.Detail); err != nil {
				return err
			}
			theirs := strings.EqualFold(e.Actor, email) || (e.Actor == "" && strings.EqualFold(e.Subject, email))
			if !theirs {
				e.IP = ""
			}
			out.Events = append(out.Events, e)
			return nil
		}); err != nil {
		return out, err
	}
	out.Notes = []string{
		"Your query history and saved queries are in GET /api/history and GET /api/saved-queries.",
		"The rows you wrote into databases belong to those databases, not to your account, and are not in this file.",
		"Keys and sessions are described, never included: their secrets are not kept in a form that could be given back.",
	}
	return out, nil
}

// each runs a query and calls fn for every row.
func (s *Store) each(q string, args []any, fn func(*sql.Rows) error) error {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// CheckPassword reports whether pw is the account's password. An account that
// only signs in with a provider has none, and nothing matches it.
func (s *Store) CheckPassword(userID int64, pw string) bool {
	var hash string
	if err := s.db.QueryRow(`SELECT pw_hash FROM users WHERE id=?`, userID).Scan(&hash); err != nil || hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// SessionAge is how long ago the session behind tok was signed in to, for a
// change that wants a recent sign-in instead of a password. Sessions keep only
// their expiry, and every one lasts sessionTTL, so the start follows from it.
func (s *Store) SessionAge(tok string) (time.Duration, bool) {
	if tok == "" {
		return 0, false
	}
	var uid, exp int64
	if err := s.db.QueryRow(`SELECT user_id, expires FROM sessions WHERE token=?`, hashKey(tok)).Scan(&uid, &exp); err != nil {
		return 0, false
	}
	started := time.Unix(exp, 0).Add(-sessionTTL)
	return time.Since(started), true
}
