// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Applications that may say which of their users a transaction acts for
// (application identity, F1: docs/FOX_F1_Identity_Design.md, sections 4 and 7).
//
// An application is registered against the account whose key its connections
// use. Its tokens, signed with a private key only the application holds, are
// accepted from that account's own login and nowhere else, so a token that
// leaks is useless without the application's database credentials too.
//
// This store is the source of truth. The engine copies every registration into
// each branch's bb.app_issuers (internal/branch/identity.go), at once on the
// running ones and on resume for the suspended ones, and the HA standby gets
// these tables with the accounts (shared.go). Only public keys are kept: the
// engine can check a token and can never make one.

const appsSchema = `
CREATE TABLE IF NOT EXISTS apps (
  name TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER NOT NULL,
  max_life INTEGER NOT NULL DEFAULT 300, on_invalid TEXT NOT NULL DEFAULT 'none'
);
CREATE TABLE IF NOT EXISTS app_keys (
  app TEXT NOT NULL, kid TEXT NOT NULL, public_key TEXT NOT NULL, created INTEGER NOT NULL,
  revoked INTEGER, compromised_since INTEGER,
  PRIMARY KEY (app, kid)
);
CREATE TABLE IF NOT EXISTS install_info (key TEXT PRIMARY KEY, value TEXT NOT NULL);`

const (
	// Security log kinds. Each names the application as its subject; a key
	// event names the key in its detail. Never a token: none is ever seen.
	EvAppRegistered = "app.registered"
	EvAppRemoved    = "app.removed"
	EvAppKeyAdded   = "app.key_added"
	EvAppKeyRevoked = "app.key_revoked"
)

// DefaultAppMaxLife and MaxAppMaxLife bound how long an application's tokens
// may live, from issue to expiry (design, section 3). Short, because a token
// is not single-use: binding to the application's own login is what makes a
// leaked one useless, and its life is how long that has to hold.
const (
	DefaultAppMaxLife = 5 * time.Minute
	MaxAppMaxLife     = 60 * time.Minute
)

var (
	appNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	kidRE     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

	ErrAppExists   = errors.New("an application by that name is already registered")
	ErrAppNotFound = errors.New("no application by that name is registered")
	ErrAppKeyFound = errors.New("that application already has a key by that id")
	ErrAppNoKey    = errors.New("that application has no key by that id")
)

// App is one registered application.
type App struct {
	Name      string   `json:"name"`
	UserID    int64    `json:"user_id"`
	Account   string   `json:"account"` // the account's email, its login role; "" if the account is gone
	Created   int64    `json:"created"`
	MaxLife   int64    `json:"max_life_seconds"`
	OnInvalid string   `json:"on_invalid"` // "none" or "refuse"
	Keys      []AppKey `json:"keys"`
}

// AppKey is one of an application's public keys.
type AppKey struct {
	Kid              string `json:"kid"`
	PublicKey        string `json:"public_key"` // 32 bytes, hex
	Created          int64  `json:"created"`
	Revoked          *int64 `json:"revoked,omitempty"`
	CompromisedSince *int64 `json:"compromised_since,omitempty"`
}

// Active reports whether tokens signed with the key are accepted now.
func (k AppKey) Active() bool { return k.Revoked == nil }

// InstallID is the audience every token for this install must name (its aud
// claim), so a token minted for one install is refused by every other. Made
// once, at random, and kept here: the standby gets it with the accounts, so a
// failover does not invalidate every application's tokens.
func (s *Store) InstallID() (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT value FROM install_info WHERE key = 'install_id'`).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if _, err := s.db.Exec(`INSERT INTO install_info(key, value) VALUES('install_id', ?) ON CONFLICT(key) DO NOTHING`,
		"install-"+strings.ToLower(randHex(10))); err != nil {
		return "", err
	}
	// Read back rather than returned: two processes making it at once agree on
	// whichever was written first.
	err = s.db.QueryRow(`SELECT value FROM install_info WHERE key = 'install_id'`).Scan(&id)
	return id, err
}

func randHex(n int) string {
	t, err := newToken(n)
	if err != nil {
		panic("crypto/rand: " + err.Error())
	}
	b, _ := base64.RawURLEncoding.DecodeString(t)
	return hex.EncodeToString(b)
}

// RegisterApp registers an application against the account whose login its
// connections use. maxLife is clamped to (0, MaxAppMaxLife]; 0 means the
// default. onInvalid is "none" (an invalid token attributes the transaction to
// nobody, and it goes on) or "refuse" (the transaction is aborted).
func (s *Store) RegisterApp(name, account string, maxLife time.Duration, onInvalid string) (App, error) {
	name = strings.TrimSpace(name)
	if !appNameRE.MatchString(name) {
		return App{}, fmt.Errorf("an application's name is 1 to 63 lower-case letters, digits, '.', '_' or '-', starting with a letter or digit: %q is not", name)
	}
	u, ok := s.UserByEmail(strings.TrimSpace(account))
	if !ok {
		return App{}, fmt.Errorf("no account %q: an application is registered against the account whose key its connections use", account)
	}
	if maxLife == 0 {
		maxLife = DefaultAppMaxLife
	}
	if maxLife < time.Second || maxLife > MaxAppMaxLife {
		return App{}, fmt.Errorf("a token's life is at most %s, and at least a second: %s is not", MaxAppMaxLife, maxLife)
	}
	switch onInvalid {
	case "":
		onInvalid = "none"
	case "none", "refuse":
	default:
		return App{}, fmt.Errorf("on an invalid token, an application's transaction is attributed to none, or refused: %q is neither", onInvalid)
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec(`INSERT INTO apps(name, user_id, created, max_life, on_invalid) VALUES(?,?,?,?,?)`,
		name, u.ID, now, int64(maxLife/time.Second), onInvalid); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY KEY") {
			return App{}, ErrAppExists
		}
		return App{}, err
	}
	return s.App(name)
}

// AddAppKey adds a public key to an application. kid may be empty, and is then
// the key's RFC 7638 thumbprint, which any JWT library can compute too.
func (s *Store) AddAppKey(app, kid string, pub ed25519.PublicKey) (AppKey, error) {
	if len(pub) != ed25519.PublicKeySize {
		return AppKey{}, fmt.Errorf("an Ed25519 public key is %d bytes, not %d", ed25519.PublicKeySize, len(pub))
	}
	if _, err := s.App(app); err != nil {
		return AppKey{}, err
	}
	kid = strings.TrimSpace(kid)
	if kid == "" {
		kid = Thumbprint(pub)
	}
	if !kidRE.MatchString(kid) {
		return AppKey{}, fmt.Errorf("a key id is 1 to 64 letters, digits, '.', '_' or '-': %q is not", kid)
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM app_keys WHERE public_key = ?`, hex.EncodeToString(pub)).Scan(&n); err != nil {
		return AppKey{}, err
	}
	if n > 0 {
		// One key, one application: otherwise a record asserted with it could
		// not say which application vouched.
		return AppKey{}, errors.New("that public key is already registered; an application needs a key of its own")
	}
	k := AppKey{Kid: kid, PublicKey: hex.EncodeToString(pub), Created: time.Now().Unix()}
	if _, err := s.db.Exec(`INSERT INTO app_keys(app, kid, public_key, created) VALUES(?,?,?,?)`,
		app, k.Kid, k.PublicKey, k.Created); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY KEY") {
			return AppKey{}, ErrAppKeyFound
		}
		return AppKey{}, err
	}
	return k, nil
}

// RevokeAppKey stops a key's tokens being accepted, from now. compromisedSince,
// when given, also marks every record asserted with it since then: reports
// show those as "(key reported compromised)", never as plain "asserted".
// Revoking is not undone; a key that is wanted again is added again, under a
// new id.
func (s *Store) RevokeAppKey(app, kid string, compromisedSince *time.Time) error {
	now := time.Now().Unix()
	var since any
	if compromisedSince != nil {
		since = compromisedSince.Unix()
	}
	res, err := s.db.Exec(`UPDATE app_keys SET revoked = coalesce(revoked, ?), compromised_since = coalesce(?, compromised_since)
		WHERE app = ? AND kid = ?`, now, since, app, kid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.App(app); err != nil {
			return err
		}
		return ErrAppNoKey
	}
	return nil
}

// RemoveApp removes an application and its keys. What it asserted stays in
// every Blackbox, under its name: a record is never rewritten.
func (s *Store) RemoveApp(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`DELETE FROM apps WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAppNotFound
	}
	if _, err := tx.Exec(`DELETE FROM app_keys WHERE app = ?`, name); err != nil {
		return err
	}
	return tx.Commit()
}

// App reads one application, with its keys.
func (s *Store) App(name string) (App, error) {
	apps, err := s.apps(`WHERE a.name = ?`, name)
	if err != nil {
		return App{}, err
	}
	if len(apps) == 0 {
		return App{}, ErrAppNotFound
	}
	return apps[0], nil
}

// Apps reads every application, with its keys, by name.
func (s *Store) Apps() ([]App, error) { return s.apps("") }

func (s *Store) apps(where string, args ...any) ([]App, error) {
	rows, err := s.db.Query(`SELECT a.name, a.user_id, coalesce(u.email, ''), a.created, a.max_life, a.on_invalid
		FROM apps a LEFT JOIN users u ON u.id = a.user_id `+where+` ORDER BY a.name`, args...)
	if err != nil {
		return nil, err
	}
	out := []App{}
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.Name, &a.UserID, &a.Account, &a.Created, &a.MaxLife, &a.OnInvalid); err != nil {
			rows.Close()
			return nil, err
		}
		a.Keys = []AppKey{}
		out = append(out, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		krows, err := s.db.Query(`SELECT kid, public_key, created, revoked, compromised_since FROM app_keys
			WHERE app = ? ORDER BY created, kid`, out[i].Name)
		if err != nil {
			return nil, err
		}
		for krows.Next() {
			var k AppKey
			var rev, comp sql.NullInt64
			if err := krows.Scan(&k.Kid, &k.PublicKey, &k.Created, &rev, &comp); err != nil {
				krows.Close()
				return nil, err
			}
			if rev.Valid {
				k.Revoked = &rev.Int64
			}
			if comp.Valid {
				k.CompromisedSince = &comp.Int64
			}
			out[i].Keys = append(out[i].Keys, k)
		}
		krows.Close()
		if err := krows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Thumbprint is an Ed25519 key's RFC 7638 JWK thumbprint, base64url: the key
// id an application's key gets when none is given.
func Thumbprint(pub ed25519.PublicKey) string {
	// The members in lexicographic order, no whitespace, as RFC 7638 requires.
	j := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	h := sha256.Sum256([]byte(j))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ParsePublicKey reads an Ed25519 public key in any of the forms an
// application is likely to have one in: a PEM "PUBLIC KEY" (what
// `openssl pkey -pubout` writes), a JWK ({"kty":"OKP","crv":"Ed25519","x":…}),
// or the 32 bytes as hex, base64 or base64url. A private key is refused,
// whatever its form, so one pasted by mistake is never kept.
func ParsePublicKey(b []byte) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(string(b))
	if strings.Contains(s, "PRIVATE KEY") {
		return nil, errors.New("that is a private key: register the public half, which `openssl pkey -in key.pem -pubout` prints. The private key stays with the application")
	}
	if blk, _ := pem.Decode([]byte(s)); blk != nil {
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("reading the PEM public key: %w", err)
		}
		pub, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("that is a %T public key; tokens are checked with Ed25519 only", k)
		}
		return pub, nil
	}
	if strings.HasPrefix(s, "{") {
		var j struct {
			Kty, Crv, X, D string
		}
		if err := json.Unmarshal([]byte(s), &j); err != nil {
			return nil, fmt.Errorf("reading the JWK: %w", err)
		}
		if j.D != "" {
			return nil, errors.New("that JWK holds a private key (it has \"d\"): register the public half only")
		}
		if j.Kty != "OKP" || j.Crv != "Ed25519" {
			return nil, fmt.Errorf("that JWK is kty %q, crv %q; tokens are checked with Ed25519 (OKP) only", j.Kty, j.Crv)
		}
		return rawKey(base64.RawURLEncoding.DecodeString(strings.TrimRight(j.X, "=")))
	}
	if len(s) == 2*ed25519.PublicKeySize {
		if b, err := hex.DecodeString(s); err == nil {
			return rawKey(b, nil)
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return rawKey(b, nil)
		}
	}
	return nil, errors.New("not an Ed25519 public key: give a PEM public key, a JWK, or the 32 bytes in hex or base64")
}

func rawKey(b []byte, err error) (ed25519.PublicKey, error) {
	if err != nil {
		return nil, fmt.Errorf("reading the key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("an Ed25519 public key is %d bytes; that is %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}
