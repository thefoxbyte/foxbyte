// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth gates FoxByte's surfaces. It stores users, API keys, sessions,
// and OAuth identities in a local SQLite file (pure-Go driver, no cgo) and
// provides an HTTP middleware plus login/OAuth/API-key handlers. Scope is
// single-tenant: authenticated users share one FoxByte instance.
package auth

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// OAuthApp holds a provider's client credentials.
type OAuthApp struct{ ClientID, ClientSecret string }

// KeyPrefix begins every API key. Brand-free on purpose: the product has been
// renamed twice, and a key already issued must keep working.
const KeyPrefix = "key_"

func (a OAuthApp) enabled() bool { return a.ClientID != "" && a.ClientSecret != "" }

// Config is the auth configuration (usually built from the environment).
type Config struct {
	DBPath     string
	WebOrigin  string // where the web UI is served (for CORS + OAuth redirect back)
	PublicURL  string // this API's public base URL (for OAuth callbacks)
	SignupOpen bool
	GitHub     OAuthApp
	Google     OAuthApp
}

// User is an authenticated account.
type User struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

// Store is the auth data layer.
type Store struct {
	db       *sql.DB
	cfg      Config
	throttle *throttle

	// OnFirstUser runs when the first account on this install is created,
	// however it was created: the web sign-up or `fox user create`. The engine
	// sets it to give that account the admin grant, which nothing else hands
	// out on a fresh install. This package cannot reach the database engine
	// itself, so the hook belongs to whoever opens the store.
	OnFirstUser func(User)
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL DEFAULT '',
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL,
  key_hash TEXT NOT NULL, prefix TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER,
  scope TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_identities (
  provider TEXT NOT NULL, subject TEXT NOT NULL, user_id INTEGER NOT NULL,
  PRIMARY KEY (provider, subject)
);
CREATE TABLE IF NOT EXISTS pipelines (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, name TEXT NOT NULL,
  spec TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pipeline_runs (
  id TEXT PRIMARY KEY,
  pipeline_id TEXT NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL, status TEXT NOT NULL,
  started INTEGER NOT NULL, finished INTEGER, tables INTEGER NOT NULL DEFAULT 0,
  tests TEXT NOT NULL DEFAULT '[]', log TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS branch_owners (
  branch TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pipeline_targets (
  branch TEXT PRIMARY KEY,
  pipeline_id TEXT NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE
);`

// Open opens (and migrates) the SQLite store.
//
// The store is shared across several processes (control plane, gateway, agent
// API), so it is opened in WAL mode with a busy timeout: concurrent writers
// (e.g. the api_keys.last_used bump on every authenticated request) wait for the
// lock instead of failing with SQLITE_BUSY — which would otherwise surface to
// clients as a spurious 401.
func Open(cfg Config) (*Store, error) {
	dsn := cfg.DBPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, cfg: cfg, throttle: newThrottle(loginMaxFails, loginWindow)}, nil
}

// initSchema creates and migrates the store.
//
// `fox start` launches the control plane, the Gateway and the Agent API
// together, and on a new install all three create this file at the same
// moment. SQLite answers SQLITE_BUSY immediately — without waiting out
// busy_timeout — when two connections that began by reading both try to
// write, and while one process switches the file to WAL. The losers exited,
// so the first `fox start` of a new install left the control plane and the
// Agent API down (found by running the integration suites on a fresh VM).
//
// So the work runs in BEGIN IMMEDIATE, which takes the write lock before
// reading anything and therefore does wait on busy_timeout, and a BUSY that
// still gets through (the WAL switch happens when the connection opens) is
// retried for a while.
func initSchema(db *sql.DB) error {
	deadline := time.Now().Add(30 * time.Second)
	for attempt := 1; ; attempt++ {
		err := initSchemaOnce(db)
		if err == nil || !isBusy(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Duration(min(attempt, 10)) * 50 * time.Millisecond)
	}
}

func initSchemaOnce(db *sql.DB) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, schema); err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	if _, err := conn.ExecContext(ctx, auditSchema); err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	if err := migrate(ctx, conn); err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

func isBusy(err error) bool {
	m := err.Error()
	return strings.Contains(m, "SQLITE_BUSY") || strings.Contains(m, "database is locked")
}

// migrate applies what the CREATE TABLE statements above cannot: they run with
// IF NOT EXISTS, so an existing install keeps the columns it was created with.
// Every step must be safe to repeat on each open.
func migrate(ctx context.Context, db *sql.Conn) error {
	has, err := hasColumn(ctx, db, "api_keys", "scope")
	if err != nil {
		return err
	}
	if !has {
		// Existing keys are unscoped, which is what the empty default means.
		if _, err := db.ExecContext(ctx, `ALTER TABLE api_keys ADD COLUMN scope TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

func hasColumn(ctx context.Context, db *sql.Conn, table, column string) (bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Close releases the underlying database handle.
//
// Long-lived processes hold a Store for their whole lifetime, so this rarely
// matters to them — but anything that opens a Store and discards it leaks the
// handle, and on Windows an open handle also keeps the file locked, so the
// database cannot be removed or replaced until the process exits.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func envOr(k, def string) string {
	if v := brand.GetenvFull(k); v != "" {
		return v
	}
	return def
}

// DefaultPublicURL is where the control plane serves the API and the web console
// out of the box: TLS on port 8080.
const DefaultPublicURL = "https://localhost:8080"

// urlDefaults resolves the public URL (OAuth callbacks) and the web origin (CORS,
// the redirect after an OAuth login, the session cookie). The console is served
// by the control plane itself, so the web origin defaults to the public URL. The
// old defaults — http://localhost:8080 and the retired Vite dev server on
// http://localhost:5173 — sent an OAuth login back to a page that doesn't exist
// and registered a callback over plain HTTP. A separately hosted UI sets
// FOX_WEB_ORIGIN.
func urlDefaults(getenv func(string) string) (publicURL, webOrigin string) {
	publicURL = strings.TrimRight(strings.TrimSpace(getenv("FOX_PUBLIC_URL")), "/")
	if publicURL == "" {
		publicURL = DefaultPublicURL
	}
	webOrigin = strings.TrimRight(strings.TrimSpace(getenv("FOX_WEB_ORIGIN")), "/")
	if webOrigin == "" {
		webOrigin = publicURL
	}
	return publicURL, webOrigin
}

// OpenFromEnv builds Config from FOX_* env vars and opens the store.
func OpenFromEnv() (*Store, error) {
	dir := brand.StateDir()
	_ = os.MkdirAll(dir, 0o755)
	public, web := urlDefaults(os.Getenv)
	return Open(Config{
		DBPath:     envOr("FOX_DB", filepath.Join(dir, "auth.db")),
		WebOrigin:  web,
		PublicURL:  public,
		SignupOpen: SignupOpenFromEnv(),
		GitHub:     OAuthApp{brand.Getenv("GITHUB_CLIENT_ID"), brand.Getenv("GITHUB_CLIENT_SECRET")},
		Google:     OAuthApp{brand.Getenv("GOOGLE_CLIENT_ID"), brand.Getenv("GOOGLE_CLIENT_SECRET")},
	})
}

// WebOrigin is the configured UI origin (used for CORS).
func (s *Store) WebOrigin() string { return s.cfg.WebOrigin }

// HasAnyUser reports whether any account exists.
func (s *Store) HasAnyUser() bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n > 0
}

// newToken returns n random bytes, URL-safe base64. Every session, API key and
// OAuth state comes from here.
func newToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randToken is newToken for callers that cannot return an error. A failing
// system random source must never produce a guessable credential, so it stops
// the process rather than return anything. (Since Go 1.24 crypto/rand already
// does this itself; the check keeps that true whatever the toolchain.)
func randToken(n int) string {
	t, err := newToken(n)
	if err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return t
}

// ---- users ----

// CreateUser creates an account (password may be "" for OAuth-only users).
func (s *Store) CreateUser(email, password string) (User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	var hash string
	if password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return User{}, err
		}
		hash = string(h)
	}
	res, err := s.db.Exec(`INSERT INTO users(email, pw_hash, created) VALUES(?,?,?)`, email, hash, time.Now().Unix())
	if err != nil {
		return User{}, fmt.Errorf("email already registered")
	}
	id, _ := res.LastInsertId()
	u := User{ID: id, Email: email}
	// The first account is the one with the lowest id. Counting before the
	// insert let two sign-ups at the same moment both see an empty store and
	// both become the admin; the lowest id is one account, whatever the timing.
	var firstID int64
	if err := s.db.QueryRow(`SELECT MIN(id) FROM users`).Scan(&firstID); err == nil && firstID == id {
		removeSetupToken()
		if s.OnFirstUser != nil {
			s.OnFirstUser(u)
		}
	}
	return u, nil
}

// Register creates an account from the sign-up form. The first account on an
// install needs the setup token (see setup.go); later ones need sign-up to be
// open. `fox user create` calls CreateUser directly and needs neither.
func (s *Store) Register(email, password, setupToken string) (User, error) {
	if !s.HasAnyUser() {
		if !checkSetupToken(setupToken) {
			return User{}, ErrSetupToken
		}
	} else if !s.cfg.SignupOpen {
		return User{}, ErrSignupClosed
	}
	return s.CreateUser(email, password)
}

// Login verifies email + password.
func (s *Store) Login(email, password string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var u User
	var hash string
	if err := s.db.QueryRow(`SELECT id, email, pw_hash FROM users WHERE email=?`, email).Scan(&u.ID, &u.Email, &hash); err != nil {
		return User{}, errors.New("invalid credentials")
	}
	if hash == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return User{}, errors.New("invalid credentials")
	}
	return u, nil
}

func (s *Store) userByID(id int64) (User, error) {
	var u User
	err := s.db.QueryRow(`SELECT id, email FROM users WHERE id=?`, id).Scan(&u.ID, &u.Email)
	return u, err
}

// ---- sessions ----

const sessionTTL = 30 * 24 * time.Hour

func (s *Store) createSession(userID int64) (string, error) {
	tok := randToken(24)
	_, err := s.db.Exec(`INSERT INTO sessions(token, user_id, expires) VALUES(?,?,?)`,
		tok, userID, time.Now().Add(sessionTTL).Unix())
	return tok, err
}

func (s *Store) userBySession(tok string) (User, bool) {
	var uid, exp int64
	if err := s.db.QueryRow(`SELECT user_id, expires FROM sessions WHERE token=?`, tok).Scan(&uid, &exp); err != nil {
		return User{}, false
	}
	if time.Now().Unix() > exp {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token=?`, tok)
		return User{}, false
	}
	u, err := s.userByID(uid)
	return u, err == nil
}

func (s *Store) deleteSession(tok string) {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE token=?`, tok)
}

// ---- api keys ----

// KeyInfo is a non-secret view of an API key.
type KeyInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Prefix  string `json:"prefix"`
	Created int64  `json:"created"`
	// Scope is empty for an ordinary account key. A non-empty scope names the
	// one branch the key may open through the Gateway, and such a key is
	// refused everywhere else (see Authn).
	Scope string `json:"scope,omitempty"`
}

func hashKey(k string) string { h := sha256.Sum256([]byte(k)); return hex.EncodeToString(h[:]) }

// CreateAPIKey returns the full secret (shown once) plus its stored metadata.
// The key is unscoped: it carries the owner's full access.
func (s *Store) CreateAPIKey(userID int64, name string) (string, KeyInfo, error) {
	return s.CreateScopedAPIKey(userID, name, "")
}

// CreateScopedAPIKey mints a key that may open exactly one branch through the
// Gateway and nothing else — no control-plane and no Agent API access (Authn
// refuses it). This is what an agent is handed with its branch, so a leaked
// agent credential cannot reach another agent's data, the account, or the
// branches that account owns. An empty scope mints an ordinary account key.
func (s *Store) CreateScopedAPIKey(userID int64, name, scope string) (string, KeyInfo, error) {
	if strings.TrimSpace(name) == "" {
		name = "key"
	}
	scope = strings.TrimSpace(scope)
	secret := KeyPrefix + randToken(24)
	id := randToken(8)
	prefix := secret[:12]
	now := time.Now().Unix()
	if _, err := s.db.Exec(`INSERT INTO api_keys(id,user_id,name,key_hash,prefix,created,scope) VALUES(?,?,?,?,?,?,?)`,
		id, userID, name, hashKey(secret), prefix, now, scope); err != nil {
		return "", KeyInfo{}, err
	}
	return secret, KeyInfo{ID: id, Name: name, Prefix: prefix, Created: now, Scope: scope}, nil
}

// AnyUserID returns some existing account's id, or false when there are none.
// It is the owner for keys the engine mints for itself: an agent branch created
// over MCP or the CLI has no authenticated caller, but every key needs an owner
// so it can be listed and revoked. A scoped key carries no account access, so
// the owner decides only who can see and revoke it.
func (s *Store) AnyUserID() (int64, bool) {
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM users ORDER BY id LIMIT 1`).Scan(&id); err != nil {
		return 0, false
	}
	return id, true
}

// RevokeScopeKeys deletes every key scoped to one branch, so an agent's
// credential dies with its branch. It never touches unscoped account keys.
func (s *Store) RevokeScopeKeys(scope string) error {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM api_keys WHERE scope=?`, scope)
	return err
}

// VerifyKey resolves an API key to its user and its scope. A false result means
// "not authenticated"; a genuine store failure (as opposed to an unknown key) is
// logged so it is diagnosable rather than silently masquerading as a bad key.
//
// An empty scope is an ordinary account key. A non-empty scope names the single
// branch the key may open through the Gateway: callers must honour it — Authn
// refuses such a key outright, and the Gateway allows it only for that branch.
func (s *Store) VerifyKey(key string) (User, string, bool) {
	h := hashKey(key)
	var uid int64
	var scope string
	switch err := s.db.QueryRow(`SELECT user_id, scope FROM api_keys WHERE key_hash=?`, h).Scan(&uid, &scope); {
	case errors.Is(err, sql.ErrNoRows):
		return User{}, "", false // no such key — an ordinary auth failure
	case err != nil:
		log.Printf("auth: VerifyKey store error (client will see this as unauthenticated): %v", err)
		return User{}, "", false
	}
	// Best-effort, throttled last_used bump: only when stale (>60s), so a burst of
	// concurrent auth checks doesn't turn into a burst of writes on the store.
	// (This makes last_used coarse by ~a minute — fine for "last active", not for
	// real-time anomaly detection.)
	now := time.Now().Unix()
	_, _ = s.db.Exec(`UPDATE api_keys SET last_used=? WHERE key_hash=? AND (last_used IS NULL OR last_used < ?)`,
		now, h, now-60)
	u, err := s.userByID(uid)
	return u, scope, err == nil
}

func (s *Store) listAPIKeys(userID int64) ([]KeyInfo, error) {
	rows, err := s.db.Query(`SELECT id,name,prefix,created,scope FROM api_keys WHERE user_id=? ORDER BY created DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyInfo
	for rows.Next() {
		var k KeyInfo
		_ = rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Created, &k.Scope)
		out = append(out, k)
	}
	return out, nil
}

func (s *Store) revokeAPIKey(userID int64, id string) error {
	_, err := s.db.Exec(`DELETE FROM api_keys WHERE id=? AND user_id=?`, id, userID)
	return err
}

// UserByEmail looks up a user by email without a password check (CLI admin use).
func (s *Store) UserByEmail(email string) (User, bool) {
	var u User
	if err := s.db.QueryRow(`SELECT id,email FROM users WHERE email=?`,
		strings.ToLower(strings.TrimSpace(email))).Scan(&u.ID, &u.Email); err != nil {
		return User{}, false
	}
	return u, true
}

// ListKeys and RevokeKey are exported wrappers for CLI admin use.
func (s *Store) ListKeys(userID int64) ([]KeyInfo, error) { return s.listAPIKeys(userID) }
func (s *Store) RevokeKey(userID int64, id string) error  { return s.revokeAPIKey(userID, id) }

// ---- oauth upsert ----

// errOAuthNoAccount is what a sign-in with a provider gets when it would have to
// create an account and may not.
var errOAuthNoAccount = errors.New("no account for this sign-in, and sign-up is closed")

// errOAuthUnverified refuses an unverified provider email: anyone can put any
// address on a provider account, so an unverified one proves nothing.
var errOAuthUnverified = errors.New("the email on that account is not verified with the provider")

// upsertOAuth signs in with a provider identity. A known identity signs in its
// account. Otherwise the provider's email must be verified: it then joins the
// account with that email, or — only when sign-up is open and the install
// already has its first account — becomes a new account. The first account is
// made with the setup token, which a provider sign-in cannot carry.
func (s *Store) upsertOAuth(provider, subject, email string, verified bool) (User, error) {
	var uid int64
	if err := s.db.QueryRow(`SELECT user_id FROM oauth_identities WHERE provider=? AND subject=?`, provider, subject).Scan(&uid); err == nil {
		return s.userByID(uid)
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !verified {
		return User{}, errOAuthUnverified
	}
	if !s.cfg.SignupOpen || !s.HasAnyUser() {
		if _, ok := s.UserByEmail(email); !ok {
			return User{}, errOAuthNoAccount
		}
	}
	{
		var u User
		if e := s.db.QueryRow(`SELECT id,email FROM users WHERE email=?`, email).Scan(&u.ID, &u.Email); e == nil {
			_, _ = s.db.Exec(`INSERT INTO oauth_identities(provider,subject,user_id) VALUES(?,?,?)`, provider, subject, u.ID)
			return u, nil
		}
	}
	nu, err := s.CreateUser(email, "")
	if err != nil {
		return User{}, err
	}
	_, _ = s.db.Exec(`INSERT INTO oauth_identities(provider,subject,user_id) VALUES(?,?,?)`, provider, subject, nu.ID)
	return nu, nil
}
