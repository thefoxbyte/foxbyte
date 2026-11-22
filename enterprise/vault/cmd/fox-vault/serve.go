//go:build enterprise && cgo && linux

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/thefoxbyte/foxbyte/enterprise/vault"
	"github.com/thefoxbyte/foxbyte/enterprise/vault/hsm"
)

// The vault database's schema (design, section 8). Only the service's role
// uses it; nothing else connects.
const schema = `
CREATE SCHEMA IF NOT EXISTS vault;
CREATE TABLE IF NOT EXISTS vault.keys (
  label        text PRIMARY KEY,
  kind         text NOT NULL,
  role         text NOT NULL CHECK (role IN ('data', 'index')),
  gen          int  NOT NULL,
  current      boolean NOT NULL DEFAULT false,
  uses         bigint NOT NULL DEFAULT 0,
  created_at   timestamptz NOT NULL DEFAULT now(),
  destroyed_at timestamptz
);
CREATE TABLE IF NOT EXISTS vault.records (
  ref        text PRIMARY KEY,
  kind       text NOT NULL,
  idx        bytea NOT NULL,
  nonce      bytea NOT NULL,
  ct         bytea NOT NULL,
  data_key   text NOT NULL REFERENCES vault.keys (label),
  index_key  text NOT NULL REFERENCES vault.keys (label),
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (kind, idx)
);
CREATE INDEX IF NOT EXISTS records_kind_key ON vault.records (kind, data_key);
CREATE TABLE IF NOT EXISTS vault.access_log (
  seq     bigint PRIMARY KEY,
  at_us   bigint NOT NULL,
  actor   text NOT NULL,
  action  text NOT NULL,
  kind    text NOT NULL,
  refs    text[] NOT NULL,
  n       int NOT NULL,
  purpose text NOT NULL,
  result  text NOT NULL,
  prev    bytea NOT NULL,
  hash    bytea NOT NULL
);
`

type server struct {
	tok    *hsm.Token
	db     *pgxpool.Pool
	secret []byte
	work   int

	// per kind: held for reading from choosing the current data key to the
	// record's insert, and for writing while rotation switches keys, so no
	// record is ever written under a key rotation is about to destroy.
	kindMu map[string]*sync.RWMutex
	rotMu  map[string]*sync.Mutex

	keyMu   sync.Mutex
	current map[string]map[string]string // kind -> role -> label
	// retired are a kind's index keys still in the token though no longer
	// current: while an index rotation runs (13.4), a record not yet moved
	// is found under its old key, so tokenise and find look under each.
	retired map[string][]string
	base    map[string]int64 // label -> uses before this process

	logMu   sync.Mutex
	lastSeq int64
	last    []byte
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socket := fs.String("socket", "/run/fox-vault/vault.sock", "the Unix socket the engine calls")
	secretFile := fs.String("secret-file", "/etc/fox-vault/secret/secret", "the per-install secret the engine proves itself with")
	lib := fs.String("pkcs11-lib", "/usr/lib/softhsm/libsofthsm2.so", "the PKCS#11 library")
	label := fs.String("token", "fox-vault", "the token's label")
	pinFile := fs.String("pin-file", "/etc/fox-vault/secret/pin", "the token's user PIN")
	dsnFile := fs.String("dsn-file", "/etc/fox-vault/secret/dsn", "the vault database's connection string")
	sessions := fs.Int("sessions", 8, "PKCS#11 sessions, so calls in parallel")
	delay := fs.Duration("hsm-delay", 0, "prototype only: added before every call to the token, for a network HSM's round trip")
	_ = fs.Parse(args)

	secret, err := readSecret(*secretFile)
	if err != nil {
		return err
	}
	pin, err := readSecret(*pinFile)
	if err != nil {
		return err
	}
	dsn, err := readSecret(*dsnFile)
	if err != nil {
		return err
	}
	tok, err := hsm.Open(*lib, *label, pin, *sessions, *delay)
	if err != nil {
		return err
	}
	defer tok.Close()
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("the vault database's connection string: %w", err)
	}
	cfg.MaxConns = int32(*sessions*2 + 4)
	var db *pgxpool.Pool
	for try := 0; ; try++ {
		if db, err = pgxpool.NewWithConfig(ctx, cfg); err == nil {
			if err = db.Ping(ctx); err == nil {
				break
			}
			db.Close()
		}
		if try == 60 {
			return fmt.Errorf("the vault database: %w", err)
		}
		time.Sleep(time.Second)
	}
	defer db.Close()
	if _, err := db.Exec(ctx, schema); err != nil {
		return fmt.Errorf("the vault's schema: %w", err)
	}
	s := &server{tok: tok, db: db, secret: []byte(secret), work: *sessions * 2,
		kindMu: map[string]*sync.RWMutex{}, rotMu: map[string]*sync.Mutex{},
		current: map[string]map[string]string{}, retired: map[string][]string{}, base: map[string]int64{}}
	if err := s.loadKeys(ctx); err != nil {
		return err
	}
	if err := s.loadLog(ctx); err != nil {
		return err
	}
	go s.flushUses()

	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(*socket, 0o600); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/tokenise", s.auth("tokenise", s.tokenise))
	mux.HandleFunc("/v1/find", s.auth("find", s.find))
	mux.HandleFunc("/v1/detokenise", s.auth("detokenise", s.detokenise))
	mux.HandleFunc("/v1/delete", s.auth("delete", s.delete))
	mux.HandleFunc("/v1/rotate", s.auth("rotate", s.rotate))
	mux.HandleFunc("/v1/update", s.auth("update", s.update))
	mux.HandleFunc("/v1/status", s.auth("status", s.status))
	mux.HandleFunc("/v1/log", s.auth("log", s.logAt))
	mux.HandleFunc("/v1/entries", s.auth("entries", s.entries))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		s.saveUses(context.Background())
		_ = srv.Close()
	}()
	info := tok.Info()
	log.Printf("fox-vault: serving on %s; token %q (%s %s), %d sessions", *socket, info.Label, info.Maker, info.Model, *sessions)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// loadKeys finds every kind's keys in the token, making the first ones when a
// kind has none yet.
func (s *server) loadKeys(ctx context.Context) error {
	for _, k := range vault.Kinds() {
		s.kindMu[k.Name] = &sync.RWMutex{}
		s.rotMu[k.Name] = &sync.Mutex{}
		s.current[k.Name] = map[string]string{}
		for _, role := range []string{"data", "index"} {
			var label string
			err := s.db.QueryRow(ctx, `SELECT label FROM vault.keys WHERE kind = $1 AND role = $2 AND current`, k.Name, role).Scan(&label)
			if errors.Is(err, pgx.ErrNoRows) {
				label = fmt.Sprintf("vault-%s-%s-1", k.Name, role)
				if err := s.makeKey(ctx, k.Name, role, label, 1, true); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			s.current[k.Name][role] = label
		}
		// An index rotation the service stopped in the middle of: its records
		// not yet moved are found under the old key until it is run again.
		rows, err := s.db.Query(ctx, `SELECT label FROM vault.keys WHERE kind = $1 AND role = 'index' AND NOT current AND destroyed_at IS NULL ORDER BY gen`, k.Name)
		if err != nil {
			return err
		}
		for rows.Next() {
			var l string
			if err := rows.Scan(&l); err != nil {
				rows.Close()
				return err
			}
			s.retired[k.Name] = append(s.retired[k.Name], l)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	rows, err := s.db.Query(ctx, `SELECT label, uses FROM vault.keys WHERE destroyed_at IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var label string
		var uses int64
		if err := rows.Scan(&label, &uses); err != nil {
			return err
		}
		ok, err := s.tok.Find(label)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("the vault names key %q, but the token does not hold it", label)
		}
		s.base[label] = uses
	}
	return rows.Err()
}

func (s *server) makeKey(ctx context.Context, kind, role, label string, gen int, current bool) error {
	ok, err := s.tok.Find(label)
	if err != nil {
		return err
	}
	if !ok {
		if role == "data" {
			err = s.tok.MakeAES(label)
		} else {
			err = s.tok.MakeHMAC(label)
		}
		if err != nil {
			return err
		}
	}
	_, err = s.db.Exec(ctx, `INSERT INTO vault.keys (label, kind, role, gen, current) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (label) DO NOTHING`, label, kind, role, gen, current)
	s.keyMu.Lock()
	s.base[label] = 0
	s.keyMu.Unlock()
	return err
}

func (s *server) currentKey(kind, role string) string {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	return s.current[kind][role]
}

// indexes is a normalised value's index under the kind's current index key,
// then under each retired one (an index rotation in progress): the first is
// what a new record is written with, all of them are where a record may be.
// The caller holds the kind for reading, so the keys cannot change meanwhile.
func (s *server) indexes(kind, norm string) (cur []byte, all [][]byte, err error) {
	s.keyMu.Lock()
	keys := append([]string{s.current[kind]["index"]}, s.retired[kind]...)
	s.keyMu.Unlock()
	for _, k := range keys {
		idx, err := s.tok.HMAC(k, []byte(norm))
		if err != nil {
			return nil, nil, err
		}
		all = append(all, idx)
	}
	return all[0], all, nil
}

// flushUses writes each key's count of encryptions every second, for the
// nonce limit (design, section 6).
func (s *server) flushUses() {
	for range time.Tick(time.Second) {
		s.saveUses(context.Background())
	}
}

func (s *server) saveUses(ctx context.Context) {
	s.keyMu.Lock()
	base := make(map[string]int64, len(s.base))
	for l, b := range s.base {
		base[l] = b
	}
	s.keyMu.Unlock()
	for l, b := range base {
		_, _ = s.db.Exec(ctx, `UPDATE vault.keys SET uses = $2 WHERE label = $1 AND uses <> $2`, l, b+s.tok.Uses(l))
	}
}

func (s *server) uses(label string) int64 {
	s.keyMu.Lock()
	b := s.base[label]
	s.keyMu.Unlock()
	return b + s.tok.Uses(label)
}

// --- the access log ---------------------------------------------------------

func (s *server) loadLog(ctx context.Context) error {
	err := s.db.QueryRow(ctx, `SELECT seq, hash FROM vault.access_log ORDER BY seq DESC LIMIT 1`).Scan(&s.lastSeq, &s.last)
	if errors.Is(err, pgx.ErrNoRows) {
		s.lastSeq, s.last = 0, vault.Genesis
		return nil
	}
	return err
}

// record appends an entry to the access log and, when w is a reply in the
// making, names the log's new head in it (vault.HeadHeader), which the engine
// copies into the install's security log: a chain shows an entry changed or
// removed from its middle, and the head kept outside shows entries cut off
// its end (design, section 10).
func (s *server) record(ctx context.Context, w http.ResponseWriter, e vault.Entry) error {
	if e.Refs == nil {
		e.Refs = []string{}
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	e.Seq = s.lastSeq + 1
	e.AtMicro = time.Now().UnixMicro()
	e.Prev = s.last
	e.Hash = e.Sum(s.last)
	if _, err := s.db.Exec(ctx, `INSERT INTO vault.access_log (seq, at_us, actor, action, kind, refs, n, purpose, result, prev, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		e.Seq, e.AtMicro, e.Actor, e.Action, e.Kind, e.Refs, e.N, e.Purpose, e.Result, e.Prev, e.Hash); err != nil {
		return fmt.Errorf("the access log: %w", err)
	}
	s.lastSeq, s.last = e.Seq, e.Hash
	if w != nil {
		w.Header().Set(vault.HeadHeader, vault.FormatHead(e.Seq, e.Hash))
	}
	return nil
}

// --- requests ---------------------------------------------------------------

type call struct {
	actor string
	req   vault.Request
	kind  *vault.Kind
}

func (s *server) auth(action string, h func(http.ResponseWriter, *http.Request, *call)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := strings.TrimSpace(r.Header.Get("X-Fox-Actor"))
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), s.secret) != 1 {
			if actor == "" || len(actor) > 200 {
				actor = "unknown"
			}
			_ = s.record(r.Context(), w, vault.Entry{Actor: actor, Action: action, Result: "refused: not the engine"})
			reply(w, http.StatusUnauthorized, vault.Response{Error: "not the engine"})
			return
		}
		if actor == "" || len(actor) > 200 {
			reply(w, http.StatusBadRequest, vault.Response{Error: "the call names no actor"})
			return
		}
		c := &call{actor: actor}
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&c.req); err != nil {
				reply(w, http.StatusBadRequest, vault.Response{Error: "the body is not a vault request"})
				return
			}
			k, ok := vault.KindOf(c.req.Kind)
			if !ok {
				_ = s.record(r.Context(), w, vault.Entry{Actor: actor, Action: action, Kind: c.req.Kind, Result: "refused: no such kind"})
				reply(w, http.StatusBadRequest, vault.Response{Error: fmt.Sprintf("no kind %q", c.req.Kind)})
				return
			}
			c.kind = k
		}
		h(w, r, c)
	}
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// each runs fn over 0..n-1 on the service's workers.
func (s *server) each(n int, fn func(i int)) {
	var wg sync.WaitGroup
	next := make(chan int)
	workers := s.work
	if workers > n {
		workers = n
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
}

func summary(results []string) string {
	count := map[string]int{}
	order := []string{}
	for _, r := range results {
		if count[r] == 0 {
			order = append(order, r)
		}
		count[r]++
	}
	parts := make([]string, 0, len(order))
	for _, r := range order {
		parts = append(parts, fmt.Sprintf("%s %d", r, count[r]))
	}
	return strings.Join(parts, ", ")
}

func (s *server) tokenise(w http.ResponseWriter, r *http.Request, c *call) {
	ctx := r.Context()
	n := len(c.req.Values)
	if n == 0 || n > 10000 {
		reply(w, http.StatusBadRequest, vault.Response{Error: "between 1 and 10,000 values a call"})
		return
	}
	if c.req.Format == vault.FormatLegacy && c.kind.Legacy == nil {
		_ = s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "tokenise", Kind: c.kind.Name, N: n, Result: "refused: no legacy format"})
		reply(w, http.StatusBadRequest, vault.Response{Error: fmt.Sprintf("the %s kind has no legacy format", c.kind.Name)})
		return
	}
	out := vault.Response{Refs: make([]string, n), New: make([]bool, n), Results: make([]string, n)}
	var failed error
	var fmu sync.Mutex
	// The kind is held for reading from the first lookup to the log's entry:
	// rotation switches keys only between calls, and a guarded delete
	// (deleteOwned) reads the log knowing every key this call hands out is
	// already named in it.
	mu := s.kindMu[c.kind.Name]
	mu.RLock()
	defer mu.RUnlock()
	s.each(n, func(i int) {
		ref, made, res, err := s.tokeniseOne(ctx, c, c.req.Values[i])
		out.Refs[i], out.New[i], out.Results[i] = ref, made, res
		if err != nil {
			fmu.Lock()
			failed = err
			fmu.Unlock()
		}
	})
	refs := make([]string, 0, n)
	for _, ref := range out.Refs {
		if ref != "" {
			refs = append(refs, ref)
		}
	}
	res := summary(out.Results)
	if failed != nil {
		res += "; failed: " + failed.Error()
	}
	if err := s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "tokenise", Kind: c.kind.Name, Refs: refs, N: n, Result: res}); err != nil || failed != nil {
		if err == nil {
			err = failed
		}
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	reply(w, http.StatusOK, out)
}

// tokeniseOne returns the value's reference key, making the record if the
// value is new. The caller holds the kind for reading.
func (s *server) tokeniseOne(ctx context.Context, c *call, v string) (ref string, made bool, result string, err error) {
	norm, err := c.kind.Accept(v)
	if err != nil {
		return "", false, vault.ResultRefused, nil
	}
	idxKey, dataKey := s.currentKey(c.kind.Name, "index"), s.currentKey(c.kind.Name, "data")
	idx, all, err := s.indexes(c.kind.Name, norm)
	if err != nil {
		return "", false, "", err
	}
	if ref, err = s.lookup(ctx, c.kind.Name, all); err != nil || ref != "" {
		return ref, false, vault.ResultDone, err
	}
	for try := 0; try < 5; try++ {
		ref, err = c.kind.NewRef(c.req.Format, s.tok.Random)
		if err != nil {
			return "", false, "", err
		}
		nonce, ct, err := s.tok.Encrypt(dataKey, vault.AAD(c.kind.Name, ref), []byte(norm))
		if err != nil {
			return "", false, "", err
		}
		var got string
		err = s.db.QueryRow(ctx, `INSERT INTO vault.records (ref, kind, idx, nonce, ct, data_key, index_key, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING RETURNING ref`,
			ref, c.kind.Name, idx, nonce, ct, dataKey, idxKey, c.actor).Scan(&got)
		if err == nil {
			return got, true, vault.ResultDone, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", false, "", err
		}
		// Either the same value arrived at once from another call, or the
		// reference key was drawn before: the first is its answer.
		if ref, err = s.lookup(ctx, c.kind.Name, all); err != nil || ref != "" {
			return ref, false, vault.ResultDone, err
		}
	}
	return "", false, "", errors.New("five reference keys in a row were taken")
}

// lookup finds the record whose index is any of idxs (a value's index under
// each live index key).
func (s *server) lookup(ctx context.Context, kind string, idxs [][]byte) (string, error) {
	var ref string
	err := s.db.QueryRow(ctx, `SELECT ref FROM vault.records WHERE kind = $1 AND idx = ANY($2) LIMIT 1`, kind, idxs).Scan(&ref)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return ref, err
}

func (s *server) find(w http.ResponseWriter, r *http.Request, c *call) {
	ctx := r.Context()
	n := len(c.req.Values)
	if n == 0 || n > 10000 {
		reply(w, http.StatusBadRequest, vault.Response{Error: "between 1 and 10,000 values a call"})
		return
	}
	out := vault.Response{Refs: make([]string, n), Results: make([]string, n)}
	var failed error
	var fmu sync.Mutex
	// As tokenise: a key found is named in the log before a guarded delete
	// can look.
	mu := s.kindMu[c.kind.Name]
	mu.RLock()
	defer mu.RUnlock()
	s.each(n, func(i int) {
		norm, err := c.kind.Accept(c.req.Values[i])
		if err != nil {
			out.Results[i] = vault.ResultRefused
			return
		}
		_, all, err := s.indexes(c.kind.Name, norm)
		if err == nil {
			out.Refs[i], err = s.lookup(ctx, c.kind.Name, all)
		}
		switch {
		case err != nil:
			fmu.Lock()
			failed = err
			fmu.Unlock()
		case out.Refs[i] == "":
			out.Results[i] = vault.ResultNotFound
		default:
			out.Results[i] = vault.ResultDone
		}
	})
	refs := make([]string, 0, n)
	for _, ref := range out.Refs {
		if ref != "" {
			refs = append(refs, ref)
		}
	}
	if err := s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "find", Kind: c.kind.Name, Refs: refs, N: n, Result: summary(out.Results)}); err != nil || failed != nil {
		if err == nil {
			err = failed
		}
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	reply(w, http.StatusOK, out)
}

func (s *server) detokenise(w http.ResponseWriter, r *http.Request, c *call) {
	ctx := r.Context()
	n := len(c.req.Refs)
	purpose := strings.TrimSpace(c.req.Purpose)
	if purpose == "" {
		_ = s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "detokenise", Kind: c.kind.Name, Refs: c.req.Refs, N: n, Result: "refused: no purpose"})
		reply(w, http.StatusBadRequest, vault.Response{Error: "detokenising needs a purpose"})
		return
	}
	if n == 0 || n > 1000 {
		reply(w, http.StatusBadRequest, vault.Response{Error: "between 1 and 1,000 reference keys a call"})
		return
	}
	out := vault.Response{Values: make([]string, n), Results: make([]string, n)}
	var failed error
	var fmu sync.Mutex
	s.each(n, func(i int) {
		v, res, err := s.readOne(ctx, c.kind.Name, c.req.Refs[i])
		out.Values[i], out.Results[i] = v, res
		if err != nil {
			fmu.Lock()
			failed = err
			fmu.Unlock()
		}
	})
	// The log is written before a value leaves: a value nobody logged is never
	// returned.
	if err := s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "detokenise", Kind: c.kind.Name, Refs: c.req.Refs, N: n, Purpose: purpose, Result: summary(out.Results)}); err != nil || failed != nil {
		if err == nil {
			err = failed
		}
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	reply(w, http.StatusOK, out)
}

// readOne decrypts one record; a record moved by a rotation between reading
// it and decrypting it is read again once.
func (s *server) readOne(ctx context.Context, kind, ref string) (string, string, error) {
	for try := 0; try < 2; try++ {
		var nonce, ct []byte
		var key string
		err := s.db.QueryRow(ctx, `SELECT nonce, ct, data_key FROM vault.records WHERE kind = $1 AND ref = $2`, kind, ref).Scan(&nonce, &ct, &key)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", vault.ResultNotFound, nil
		}
		if err != nil {
			return "", "", err
		}
		v, err := s.tok.Decrypt(key, nonce, vault.AAD(kind, ref), ct)
		if errors.Is(err, hsm.ErrNotVerified) {
			return "", vault.ResultNotVerified, nil
		}
		if err != nil && try == 0 && strings.Contains(err.Error(), "destroyed") {
			continue
		}
		if err != nil {
			return "", "", err
		}
		return string(v), vault.ResultDone, nil
	}
	return "", "", errors.New("the record kept moving")
}

func (s *server) delete(w http.ResponseWriter, r *http.Request, c *call) {
	ctx := r.Context()
	n := len(c.req.Refs)
	if n == 0 || n > 1000 {
		reply(w, http.StatusBadRequest, vault.Response{Error: "between 1 and 1,000 reference keys a call"})
		return
	}
	if len(c.req.Owners) > 0 {
		s.deleteOwned(w, r, c)
		return
	}
	out := vault.Response{Results: make([]string, n)}
	for i, ref := range c.req.Refs {
		tag, err := s.db.Exec(ctx, `DELETE FROM vault.records WHERE kind = $1 AND ref = $2`, c.kind.Name, ref)
		if err != nil {
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
		if tag.RowsAffected() == 1 {
			out.Results[i] = vault.ResultDone
		} else {
			out.Results[i] = vault.ResultNotFound
		}
	}
	if err := s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "delete", Kind: c.kind.Name, Refs: c.req.Refs, N: n, Purpose: strings.TrimSpace(c.req.Purpose), Result: summary(out.Results)}); err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	reply(w, http.StatusOK, out)
}

// deleteOwned is a delete guarded for orphans (point 13.3): reference keys a
// migration made on a branch that is gone. A key is deleted only when its
// record was made by one of the owners (the migration's actors) and no entry
// in the access log, by anyone else, names it: a key someone else was handed
// or read back is in use, wherever it is kept, and stays. The kind is held for
// writing, so no tokenise or find can hand a key out between the log's read
// and the delete.
func (s *server) deleteOwned(w http.ResponseWriter, r *http.Request, c *call) {
	ctx := r.Context()
	refs, owners := c.req.Refs, c.req.Owners
	for _, o := range owners {
		if strings.TrimSpace(o) == "" || len(o) > 200 {
			reply(w, http.StatusBadRequest, vault.Response{Error: "an owner is an actor, 1 to 200 characters"})
			return
		}
	}
	mu := s.kindMu[c.kind.Name]
	mu.Lock()
	defer mu.Unlock()
	used := map[string]bool{}
	rows, err := s.db.Query(ctx, `SELECT DISTINCT x FROM vault.access_log l CROSS JOIN LATERAL unnest(l.refs) AS x
		WHERE l.refs && $1::text[] AND x = ANY($1::text[]) AND l.actor <> ALL($2::text[])`, refs, owners)
	if err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	for rows.Next() {
		var x string
		if err := rows.Scan(&x); err != nil {
			rows.Close()
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
		used[x] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	out := vault.Response{Results: make([]string, len(refs))}
	var gone []string
	for i, ref := range refs {
		if used[ref] {
			out.Results[i] = vault.ResultInUse
			continue
		}
		var by string
		err := s.db.QueryRow(ctx, `DELETE FROM vault.records WHERE kind = $1 AND ref = $2 AND created_by = ANY($3::text[]) RETURNING created_by`,
			c.kind.Name, ref, owners).Scan(&by)
		switch {
		case err == nil:
			out.Results[i] = vault.ResultDone
			gone = append(gone, ref)
		case errors.Is(err, pgx.ErrNoRows):
			var exists bool
			if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM vault.records WHERE kind = $1 AND ref = $2)`, c.kind.Name, ref).Scan(&exists); err != nil {
				reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
				return
			}
			out.Results[i] = vault.ResultNotFound
			if exists {
				out.Results[i] = vault.ResultNotTheirs
			}
		default:
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
	}
	if err := s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "delete", Kind: c.kind.Name, Refs: gone, N: len(refs),
		Purpose: c.req.Purpose, Result: summary(out.Results)}); err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	reply(w, http.StatusOK, out)
}

// rotate moves a kind's records to a new data key, in batches, while the vault
// keeps answering, then destroys the old key in the token (design, section 6).
// rotate makes a kind's data key (the default) or index key anew, moves every
// record to it while the vault keeps answering, then destroys the old key in
// the token (design, sections 6 and 12; 13.4). Either way the kind's rotation
// lock is held, so its data and index keys never rotate at once.
func (s *server) rotate(w http.ResponseWriter, r *http.Request, c *call) {
	switch c.req.Key {
	case "", "data", "index":
	default:
		reply(w, http.StatusBadRequest, vault.Response{Error: fmt.Sprintf("no key %q to rotate: data or index", c.req.Key)})
		return
	}
	rm := s.rotMu[c.kind.Name]
	if !rm.TryLock() {
		reply(w, http.StatusConflict, vault.Response{Error: "a rotation of " + c.kind.Name + " is already running"})
		return
	}
	defer rm.Unlock()
	if c.req.Key == "index" {
		s.rotateIndex(w, r, c)
		return
	}
	s.rotateData(w, r, c)
}

func (s *server) rotateData(w http.ResponseWriter, r *http.Request, c *call) {
	ctx := context.WithoutCancel(r.Context())
	kind := c.kind.Name
	start := time.Now()
	var gen int
	if err := s.db.QueryRow(ctx, `SELECT coalesce(max(gen), 0) + 1 FROM vault.keys WHERE kind = $1 AND role = 'data'`, kind).Scan(&gen); err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	label := fmt.Sprintf("vault-%s-data-%d", kind, gen)
	if err := s.makeKey(ctx, kind, "data", label, gen, false); err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	// Switch: wait for every tokenise holding the old key to insert its
	// record, then make the new key current.
	mu := s.kindMu[kind]
	mu.Lock()
	_, err := s.db.Exec(ctx, `UPDATE vault.keys SET current = (label = $2) WHERE kind = $1 AND role = 'data'`, kind, label)
	if err == nil {
		s.keyMu.Lock()
		s.current[kind]["data"] = label
		s.keyMu.Unlock()
	}
	mu.Unlock()
	if err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	moved := 0
	for {
		rows, err := s.db.Query(ctx, `SELECT ref, nonce, ct, data_key FROM vault.records WHERE kind = $1 AND data_key <> $2 LIMIT 2000`, kind, label)
		if err != nil {
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
		type rec struct {
			ref, key  string
			nonce, ct []byte
		}
		var batch []rec
		for rows.Next() {
			var x rec
			if err := rows.Scan(&x.ref, &x.nonce, &x.ct, &x.key); err != nil {
				rows.Close()
				reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
				return
			}
			batch = append(batch, x)
		}
		rows.Close()
		if len(batch) == 0 {
			break
		}
		var failed error
		var fmu sync.Mutex
		s.each(len(batch), func(i int) {
			x := batch[i]
			aad := vault.AAD(kind, x.ref)
			plain, err := s.tok.Decrypt(x.key, x.nonce, aad, x.ct)
			if err == nil {
				var nonce, ct []byte
				if nonce, ct, err = s.tok.Encrypt(label, aad, plain); err == nil {
					_, err = s.db.Exec(ctx, `UPDATE vault.records SET nonce = $3, ct = $4, data_key = $5, updated_at = now()
						WHERE ref = $1 AND data_key = $2`, x.ref, x.key, nonce, ct, label)
				}
			}
			if err != nil {
				fmu.Lock()
				failed = fmt.Errorf("%s: %w", x.ref, err)
				fmu.Unlock()
			}
		})
		if failed != nil {
			_ = s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "rotate", Kind: kind, N: moved, Purpose: "data key", Result: "failed: " + failed.Error()})
			reply(w, http.StatusInternalServerError, vault.Response{Error: failed.Error() + " (run it again: records already moved stay moved)"})
			return
		}
		moved += len(batch)
	}
	rows, err := s.db.Query(ctx, `SELECT label FROM vault.keys WHERE kind = $1 AND role = 'data' AND label <> $2 AND destroyed_at IS NULL`, kind, label)
	if err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	var old []string
	for rows.Next() {
		var l string
		if rows.Scan(&l) == nil {
			old = append(old, l)
		}
	}
	rows.Close()
	for _, l := range old {
		if err := s.tok.Destroy(l); err != nil {
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
		_, _ = s.db.Exec(ctx, `UPDATE vault.keys SET destroyed_at = now() WHERE label = $1`, l)
	}
	res := fmt.Sprintf("done: %d records moved to %s in %s; destroyed %s", moved, label, time.Since(start).Round(time.Millisecond), strings.Join(old, ", "))
	if err := s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "rotate", Kind: kind, N: moved, Purpose: "data key", Result: res}); err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	reply(w, http.StatusOK, vault.Response{Results: []string{res}})
}

// rotateIndex makes the kind's index key anew. From the switch, new records
// are indexed under the new key, and tokenise and find look under the new
// and the old (indexes), so a value is found throughout; each record is
// indexed again from its decrypted value, then the old key is destroyed. The
// caller holds the kind's rotation lock.
func (s *server) rotateIndex(w http.ResponseWriter, r *http.Request, c *call) {
	ctx := context.WithoutCancel(r.Context())
	kind := c.kind.Name
	start := time.Now()
	fail := func(moved int, err error) {
		_ = s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "rotate", Kind: kind, N: moved, Purpose: "index key", Result: "failed: " + err.Error()})
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error() + " (run it again: records already moved stay moved)"})
	}
	var gen int
	if err := s.db.QueryRow(ctx, `SELECT coalesce(max(gen), 0) + 1 FROM vault.keys WHERE kind = $1 AND role = 'index'`, kind).Scan(&gen); err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	label := fmt.Sprintf("vault-%s-index-%d", kind, gen)
	if err := s.makeKey(ctx, kind, "index", label, gen, false); err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	// Switch, between calls: the old current key joins the retired ones.
	mu := s.kindMu[kind]
	mu.Lock()
	_, err := s.db.Exec(ctx, `UPDATE vault.keys SET current = (label = $2) WHERE kind = $1 AND role = 'index'`, kind, label)
	if err == nil {
		s.keyMu.Lock()
		if old := s.current[kind]["index"]; old != label {
			s.retired[kind] = append(s.retired[kind], old)
		}
		s.current[kind]["index"] = label
		s.keyMu.Unlock()
	}
	mu.Unlock()
	if err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	moved := 0
	for {
		rows, err := s.db.Query(ctx, `SELECT ref, nonce, ct, data_key, index_key FROM vault.records WHERE kind = $1 AND index_key <> $2 LIMIT 2000`, kind, label)
		if err != nil {
			fail(moved, err)
			return
		}
		type rec struct {
			ref, key, old string
			nonce, ct     []byte
		}
		var batch []rec
		for rows.Next() {
			var x rec
			if err := rows.Scan(&x.ref, &x.nonce, &x.ct, &x.key, &x.old); err != nil {
				rows.Close()
				fail(moved, err)
				return
			}
			batch = append(batch, x)
		}
		rows.Close()
		if len(batch) == 0 {
			break
		}
		var failed error
		var fmu sync.Mutex
		s.each(len(batch), func(i int) {
			x := batch[i]
			plain, err := s.tok.Decrypt(x.key, x.nonce, vault.AAD(kind, x.ref), x.ct)
			if err == nil {
				var idx []byte
				if idx, err = s.tok.HMAC(label, plain); err == nil {
					// Only where the record is still as read: an update or a
					// delete meanwhile has written it under the new key, or
					// removed it.
					_, err = s.db.Exec(ctx, `UPDATE vault.records SET idx = $3, index_key = $4
						WHERE ref = $1 AND index_key = $2`, x.ref, x.old, idx, label)
				}
			}
			if err != nil {
				fmu.Lock()
				failed = fmt.Errorf("%s: %w", x.ref, err)
				fmu.Unlock()
			}
		})
		if failed != nil {
			fail(moved, failed)
			return
		}
		moved += len(batch)
	}
	// No call looks under the old keys once they are no longer retired; one
	// in flight holds the kind for reading, so the switch waits for it.
	mu.Lock()
	s.keyMu.Lock()
	old := s.retired[kind]
	s.retired[kind] = nil
	s.keyMu.Unlock()
	mu.Unlock()
	for _, l := range old {
		if err := s.tok.Destroy(l); err != nil {
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
		_, _ = s.db.Exec(ctx, `UPDATE vault.keys SET destroyed_at = now() WHERE label = $1`, l)
	}
	res := fmt.Sprintf("done: %d records indexed under %s in %s; destroyed %s", moved, label, time.Since(start).Round(time.Millisecond), strings.Join(old, ", "))
	if err := s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "rotate", Kind: kind, N: moved, Purpose: "index key", Result: res}); err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	reply(w, http.StatusOK, vault.Response{Results: []string{res}})
}

// update replaces the values under existing reference keys (design, section
// 12; 13.4): Refs[i] gets Values[i], which must pass the kind's check. The
// key stays; the old ciphertext stays only in the database's history and
// backups, under a data key the next rotation destroys. A value another key
// already holds is refused and that key named, since a value has one key. The
// kind is held for writing: no tokenise or find can hand out a key whose
// value is changing.
func (s *server) update(w http.ResponseWriter, r *http.Request, c *call) {
	ctx := r.Context()
	n := len(c.req.Refs)
	purpose := strings.TrimSpace(c.req.Purpose)
	if purpose == "" {
		_ = s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "update", Kind: c.kind.Name, Refs: c.req.Refs, N: n, Result: "refused: no purpose"})
		reply(w, http.StatusBadRequest, vault.Response{Error: "an update needs a purpose"})
		return
	}
	if n == 0 || n > 1000 || len(c.req.Values) != n {
		reply(w, http.StatusBadRequest, vault.Response{Error: "between 1 and 1,000 reference keys a call, each with its new value"})
		return
	}
	mu := s.kindMu[c.kind.Name]
	mu.Lock()
	defer mu.Unlock()
	out := vault.Response{Refs: make([]string, n), Results: make([]string, n)}
	var failed error
	for i, ref := range c.req.Refs {
		res, other, err := s.updateOne(ctx, c.kind, ref, c.req.Values[i])
		out.Results[i], out.Refs[i] = res, other
		if err != nil {
			failed = fmt.Errorf("%s: %w", ref, err)
			break
		}
	}
	res := summary(out.Results)
	if failed != nil {
		res += "; failed: " + failed.Error()
	}
	if err := s.record(ctx, w, vault.Entry{Actor: c.actor, Action: "update", Kind: c.kind.Name, Refs: c.req.Refs, N: n, Purpose: purpose, Result: res}); err != nil || failed != nil {
		if err == nil {
			err = failed
		}
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	reply(w, http.StatusOK, out)
}

// updateOne writes one record's new value; other is the key that holds the
// value already, when it is not ref. The caller holds the kind for writing.
func (s *server) updateOne(ctx context.Context, k *vault.Kind, ref, v string) (result, other string, err error) {
	norm, err := k.Accept(v)
	if err != nil {
		return vault.ResultRefused, "", nil
	}
	var exists bool
	if err := s.db.QueryRow(ctx, `SELECT true FROM vault.records WHERE kind = $1 AND ref = $2`, k.Name, ref).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return vault.ResultNotFound, "", nil
	} else if err != nil {
		return "", "", err
	}
	idx, all, err := s.indexes(k.Name, norm)
	if err != nil {
		return "", "", err
	}
	holder, err := s.lookup(ctx, k.Name, all)
	if err != nil {
		return "", "", err
	}
	switch holder {
	case "":
	case ref:
		return vault.ResultUnchanged, "", nil
	default:
		return vault.ResultTaken, holder, nil
	}
	dataKey, idxKey := s.currentKey(k.Name, "data"), s.currentKey(k.Name, "index")
	nonce, ct, err := s.tok.Encrypt(dataKey, vault.AAD(k.Name, ref), []byte(norm))
	if err != nil {
		return "", "", err
	}
	tag, err := s.db.Exec(ctx, `UPDATE vault.records SET idx = $3, index_key = $4, nonce = $5, ct = $6, data_key = $7, updated_at = now()
		WHERE kind = $1 AND ref = $2`, k.Name, ref, idx, idxKey, nonce, ct, dataKey)
	if err != nil {
		return "", "", err
	}
	if tag.RowsAffected() == 0 {
		return vault.ResultNotFound, "", nil
	}
	return vault.ResultDone, "", nil
}

func (s *server) status(w http.ResponseWriter, r *http.Request, c *call) {
	ctx := r.Context()
	var st vault.Status
	info := s.tok.Info()
	st.Token.Label, st.Token.Maker, st.Token.Model, st.Token.Serial, st.Token.Software = info.Label, info.Maker, info.Model, info.Serial, info.Software()
	for _, k := range vault.Kinds() {
		ks := vault.KindStatus{Name: k.Name, Prefix: k.Prefix, Rules: k.Rules, HSMRequired: k.HSMRequired}
		switch {
		case k.HSMRequired && info.Software():
			ks.Compliant = "no: software token (trials and testing only)"
		case k.HSMRequired:
			ks.Compliant = "HSM; its certificate is declared by the customer"
		default:
			ks.Compliant = "no rules mapped"
		}
		if err := s.db.QueryRow(ctx, `SELECT count(*) FROM vault.records WHERE kind = $1`, k.Name).Scan(&ks.Records); err != nil {
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
		rows, err := s.db.Query(ctx, `SELECT k.label, k.role, k.current, k.destroyed_at IS NOT NULL,
			(SELECT count(*) FROM vault.records r WHERE r.data_key = k.label OR r.index_key = k.label),
			k.gen, to_char(k.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			coalesce(to_char(k.destroyed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '')
			FROM vault.keys k WHERE k.kind = $1 ORDER BY k.role, k.gen`, k.Name)
		if err != nil {
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
		for rows.Next() {
			var ky vault.KeyStatus
			if err := rows.Scan(&ky.Label, &ky.Role, &ky.Current, &ky.Destroyed, &ky.Records, &ky.Gen, &ky.Created, &ky.DestroyedAt); err != nil {
				rows.Close()
				reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
				return
			}
			ks.Keys = append(ks.Keys, ky)
		}
		rows.Close()
		for i := range ks.Keys {
			ky := &ks.Keys[i]
			ky.Uses = s.uses(ky.Label)
			if ky.Destroyed {
				continue
			}
			a, err := s.tok.Attrs(ky.Label)
			if err != nil {
				reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
				return
			}
			ky.Sensitive, ky.Extractable, ky.AlwaysSensitive, ky.NeverExtractable, ky.Local = a.Sensitive, a.Extractable, a.AlwaysSensitive, a.NeverExtractable, a.Local
		}
		st.Kinds = append(st.Kinds, ks)
	}
	rows, err := s.db.Query(ctx, `SELECT seq, at_us, actor, action, kind, refs, n, purpose, result, prev, hash FROM vault.access_log ORDER BY seq`)
	if err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	var entries []vault.Entry
	for rows.Next() {
		var e vault.Entry
		if err := rows.Scan(&e.Seq, &e.AtMicro, &e.Actor, &e.Action, &e.Kind, &e.Refs, &e.N, &e.Purpose, &e.Result, &e.Prev, &e.Hash); err != nil {
			rows.Close()
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
		entries = append(entries, e)
	}
	rows.Close()
	st.Log.Entries = int64(len(entries))
	st.Log.BrokenAt = vault.Verify(entries)
	if n := len(entries); n > 0 {
		st.Log.Head = vault.FormatHead(entries[n-1].Seq, entries[n-1].Hash)
	}
	s.logMu.Lock()
	last := s.lastSeq
	s.logMu.Unlock()
	if st.Log.BrokenAt == 0 && st.Log.Entries < last {
		// Entries cut off the end leave a chain that verifies; the service
		// remembers how long it was.
		st.Log.BrokenAt = st.Log.Entries + 1
	}
	reply(w, http.StatusOK, st)
}

// logAt answers the hash of one entry of the access log, so the engine can
// check a head it recorded earlier against the log as it is now.
func (s *server) logAt(w http.ResponseWriter, r *http.Request, c *call) {
	seq, err := strconv.ParseInt(r.URL.Query().Get("seq"), 10, 64)
	if err != nil || seq < 1 {
		reply(w, http.StatusBadRequest, vault.Response{Error: "seq is an entry's number"})
		return
	}
	var hash []byte
	err = s.db.QueryRow(r.Context(), `SELECT hash FROM vault.access_log WHERE seq = $1`, seq).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		reply(w, http.StatusNotFound, vault.Response{Error: "no such entry"})
		return
	}
	if err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	reply(w, http.StatusOK, vault.Response{Results: []string{vault.FormatHead(seq, hash)}})
}

// entries lists the access log, newest first: limit entries (100 by default,
// at most 1,000) before entry before, or the newest when before is 0. An
// entry names reference keys and a purpose, never a value.
func (s *server) entries(w http.ResponseWriter, r *http.Request, c *call) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	rows, err := s.db.Query(r.Context(), `SELECT seq, at_us, actor, action, kind, refs, n, purpose, result
		FROM vault.access_log WHERE ($1 = 0 OR seq < $1) ORDER BY seq DESC LIMIT $2`, before, limit)
	if err != nil {
		reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
		return
	}
	defer rows.Close()
	out := vault.Entries{Entries: []vault.LogRow{}}
	for rows.Next() {
		var e vault.LogRow
		var us int64
		if err := rows.Scan(&e.Seq, &us, &e.Actor, &e.Action, &e.Kind, &e.Refs, &e.N, &e.Purpose, &e.Result); err != nil {
			reply(w, http.StatusInternalServerError, vault.Response{Error: err.Error()})
			return
		}
		e.At = time.UnixMicro(us).UTC()
		out.Entries = append(out.Entries, e)
	}
	reply(w, http.StatusOK, out)
}
