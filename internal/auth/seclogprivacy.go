// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Privacy for the security log (findings PRIV-4 and PRIV-7): what it keeps
// about a person once their account is gone, and for how long it keeps
// anything at all.
//
// The log is a hash chain (audit.go), and each event's hash covers its raw
// fields, emails and addresses included. Rewriting those hashes would break
// every anchor already signed outside the store, so neither operation here
// touches one. Instead:
//
//   - Pseudonymising rewrites an event's actor, subject, IP and detail in place
//     and leaves its row_hash, and so the chain and every anchor, exactly as it
//     was. The original hash can no longer be recomputed, because the values it
//     covered are gone; what vouches for the event from then on is a seal: a
//     hash over the event's original row_hash and its fields as they now stand,
//     written by the pseudonymisation event that changed it. That event is
//     itself appended to the chain, and its detail carries a digest of every
//     seal it wrote, so a seal cannot be added, changed or removed afterwards
//     without breaking an event the anchors cover. This works the same for
//     events written before this file existed: their hashes are left alone.
//
//   - Pruning deletes a run of the oldest events and appends one event that
//     says where the log now starts and the hash the first kept event chains
//     from. A verifier starts from there instead of from the empty hash.
//
// The table's triggers still refuse every UPDATE and DELETE except these two,
// which unlock them only inside their own transaction (security_log_unlock is
// written and emptied before the commit, so nothing outside ever sees it set).
// That is a guard against mistakes, not against someone with the file: the
// chain, the seals and the anchors are what catch that.

// Event kinds this file writes. Kept here rather than with the others in
// audit.go: they belong to the log's own upkeep, not to anything a person did
// through a door.
const (
	// EvSecurityLogPseudonymised: a deleted account's email and addresses were
	// replaced by its pseudonym. Subject is the pseudonym, never the email.
	EvSecurityLogPseudonymised = "security-log.pseudonymised"
	// EvSecurityLogPruned: events older than the retention were removed.
	// Subject is the id of the last one removed; detail names the hash the
	// first kept event chains from.
	EvSecurityLogPruned = "security-log.pruned"
	// EvSecurityLogPseudonymLookup: someone computed the pseudonym of an
	// email, to find that person's events. Subject is the pseudonym.
	EvSecurityLogPseudonymLookup = "security-log.pseudonym_lookup"
)

// EventSeal vouches for an event whose fields were pseudonymised: Hash covers
// the event's original row_hash and its fields as they now are, and By is the
// pseudonymisation event that wrote it.
type EventSeal struct {
	Event int64  `json:"event"`
	By    int64  `json:"by"`
	Hash  string `json:"hash"`
}

// securityPrivacySchema is created by migrateSecurityLogPrivacy. The seals are
// per node, like the log they vouch for, so they are not part of the document
// an HA standby is sent (shared.go).
const securityPrivacySchema = `
CREATE TABLE IF NOT EXISTS security_event_seals (
  event_id INTEGER NOT NULL,
  by_event INTEGER NOT NULL,
  seal TEXT NOT NULL,
  PRIMARY KEY (event_id, by_event)
);
CREATE INDEX IF NOT EXISTS security_event_seals_by ON security_event_seals(by_event);
CREATE TABLE IF NOT EXISTS security_log_unlock (op TEXT NOT NULL);`

// The triggers that keep the log append-only, now with the two exceptions.
// An update may only change the four fields a person's data can be in, and
// only while pseudonymisation holds the unlock; ids, times, kinds and hashes
// can never change.
const securityLogTriggers = `
DROP TRIGGER IF EXISTS security_events_no_update;
DROP TRIGGER IF EXISTS security_events_no_delete;
CREATE TRIGGER security_events_no_update BEFORE UPDATE ON security_events
  WHEN NOT EXISTS (SELECT 1 FROM security_log_unlock WHERE op = 'pseudonymise')
    OR NEW.id IS NOT OLD.id OR NEW.at IS NOT OLD.at OR NEW.kind IS NOT OLD.kind
    OR NEW.prev_hash IS NOT OLD.prev_hash OR NEW.row_hash IS NOT OLD.row_hash
  BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END;
CREATE TRIGGER security_events_no_delete BEFORE DELETE ON security_events
  WHEN NOT EXISTS (SELECT 1 FROM security_log_unlock WHERE op = 'prune')
  BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END;`

// migrateSecurityLogPrivacy adds the seal table and replaces the old triggers
// with the ones that allow the controlled changes. Safe to repeat: the
// triggers are only replaced while they are the old ones, so an open does not
// rewrite the schema every time.
func migrateSecurityLogPrivacy(ctx context.Context, db *sql.Conn) error {
	if _, err := db.ExecContext(ctx, securityPrivacySchema); err != nil {
		return err
	}
	// Nothing is ever committed into this table; a row left by a crash in the
	// middle of a transaction cannot exist, but clearing it costs nothing.
	if _, err := db.ExecContext(ctx, `DELETE FROM security_log_unlock`); err != nil {
		return err
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'trigger'
		AND name IN ('security_events_no_update', 'security_events_no_delete') AND sql LIKE '%security_log_unlock%'`).Scan(&n); err != nil {
		return err
	}
	if n == 2 {
		return nil
	}
	_, err := db.ExecContext(ctx, securityLogTriggers)
	return err
}

// ---- pseudonyms ----

// pseudonymKeyFile holds the install's secret for pseudonyms. It sits beside
// the store rather than in it, so a copy of the store alone does not let
// anyone test a guessed email against a pseudonym. Each HA node keeps its own,
// as it keeps its own log.
const pseudonymKeyFile = "security-log-pseudonym.key"

func (s *Store) pseudonymKey() ([]byte, error) {
	path := filepath.Join(filepath.Dir(s.cfg.DBPath), pseudonymKeyFile)
	if b, err := os.ReadFile(path); err == nil {
		k, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) < 32 {
			return nil, fmt.Errorf("the pseudonym key %s is not readable; restore it from a backup rather than replacing it, "+
				"or the same person will get a different pseudonym from here on", path)
		}
		return k, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	// O_EXCL, so two processes making it at once agree on one key: the loser
	// reads the winner's.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		return s.pseudonymKey()
	}
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(hex.EncodeToString(k) + "\n"); err != nil {
		f.Close()
		return nil, err
	}
	return k, f.Close()
}

// Pseudonym is the token that stands for an email in the security log once its
// account is deleted. The same email always gives the same token on this
// install, so an investigation can still follow one person through the log
// (and someone who already knows the email can find their events with `fox
// audit pseudonym`), but the token says nothing about the email without the
// install's key.
func (s *Store) Pseudonym(email string) (string, error) {
	k, err := s.pseudonymKey()
	if err != nil {
		return "", err
	}
	return pseudonymWith(k, "email", strings.ToLower(strings.TrimSpace(email))), nil
}

func pseudonymWith(key []byte, kind, value string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(kind + "\x00" + value))
	prefix := "person:"
	if kind == "ip" {
		prefix = "address:"
	}
	return prefix + hex.EncodeToString(m.Sum(nil))[:20]
}

// replaceEmail replaces every whole occurrence of email in s, ignoring case.
// Whole, so that removing a@x.co does not also rewrite the middle of
// aa@x.com.
func replaceEmail(s, email, token string) string {
	if email == "" {
		return s
	}
	lower := strings.ToLower(s)
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(lower[i:], email)
		if j < 0 {
			break
		}
		j += i
		end := j + len(email)
		before := j == 0 || !emailChar(lower[j-1])
		after := end == len(lower) || !emailChar(lower[end]) ||
			(lower[end] == '.' && (end+1 == len(lower) || !emailChar(lower[end+1])))
		if before && after {
			b.WriteString(s[i:j])
			b.WriteString(token)
		} else {
			b.WriteString(s[i:end])
		}
		i = end
	}
	if i == 0 {
		return s
	}
	b.WriteString(s[i:])
	return b.String()
}

func emailChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("._%+-", c) >= 0
}

// pseudonymiseEvent is what pseudonymising one email does to one event: the
// email goes wherever it appears, and the IP goes when the address was this
// person's — they acted, or nobody had signed in and they were the account
// being tried. An admin's address on an event about this person is the
// admin's, and stays.
func pseudonymiseEvent(e SecurityEvent, key []byte, email string) SecurityEvent {
	token := pseudonymWith(key, "email", email)
	theirs := strings.EqualFold(e.Actor, email) || (e.Actor == "" && strings.EqualFold(e.Subject, email))
	e.Actor = replaceEmail(e.Actor, email, token)
	e.Subject = replaceEmail(e.Subject, email, token)
	e.Detail = replaceEmail(e.Detail, email, token)
	if theirs && e.IP != "" && !strings.HasPrefix(e.IP, "address:") {
		e.IP = pseudonymWith(key, "ip", e.IP)
	}
	return e
}

// ---- seals ----

// SealHash is the seal an event gets from pseudonymisation event by.
func SealHash(e SecurityEvent, by int64) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		"seal/1", strconv.FormatInt(by, 10), e.RowHash, e.PrevHash, strconv.FormatInt(e.ID, 10),
		e.At, e.Kind, e.Actor, e.Subject, e.IP, e.Detail,
	}, "|")))
	return hex.EncodeToString(h[:])
}

// sealDigest is what a pseudonymisation event records about the seals it
// wrote: one hash over all of them, in event order.
func sealDigest(seals []EventSeal) string {
	sorted := append([]EventSeal(nil), seals...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Event < sorted[j].Event })
	h := sha256.New()
	for _, s := range sorted {
		fmt.Fprintf(h, "%d:%s\n", s.Event, s.Hash)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// EventIntact reports whether an event matches what vouches for it: its own
// hash, or, once pseudonymised, its newest seal.
func EventIntact(e SecurityEvent) bool {
	if len(e.Seals) == 0 {
		return EventHash(e) == e.RowHash
	}
	last := e.Seals[0]
	for _, s := range e.Seals[1:] {
		if s.By > last.By {
			last = s
		}
	}
	return SealHash(e, last.By) == last.Hash
}

// sealDetail is a pseudonymisation event's detail. The digest is what binds
// the seals into the chain.
func sealDetail(n int, digest string) string {
	return fmt.Sprintf("%d events pseudonymised; seals sha256:%s", n, digest)
}

func parseSealDigest(detail string) (string, bool) {
	_, d, ok := strings.Cut(detail, "seals sha256:")
	if !ok || len(d) < 64 {
		return "", false
	}
	return d[:64], true
}

// CheckSeals checks that every seal in evs was written by a pseudonymisation
// event still in the log and that each such event's seals are exactly the ones
// it recorded. Each seal's own hash is checked with the chain (EventIntact).
func CheckSeals(evs []SecurityEvent) []string {
	var problems []string
	byID := map[int64]SecurityEvent{}
	for _, e := range evs {
		byID[e.ID] = e
	}
	for _, e := range evs {
		if e.Kind == EvSecurityLogPseudonymised {
			want, ok := parseSealDigest(e.Detail)
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("event %d does not say which seals it wrote", e.ID))
			case sealDigest(e.Issued) != want:
				problems = append(problems, fmt.Sprintf("the seals written by event %d have been changed", e.ID))
			}
		}
		for _, s := range e.Seals {
			if by, ok := byID[s.By]; !ok || by.Kind != EvSecurityLogPseudonymised {
				problems = append(problems, fmt.Sprintf("event %d carries a seal from event %d, which did not write one", e.ID, s.By))
			}
		}
	}
	return problems
}

// attachSeals fills in, for each event, the seals that vouch for it and the
// seals it wrote, so the events alone are enough to verify them.
func (s *Store) attachSeals(evs []SecurityEvent) error {
	if len(evs) == 0 {
		return nil
	}
	lo, hi := evs[0].ID, evs[len(evs)-1].ID
	rows, err := s.db.Query(`SELECT event_id, by_event, seal FROM security_event_seals
		WHERE event_id BETWEEN ?1 AND ?2 OR by_event BETWEEN ?1 AND ?2 ORDER BY event_id, by_event`, lo, hi)
	if err != nil {
		return err
	}
	defer rows.Close()
	idx := map[int64]int{}
	for i, e := range evs {
		idx[e.ID] = i
	}
	for rows.Next() {
		var x EventSeal
		if err := rows.Scan(&x.Event, &x.By, &x.Hash); err != nil {
			return err
		}
		if i, ok := idx[x.Event]; ok {
			evs[i].Seals = append(evs[i].Seals, x)
		}
		if i, ok := idx[x.By]; ok {
			evs[i].Issued = append(evs[i].Issued, x)
		}
	}
	return rows.Err()
}

// ---- pseudonymisation ----

// PseudonymiseResult is what pseudonymising a deleted account did.
type PseudonymiseResult struct {
	Pseudonym string `json:"pseudonym"`
	Events    int    `json:"events"`  // events whose fields changed
	EventID   int64  `json:"eventId"` // the security-log.pseudonymised event
}

// PseudonymiseSecurityLog replaces an email, and the addresses it signed in
// from, with their pseudonyms in every security-log event, and records that it
// did. actor is who asked; when it is the person themselves (deleting their
// own account) their pseudonym is recorded instead.
//
// Call it after the account is deleted and the deletion recorded, so the
// record of the deletion is pseudonymised with everything else. It refuses
// when an event it would change no longer verifies: sealing a changed event
// would vouch for the change.
func (s *Store) PseudonymiseSecurityLog(email, actor string) (PseudonymiseResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return PseudonymiseResult{}, errors.New("whose events: an email")
	}
	key, err := s.pseudonymKey()
	if err != nil {
		return PseudonymiseResult{}, err
	}
	token := pseudonymWith(key, "email", email)
	if strings.EqualFold(actor, email) {
		actor = token
	}
	var res PseudonymiseResult
	err = retryBusy(func() error {
		var e error
		res, e = s.pseudonymise(key, email, token, actor)
		return e
	})
	return res, err
}

func (s *Store) pseudonymise(key []byte, email, token, actor string) (PseudonymiseResult, error) {
	res := PseudonymiseResult{Pseudonym: token}
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	// Overwrite freed pages, so the old values do not linger in the file.
	if _, err := conn.ExecContext(ctx, "PRAGMA secure_delete = ON"); err != nil {
		return res, err
	}
	defer func() { _, _ = conn.ExecContext(ctx, "PRAGMA secure_delete = OFF") }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return res, err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()
	var head int64
	if err := conn.QueryRowContext(ctx, `SELECT coalesce(max(id), 0) FROM security_events`).Scan(&head); err != nil {
		return res, err
	}
	by := head + 1 // the event this records, appended below under the same lock

	evs, err := matchingEvents(ctx, conn, email)
	if err != nil {
		return res, err
	}
	var seals []EventSeal
	var changed []SecurityEvent
	for _, e := range evs {
		next := pseudonymiseEvent(e, key, email)
		if next.Actor == e.Actor && next.Subject == e.Subject && next.IP == e.IP && next.Detail == e.Detail {
			continue
		}
		if !EventIntact(e) {
			return res, fmt.Errorf("event %d of the security log no longer verifies, so it is not being sealed — run `fox audit verify`", e.ID)
		}
		next.Seals = nil
		seals = append(seals, EventSeal{Event: e.ID, By: by, Hash: SealHash(next, by)})
		changed = append(changed, next)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO security_log_unlock(op) VALUES('pseudonymise')`); err != nil {
		return res, err
	}
	for i, e := range changed {
		if _, err := conn.ExecContext(ctx, `UPDATE security_events SET actor=?, subject=?, ip=?, detail=? WHERE id=?`,
			e.Actor, e.Subject, e.IP, e.Detail, e.ID); err != nil {
			return res, err
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO security_event_seals(event_id, by_event, seal) VALUES(?,?,?)`,
			seals[i].Event, seals[i].By, seals[i].Hash); err != nil {
			return res, err
		}
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM security_log_unlock`); err != nil {
		return res, err
	}
	if err := appendEventIn(ctx, conn, EvSecurityLogPseudonymised, actor, token, "", sealDetail(len(seals), sealDigest(seals))); err != nil {
		return res, err
	}
	if err := conn.QueryRowContext(ctx, `SELECT max(id) FROM security_events`).Scan(&res.EventID); err != nil {
		return res, err
	}
	if res.EventID != by {
		return res, fmt.Errorf("the security log moved while it was being pseudonymised (event %d, expected %d)", res.EventID, by)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return res, err
	}
	commit = true
	res.Events = len(changed)
	return res, nil
}

// matchingEvents reads, with their seals, the events that mention an email
// anywhere it could be.
func matchingEvents(ctx context.Context, conn *sql.Conn, email string) ([]SecurityEvent, error) {
	rows, err := conn.QueryContext(ctx, `SELECT id,at,kind,actor,subject,ip,detail,prev_hash,row_hash FROM security_events
		WHERE instr(lower(actor), ?1) > 0 OR instr(lower(subject), ?1) > 0 OR instr(lower(detail), ?1) > 0 ORDER BY id`, email)
	if err != nil {
		return nil, err
	}
	var evs []SecurityEvent
	for rows.Next() {
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Kind, &e.Actor, &e.Subject, &e.IP, &e.Detail, &e.PrevHash, &e.RowHash); err != nil {
			rows.Close()
			return nil, err
		}
		evs = append(evs, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range evs {
		srows, err := conn.QueryContext(ctx, `SELECT event_id, by_event, seal FROM security_event_seals WHERE event_id=? ORDER BY by_event`, evs[i].ID)
		if err != nil {
			return nil, err
		}
		for srows.Next() {
			var x EventSeal
			if err := srows.Scan(&x.Event, &x.By, &x.Hash); err != nil {
				srows.Close()
				return nil, err
			}
			evs[i].Seals = append(evs[i].Seals, x)
		}
		srows.Close()
		if err := srows.Err(); err != nil {
			return nil, err
		}
	}
	return evs, nil
}

// ---- retention ----

// SecurityLogRetentionEnv is the setting: how long the security log keeps an
// event. Unset means for ever.
const SecurityLogRetentionEnv = "FOX_SECURITY_LOG_RETENTION"

// ParseRetention reads a retention such as "400d" or "9600h". Empty, "0",
// "off" and "keep" mean keep everything. Less than a day is refused: it is
// almost always a missing unit, and the events it would delete are the ones
// an incident needs.
func ParseRetention(v string) (time.Duration, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", "0", "off", "keep", "forever":
		return 0, nil
	}
	var d time.Duration
	if n, ok := strings.CutSuffix(v, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("%s: %q is not a number of days (say 400d)", SecurityLogRetentionEnv, v)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(v); err != nil {
			return 0, fmt.Errorf("%s: %q is not a retention (say 400d)", SecurityLogRetentionEnv, v)
		}
	}
	if d < 24*time.Hour {
		return 0, fmt.Errorf("%s: %q is less than a day; say 400d for 400 days", SecurityLogRetentionEnv, v)
	}
	return d, nil
}

// PruneResult is what a prune removed.
type PruneResult struct {
	UpTo    int64  `json:"upTo"`    // the last event removed; 0 when none were
	Head    string `json:"head"`    // its row hash, which the first kept event chains from
	Removed int    `json:"removed"` // how many went this time
	EventID int64  `json:"eventId"` // the security-log.pruned event
}

// PrunedUpTo reads where the log starts from the newest prune event in evs:
// the last id removed and the hash the next event chains from. Zero and "" when
// nothing has been pruned.
func PrunedUpTo(evs []SecurityEvent) (int64, string) {
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		if e.Kind != EvSecurityLogPruned {
			continue
		}
		n, err := strconv.ParseInt(e.Subject, 10, 64)
		_, h, ok := strings.Cut(e.Detail, "previous head ")
		if err != nil || !ok || len(h) < 64 {
			return 0, ""
		}
		return n, h[:64]
	}
	return 0, ""
}

// SecurityLogStart is where the log starts: the last id removed by retention,
// and the hash the first kept event chains from. Zero and "" when nothing has
// been pruned.
func (s *Store) SecurityLogStart() (int64, string, error) {
	var e SecurityEvent
	err := s.db.QueryRow(`SELECT id,at,kind,actor,subject,ip,detail,prev_hash,row_hash FROM security_events WHERE kind = ? ORDER BY id DESC LIMIT 1`,
		EvSecurityLogPruned).Scan(&e.ID, &e.At, &e.Kind, &e.Actor, &e.Subject, &e.IP, &e.Detail, &e.PrevHash, &e.RowHash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	n, h := PrunedUpTo([]SecurityEvent{e})
	return n, h, nil
}

// PruneSecurityEvents removes the oldest events recorded before cutoff, never
// past event maxID, and records where the log now starts. The caller passes
// the last anchored id as maxID, so what is removed was already vouched for
// outside the store and the record of the prune is the only thing new.
//
// The events removed are checked first: pruning an event that no longer
// verifies would hide that it had been changed.
func (s *Store) PruneSecurityEvents(cutoff time.Time, maxID int64, actor string) (PruneResult, error) {
	if maxID <= 0 {
		return PruneResult{}, nil
	}
	var res PruneResult
	err := retryBusy(func() error {
		var e error
		res, e = s.prune(cutoff, maxID, actor)
		return e
	})
	return res, err
}

func (s *Store) prune(cutoff time.Time, maxID int64, actor string) (PruneResult, error) {
	var res PruneResult
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return res, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA secure_delete = ON"); err != nil {
		return res, err
	}
	defer func() { _, _ = conn.ExecContext(ctx, "PRAGMA secure_delete = OFF") }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return res, err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	// Where the log starts now.
	var startID int64
	var startHash string
	{
		var last SecurityEvent
		err := conn.QueryRowContext(ctx, `SELECT id,at,kind,actor,subject,ip,detail,prev_hash,row_hash FROM security_events
			WHERE kind = ? ORDER BY id DESC LIMIT 1`, EvSecurityLogPruned).
			Scan(&last.ID, &last.At, &last.Kind, &last.Actor, &last.Subject, &last.IP, &last.Detail, &last.PrevHash, &last.RowHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return res, err
		}
		if err == nil {
			startID, startHash = PrunedUpTo([]SecurityEvent{last})
		}
	}

	// The run of oldest events before the cutoff. Times are compared as
	// times (see HasRecentEvent for why not as text), so they are read in id
	// order until the first one that is new enough.
	rows, err := conn.QueryContext(ctx, `SELECT id,at,kind,actor,subject,ip,detail,prev_hash,row_hash FROM security_events
		WHERE id <= ? ORDER BY id`, maxID)
	if err != nil {
		return res, err
	}
	var old []SecurityEvent
	for rows.Next() {
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Kind, &e.Actor, &e.Subject, &e.IP, &e.Detail, &e.PrevHash, &e.RowHash); err != nil {
			rows.Close()
			return res, err
		}
		if atOrAfter(e.At, cutoff) {
			break
		}
		old = append(old, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	if len(old) == 0 {
		return res, nil
	}
	if err := attachSealsIn(ctx, conn, old); err != nil {
		return res, err
	}
	if id, why := CheckEventChainFrom(old, startID, startHash); id != 0 {
		return res, fmt.Errorf("not pruning the security log: %s — inspect with `fox audit verify`", why)
	}
	last := old[len(old)-1]
	if _, err := conn.ExecContext(ctx, `INSERT INTO security_log_unlock(op) VALUES('prune')`); err != nil {
		return res, err
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM security_events WHERE id <= ?`, last.ID); err != nil {
		return res, err
	}
	// Seals whose writer is gone vouch for nothing that is left: every event
	// a pseudonymisation sealed came before it. Seals of removed events whose
	// writer is kept stay, because that writer's digest covers them.
	if _, err := conn.ExecContext(ctx, `DELETE FROM security_event_seals WHERE by_event <= ?`, last.ID); err != nil {
		return res, err
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM security_log_unlock`); err != nil {
		return res, err
	}
	detail := fmt.Sprintf("%d events recorded before %s removed by retention; previous head %s",
		len(old), cutoff.UTC().Format(time.RFC3339), last.RowHash)
	if err := appendEventIn(ctx, conn, EvSecurityLogPruned, actor, strconv.FormatInt(last.ID, 10), "", detail); err != nil {
		return res, err
	}
	if err := conn.QueryRowContext(ctx, `SELECT max(id) FROM security_events`).Scan(&res.EventID); err != nil {
		return res, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return res, err
	}
	commit = true
	res.UpTo, res.Head, res.Removed = last.ID, last.RowHash, len(old)
	return res, nil
}

func attachSealsIn(ctx context.Context, conn *sql.Conn, evs []SecurityEvent) error {
	lo, hi := evs[0].ID, evs[len(evs)-1].ID
	rows, err := conn.QueryContext(ctx, `SELECT event_id, by_event, seal FROM security_event_seals WHERE event_id BETWEEN ? AND ?`, lo, hi)
	if err != nil {
		return err
	}
	defer rows.Close()
	idx := map[int64]int{}
	for i, e := range evs {
		idx[e.ID] = i
	}
	for rows.Next() {
		var x EventSeal
		if err := rows.Scan(&x.Event, &x.By, &x.Hash); err != nil {
			return err
		}
		if i, ok := idx[x.Event]; ok {
			evs[i].Seals = append(evs[i].Seals, x)
		}
	}
	return rows.Err()
}

// VerifyEvents checks a whole log as read by SecurityEvents(0, 0): the chain
// from wherever retention left it starting, and the seals. It returns the
// first bad id (0 when none) and every problem found.
func VerifyEvents(evs []SecurityEvent) (int64, []string) {
	var problems []string
	upTo, head := PrunedUpTo(evs)
	first, why := CheckEventChainFrom(evs, upTo, head)
	if first != 0 {
		problems = append(problems, why)
	}
	return first, append(problems, CheckSeals(evs)...)
}
