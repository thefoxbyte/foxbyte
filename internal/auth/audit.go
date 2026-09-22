// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// The security log (audit v2 G28). The Blackbox records what happened to the
// databases; this records what happened to the doors: who signed in and who
// failed to, who made or revoked a key, whose password changed, which account
// was deleted, who was made an admin, and every request refused for lack of
// access. An auditor asks for exactly these.
//
// It is tamper-evident the same way the Blackbox is. Each event is chained to
// the one before (row_hash = sha256 over prev_hash and the event's fields),
// SQLite triggers refuse UPDATE and DELETE, and the checkpointer anchors the
// chain's head in a signed file outside the store (branch.CheckpointSecurityLog),
// so rewriting history — even recomputing every hash — breaks either the chain
// or an anchor. `fox audit verify` checks both.

// Event kinds.
const (
	EvLoginOK        = "login"
	EvLoginFailed    = "login.failed"
	EvThrottled      = "login.throttled"
	EvRegister       = "account.created"
	EvSetupRefused   = "account.setup_token_refused"
	EvOAuthRefused   = "oauth.refused"
	EvPasswordChange = "account.password_changed"
	EvPasswordReset  = "account.password_reset"
	EvAccountDeleted = "account.deleted"
	EvKeyCreated     = "key.created"
	EvKeyRevoked     = "key.revoked"
	EvAdminGranted   = "admin.granted"
	EvAdminRevoked   = "admin.revoked"
	EvOwnerChanged   = "branch.owner_changed"
	EvDenied         = "access.denied"
	EvGatewayRefused = "gateway.refused"
)

const auditSchema = `
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  prev_hash TEXT NOT NULL,
  row_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS security_events_no_update BEFORE UPDATE ON security_events
  BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS security_events_no_delete BEFORE DELETE ON security_events
  BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END;`

// SecurityEvent is one entry of the security log.
type SecurityEvent struct {
	ID       int64  `json:"id"`
	At       string `json:"at"` // RFC 3339, UTC, nanoseconds
	Kind     string `json:"kind"`
	Actor    string `json:"actor,omitempty"`
	Subject  string `json:"subject,omitempty"`
	IP       string `json:"ip,omitempty"`
	Detail   string `json:"detail,omitempty"`
	PrevHash string `json:"prev_hash"`
	RowHash  string `json:"row_hash"`
}

// EventHash is an event's row hash: SHA-256 over prev_hash and its fields,
// joined with "|", hex.
func EventHash(e SecurityEvent) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		e.PrevHash, strconv.FormatInt(e.ID, 10), e.At, e.Kind, e.Actor, e.Subject, e.IP, e.Detail,
	}, "|")))
	return hex.EncodeToString(h[:])
}

// Audit appends an event. It never fails the action it records: a store that
// cannot be written is logged, and the action goes on — refusing sign-ins
// because the log is busy would turn the log into an outage.
func (s *Store) Audit(kind, actor, subject, ip, detail string) {
	if s == nil || s.db == nil {
		return
	}
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if err = s.appendEvent(kind, actor, subject, ip, detail); err == nil || !isBusy(err) {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 20 * time.Millisecond)
	}
	if err != nil {
		log.Printf("security log: could not record %s (%s): %v", kind, subject, err)
	}
}

// appendEvent chains one event onto the log, under SQLite's write lock so two
// processes cannot both chain onto the same head.
func (s *Store) appendEvent(kind, actor, subject, ip, detail string) error {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()
	e := SecurityEvent{At: time.Now().UTC().Format(time.RFC3339Nano), Kind: kind,
		Actor: actor, Subject: clip(subject), IP: ip, Detail: clip(detail)}
	err = conn.QueryRowContext(ctx, `SELECT id, row_hash FROM security_events ORDER BY id DESC LIMIT 1`).Scan(&e.ID, &e.PrevHash)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	e.ID++
	e.RowHash = EventHash(e)
	if _, err := conn.ExecContext(ctx, `INSERT INTO security_events(id,at,kind,actor,subject,ip,detail,prev_hash,row_hash)
		VALUES(?,?,?,?,?,?,?,?,?)`, e.ID, e.At, e.Kind, e.Actor, e.Subject, e.IP, e.Detail, e.PrevHash, e.RowHash); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	commit = true
	return nil
}

func clip(s string) string {
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}

// SecurityEvents returns events with id > after, oldest first, at most limit
// (0: all).
func (s *Store) SecurityEvents(after int64, limit int) ([]SecurityEvent, error) {
	q := `SELECT id,at,kind,actor,subject,ip,detail,prev_hash,row_hash FROM security_events WHERE id > ? ORDER BY id`
	args := []any{after}
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecurityEvent{}
	for rows.Next() {
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Kind, &e.Actor, &e.Subject, &e.IP, &e.Detail, &e.PrevHash, &e.RowHash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecentSecurityEvents returns the newest events, newest first.
func (s *Store) RecentSecurityEvents(limit int) ([]SecurityEvent, error) {
	var maxID int64
	_ = s.db.QueryRow(`SELECT coalesce(max(id),0) FROM security_events`).Scan(&maxID)
	after := maxID - int64(limit)
	if after < 0 {
		after = 0
	}
	evs, err := s.SecurityEvents(after, 0)
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	return evs, err
}

// CheckEventChain recomputes the chain. It returns the id of the first event
// that does not match, or 0 when all do.
func CheckEventChain(evs []SecurityEvent) (int64, string) {
	prev := ""
	var lastID int64
	for _, e := range evs {
		switch {
		case e.ID != lastID+1:
			return e.ID, fmt.Sprintf("event %d follows %d: events are missing", e.ID, lastID)
		case e.PrevHash != prev:
			return e.ID, fmt.Sprintf("event %d does not chain to the event before it", e.ID)
		case EventHash(e) != e.RowHash:
			return e.ID, fmt.Sprintf("event %d has been changed", e.ID)
		}
		prev, lastID = e.RowHash, e.ID
	}
	return 0, ""
}
