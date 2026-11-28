// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
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
// or an anchor. `fox audit verify` checks both over every event; a checkpoint
// checks only what has been added since the last anchor (see
// branch.CheckpointSecurityLog for exactly what that does and does not cover).

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
	// EvAccountClaimed: a provider sign-in proved the email of an account that
	// was made by open sign-up, so whoever made that account loses its password,
	// sessions and keys (emailproof.go).
	EvAccountClaimed = "account.claimed"
	EvKeyCreated     = "key.created"
	EvKeyRevoked     = "key.revoked"
	EvAdminGranted   = "admin.granted"
	EvAdminRevoked   = "admin.revoked"
	// EvEditionSwitch is the console's Install button: who asked, for which
	// edition, and that the Enterprise License was accepted.
	EvEditionSwitch  = "edition.switch_started"
	EvOwnerChanged   = "branch.owner_changed"
	EvDenied         = "access.denied"
	EvGatewayRefused = "gateway.refused"
	// Realtime keys are recorded separately from EvKeyCreated so that the
	// question "who was given the change feed, and when was it taken away" has
	// an answer that does not have to be inferred from a key's scope. They are
	// also the credential most likely to be handed to something other than a
	// person, which is exactly the kind an audit asks about.
	EvRealtimeKeyCreated = "realtime.key_created"
	EvRealtimeKeyRevoked = "realtime.key_revoked"
	// Which tables stream, and who decided. The DDL that `prepare` runs is
	// already in the Blackbox with the login behind it; this is the decision
	// that asked for it, which the Blackbox cannot show because adding a table
	// to a publication is not a change to anyone's data.
	EvRealtimeEnabled  = "realtime.enabled"
	EvRealtimeDisabled = "realtime.disabled"
	EvRealtimePrepared = "realtime.prepared"
	// Promotion: who asked for a branch's changes to be applied elsewhere, and who
	// decided. The statements themselves are in the target's Blackbox; this is the
	// door they came through.
	EvChangeRequested = "branch.change_requested"
	EvChangeDecided   = "branch.change_decided"
	// A decision and an apply each record their intent before they happen and
	// their outcome after (see BeginPrivileged). EvChangeDecided stays the
	// decision's success; EvChangeApplied is the statements going in.
	EvChangeDecideStarted = "branch.change_decide_started"
	EvChangeDecideFailed  = "branch.change_decide_failed"
	EvChangeApplyStarted  = "branch.change_apply_started"
	EvChangeApplied       = "branch.change_applied"
	EvChangeApplyFailed   = "branch.change_apply_failed"
	// The intent and failure halves of the admin mutations above, whose success
	// keeps its existing kind (EvAdminGranted, EvAdminRevoked, EvAccountDeleted,
	// EvEditionSwitch), so AdminEpoch and anything reading those is unchanged.
	EvAdminGrantStarted    = "admin.grant_started"
	EvAdminGrantFailed     = "admin.grant_failed"
	EvAdminRevokeStarted   = "admin.revoke_started"
	EvAdminRevokeFailed    = "admin.revoke_failed"
	EvAccountDeleteStarted = "account.delete_started"
	EvAccountDeleteFailed  = "account.delete_failed"
	EvEditionSwitchAsked   = "edition.switch_requested"
	EvEditionSwitchFailed  = "edition.switch_failed"
	// Who may change main (mainwrite.go): the install's mode, and an account's
	// grant of write. Each an intent, then its outcome (BeginPrivileged).
	EvMainWriteModeStarted   = "main-write.mode_started"
	EvMainWriteModeSet       = "main-write.mode_set"
	EvMainWriteModeFailed    = "main-write.mode_failed"
	EvMainWriteGrantStarted  = "main-write.grant_started"
	EvMainWriteGranted       = "main-write.granted"
	EvMainWriteGrantFailed   = "main-write.grant_failed"
	EvMainWriteRevokeStarted = "main-write.revoke_started"
	EvMainWriteRevoked       = "main-write.revoked"
	EvMainWriteRevokeFailed  = "main-write.revoke_failed"
	// Licensing: when this install's paid entitlement changed, and to what.
	//
	// Recorded by the engine rather than by the command someone typed. On macOS
	// and Windows `fox license` runs on the host, which has no store and so
	// could not chain onto this log at all — but the deeper reason is that the
	// question an auditor asks is which features this engine actually honoured,
	// and that is the engine's answer to give rather than a laptop's.
	EvLicenseActivated = "license.activated"
	EvLicenseRebound   = "license.rebound"
	EvLicenseLapsed    = "license.lapsed"
	EvLicenseRemoved   = "license.removed"
	// Automatic failover: a machine took over, or declined to.
	//
	// Both are recorded, and the refusals are the reason this is in the
	// security log rather than only in a log file. "Nothing promoted it" and
	// "it decided not to, because somebody else could still reach the primary"
	// are the same outage to a user and entirely different facts to whoever
	// reviews the incident — and the second one is a split brain that did not
	// happen, which is worth being able to prove. This log stays writable on
	// each node by design (HA plan phase 2 leaves it per-node), so it is
	// readable on the machine that took over as well as the one that did not.
	EvFailoverPromoted = "ha.promoted"
	EvFailoverRefused  = "ha.promotion_refused"
	// A whole query result taken out of the database (point 1.3): who, which
	// branch, the format, how many rows, and a fingerprint of the query, never
	// its text, which can hold personal data.
	EvDataExport = "data.export"
	// Query history (points 8.1, 8.3): someone's history deleted, by them or
	// for them, and the install's settings changed. Who acted, on whose
	// history and how many entries; never the SQL itself.
	EvHistoryPurged   = "history.purged"
	EvHistorySettings = "history.settings_changed"
	// Somebody's history read by whoever runs the machine, for a request about
	// that person's own data. Reading your own is not an event.
	EvHistoryRead = "history.read"
	// Row tracking (points 5 and 6) turned on or off for a table, or for new
	// tables: who decided, on which branch.
	EvTrackingChanged = "tracking.changed"
	// A branch scanned for personal data (point 4.1): who, and how much it
	// covered. Never a value: the scan keeps none.
	EvPersonalDataScanned = "personal-data.scanned"
	// A reviewer's decision on a finding (point 4.6): confirmed, rejected or
	// reopened, and where. A location, never a value.
	EvPersonalDataMarked = "personal-data.marked"
	// Masked samples of a finding shown to a reviewer: a read of personal
	// data, masked or not, is something an auditor asks about.
	EvPersonalDataSampled = "personal-data.sampled"
	// A new column or JSON path accepted as holding nothing to classify
	// (point 4.7): who, and where.
	EvPersonalDataAccepted = "personal-data.accepted"
	// The Aadhaar exposure report run (point 4.5): which branch, and how much
	// it found, as counts. Never a place, a row or a digit.
	EvAadhaarExposure = "personal-data.aadhaar"
	// The access review report produced (point 4.8): who asked, and what it
	// covered. A report of who can reach what is itself worth knowing about.
	EvAccessReviewed = "access.reviewed"
	// The hardening report produced (point 3.2): which branch, and how it
	// stood. A list of a database's weak points is itself worth knowing about.
	EvHardeningReported = "hardening.reported"
	// A hardening fix made, or a profile applied (points 3.3, 3.4): which
	// check or profile, on which branch, what changed, and whether it held.
	EvHardeningFixed   = "hardening.fixed"
	EvHardeningProfile = "hardening.profile"
	// Masking (F5): set up on a branch, a rule set or taken off, an account
	// masked or unmasked. Who decided what a person sees of personal data is
	// something an auditor asks about.
	EvMaskSetup   = "mask.setup"
	EvMaskRule    = "mask.rule"
	EvMaskAccount = "mask.account"
	EvMaskKey     = "mask.key"
	EvMaskUnmask  = "mask.unmask"
	EvMaskBranch  = "mask.branch" // a masked branch made, opened, or refused
	// The databases' audit log (F6) turned on or off: who decided. Whoever
	// can stop the record of who did what is someone an auditor asks about.
	EvAuditLogOn  = "audit-log.on"
	EvAuditLogOff = "audit-log.off"
	// A table marked for the audit log, its mark changed, or taken off: who,
	// on which branch. Unmarking is how a table's statements stop being
	// recorded, so it is recorded here as well as by pgAudit.
	EvAuditMarked = "audit-log.marked"
	// The audit log read: who, and what they asked for. Its records name
	// logins, and whom changes were for, so reading them is recorded as
	// reading someone's query history is.
	EvAuditLogRead = "audit-log.read"
	// Forensic mode on or off (with the reason given), retention changed, and
	// a person's statement text purged: each changes what the audit log keeps
	// about people.
	EvAuditLogMode      = "audit-log.mode"
	EvAuditLogRetention = "audit-log.retention"
	EvAuditLogPurged    = "audit-log.purged"
	// Forwarding to a SIEM set, changed or stopped: where a copy of every
	// record goes, and whether statement text goes with it.
	EvAuditLogForward = "audit-log.forward"
	// The evidence export produced (F6 step 6b): for which period, and
	// whether the records went with it.
	EvAuditLogEvidence = "audit-log.evidence"
	// A session's query cancelled, or the session ended, and a table vacuumed
	// or analysed (point 12.5).
	EvSessionCancel = "session.cancel"
	EvSessionEnd    = "session.end"
	EvMaintenance   = "maintenance"
	// The vault (point 13). EvVaultCall is every call to it, with the access
	// log's head after the call, so the head is kept outside the vault, in a
	// log FoxByte already anchors.
	EvVaultSetup = "vault.setup"
	EvVaultCall  = "vault.call"
	// A grant given or revoked (13.2), and a call the engine refused before it
	// reached the vault: no grant, a masked account, a limit reached. Refusals
	// are a kind of their own so the head check reads only vault.call.
	EvVaultGrant   = "vault.grant"
	EvVaultRefused = "vault.refused"
	// A migration (13.3): a branch's Aadhaar numbers moved into the vault, or
	// previewed; and a migration's orphaned keys deleted.
	EvVaultMigrate = "vault.migrate"
	EvVaultOrphans = "vault.orphans"
	// A declaration made or withdrawn, and the evidence read (13.4b).
	EvVaultDeclare  = "vault.declare"
	EvVaultEvidence = "vault.evidence"
	// The DPDP inventory (point 11.1): an entry set or removed, where, and
	// its basis and retention. Never the purpose or the note: they are the
	// customer's free text.
	EvDPDPSet     = "dpdp.set"
	EvDPDPRemoved = "dpdp.removed"
	// Erasure requests (point 11.2, F4): made or planned again, applied, a
	// table rewritten later, withdrawn. Counts and tables, never a value or
	// a row key.
	EvErasurePlanned   = "erasure.planned"
	EvErasureApplied   = "erasure.applied"
	EvErasureRewritten = "erasure.rewritten"
	EvErasureBranch    = "erasure.branch" // one branch applied or skipped, or remade or deleted from the request
	EvErasureWithdrawn = "erasure.withdrawn"
	EvErasureRestore   = "erasure.restore"  // an admin restored past a request; the erasure is applied again
	EvErasureEvidence  = "erasure.evidence" // a request's evidence produced; whether it carried the row keys
	// Copies FoxByte makes that an erasure lists but does not reach (F4 step
	// 5): an install tar written (its path, branches and time), a Blackbox
	// exported, and the backup target moved away from (its backups stay).
	EvBackupExport = "backup.export"
	EvLedgerExport = "ledger.export"
	EvBackupTarget = "backup.target"
)

// LicenseKindPrefix is what every licence event kind starts with. The licence
// recorder asks for the last event of any of them, and does it with one
// indexed-order query rather than by reading the log back in Go.
const LicenseKindPrefix = "license."

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
  BEGIN SELECT RAISE(ABORT, 'security_events is append-only'); END;
CREATE INDEX IF NOT EXISTS security_events_kind_id ON security_events(kind, id);`

// AdminEpoch identifies the newest change to who is an admin that the security
// log holds: the id of the last admin.granted or admin.revoked event, or 0.
//
// Every process that remembers who is an admin (internal/access) compares it,
// so a grant or a revoke made anywhere — at the CLI, in the console, by another
// process — reaches all of them at once, instead of when their memory of the
// old answer expires. Indexed on (kind, id), so it stays one lookup however long
// the log grows.
func (s *Store) AdminEpoch() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT coalesce(max(id), 0) FROM security_events WHERE kind IN (?, ?)`,
		EvAdminGranted, EvAdminRevoked).Scan(&n)
	return n, err
}

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
	// Seals vouch for an event that was pseudonymised, and Issued are the
	// seals a pseudonymisation event wrote (seclogprivacy.go). Filled in by
	// SecurityEvents for verifying; not part of the event as shown.
	Seals  []EventSeal `json:"-"`
	Issued []EventSeal `json:"-"`
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
	err := retryBusy(func() error { return s.appendEvent(kind, actor, subject, ip, detail) })
	if err != nil {
		log.Printf("security log: could not record %s (%s): %v", kind, subject, err)
	}
}

// ErrSecurityLogUnavailable is returned by BeginPrivileged when the intent
// could not be recorded. The caller refuses the action.
var ErrSecurityLogUnavailable = errors.New("the security log could not record this action, so it was not done")

// Privileged is a privileged action whose intent is in the security log. Done
// records how it ended.
type Privileged struct {
	s                  *Store
	succeeded, failed  string
	actor, subject, ip string
	done               bool
}

// BeginPrivileged records that actor is about to take a privileged action
// (applying a change request, granting admin, deleting an account, …), as an
// event of kind started, and returns the handle that records the outcome.
//
// It fails closed, unlike Audit. Audit is written after an action and never
// stops it, which is right for a sign-in but means an approval or a grant could
// happen with nothing in the log at all if the store was unwritable at that
// moment. An intent written first means the log always holds at least the
// attempt; when it cannot be written, the caller does not act.
func (s *Store) BeginPrivileged(started, succeeded, failed, actor, subject, ip, detail string) (*Privileged, error) {
	if s == nil || s.db == nil {
		return nil, ErrSecurityLogUnavailable
	}
	if err := retryBusy(func() error { return s.appendEvent(started, actor, subject, ip, detail) }); err != nil {
		log.Printf("security log: could not record %s (%s), refusing it: %v", started, subject, err)
		return nil, fmt.Errorf("%w: %v", ErrSecurityLogUnavailable, err)
	}
	return &Privileged{s: s, succeeded: succeeded, failed: failed, actor: actor, subject: subject, ip: ip}, nil
}

// Done records the outcome: succeeded with detail when err is nil, otherwise
// failed with the error after detail. The action has happened (or not) by
// now, so this cannot refuse anything; a write that fails is logged, as Audit
// does. A second call does nothing, so a deferred Done after an explicit one
// is safe.
func (p *Privileged) Done(err error, detail string) {
	if p == nil || p.done {
		return
	}
	p.done = true
	if err == nil {
		p.s.Audit(p.succeeded, p.actor, p.subject, p.ip, detail)
		return
	}
	if detail != "" {
		detail += ": "
	}
	p.s.Audit(p.failed, p.actor, p.subject, p.ip, detail+err.Error())
}

// HasRecentEvent reports whether an event of this kind was recorded at or after
// t.
//
// The times are compared as times. They are stored as RFC 3339 text with
// nanoseconds, which drops trailing zeros, so the same instant can be written
// "…:07Z" or "…:07.1Z", and as strings those do not sort as times: 'Z' sorts
// after '.', so "…:07.1Z" came before "…:07Z", and "…:07.1Z" after
// "…:07.10001Z". The log is append-only, so the newest events are the highest
// ids, and only those are read.
func (s *Store) HasRecentEvent(kind string, t time.Time) bool {
	if s == nil || s.db == nil {
		return false
	}
	rows, err := s.db.Query(`SELECT at FROM security_events WHERE kind = ? ORDER BY id DESC LIMIT 200`, kind)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var at string
		if rows.Scan(&at) == nil && atOrAfter(at, t) {
			return true
		}
	}
	return false
}

// atOrAfter reports whether a stored event time is at or after t.
func atOrAfter(at string, t time.Time) bool {
	when, err := time.Parse(time.RFC3339Nano, at)
	return err == nil && !when.Before(t)
}

// retryBusy runs fn until it stops reporting SQLITE_BUSY, for a few hundred
// milliseconds.
//
// The DSN already sets busy_timeout, which covers contention between
// statements. What it does not cover is the moment a connection is *opened*:
// the WAL-mode pragma runs then, and a BUSY there is returned rather than
// waited on (the same reason initSchema retries). The pool opens connections
// lazily, so any statement can be the one that pays for it — which is how a
// single-threaded test on Windows saw "database is locked" reading a table it
// had just written.
//
// One policy for the whole table: a reader that gave up where the writer
// retries would silently see an empty log and act on it.
func retryBusy(fn func() error) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if err = fn(); err == nil || !isBusy(err) {
			return err
		}
		time.Sleep(time.Duration(attempt+1) * 20 * time.Millisecond)
	}
	return err
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
	if err := appendEventIn(ctx, conn, kind, actor, subject, ip, detail); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	commit = true
	return nil
}

// appendEventIn chains one event onto the log inside a transaction the caller
// has already opened with BEGIN IMMEDIATE, so the event commits or rolls back
// with the change it records.
func appendEventIn(ctx context.Context, conn *sql.Conn, kind, actor, subject, ip, detail string) error {
	e := SecurityEvent{At: time.Now().UTC().Format(time.RFC3339Nano), Kind: kind,
		Actor: actor, Subject: clip(subject), IP: ip, Detail: clip(detail)}
	err := conn.QueryRowContext(ctx, `SELECT id, row_hash FROM security_events ORDER BY id DESC LIMIT 1`).Scan(&e.ID, &e.PrevHash)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	e.ID++
	e.RowHash = EventHash(e)
	if _, err := conn.ExecContext(ctx, `INSERT INTO security_events(id,at,kind,actor,subject,ip,detail,prev_hash,row_hash)
		VALUES(?,?,?,?,?,?,?,?,?)`, e.ID, e.At, e.Kind, e.Actor, e.Subject, e.IP, e.Detail, e.PrevHash, e.RowHash); err != nil {
		return err
	}
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, s.attachSeals(out)
}

// SecurityEventsOfKind returns one kind's events, oldest first: what the
// audit log's marks were set to, for one, read back from who set them.
func (s *Store) SecurityEventsOfKind(kind string) ([]SecurityEvent, error) {
	rows, err := s.db.Query(`SELECT id,at,kind,actor,subject,ip,detail,prev_hash,row_hash FROM security_events WHERE kind = ? ORDER BY id`, kind)
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

// LastSecurityEventOfKind returns the newest event of a kind, or nil when
// there is none.
func (s *Store) LastSecurityEventOfKind(kind string) (*SecurityEvent, error) {
	var e SecurityEvent
	err := s.db.QueryRow(`SELECT id,at,kind,actor,subject,ip,detail,prev_hash,row_hash FROM security_events WHERE kind = ? ORDER BY id DESC LIMIT 1`, kind).
		Scan(&e.ID, &e.At, &e.Kind, &e.Actor, &e.Subject, &e.IP, &e.Detail, &e.PrevHash, &e.RowHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
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

// LastLicenseEvent returns the newest licence event's kind and subject, and
// whether there was one.
//
// The licence recorder compares against this so an unchanged licence is not
// recorded again on every engine start. Kind and subject are enough for that
// comparison on purpose: between them they carry which licence, which machine
// it is bound to, and whether it was unlocking anything — so nothing has to
// parse a sentence written for a person to read.
func (s *Store) LastLicenseEvent() (kind, subject string, ok bool, err error) {
	if s == nil || s.db == nil {
		return "", "", false, nil
	}
	err = retryBusy(func() error {
		row := s.db.QueryRow(
			`SELECT kind,subject FROM security_events WHERE kind LIKE ? ORDER BY id DESC LIMIT 1`,
			LicenseKindPrefix+"%")
		switch e := row.Scan(&kind, &subject); {
		case e == sql.ErrNoRows:
			kind, subject, ok = "", "", false
			return nil
		case e != nil:
			return e
		}
		ok = true
		return nil
	})
	if err != nil {
		return "", "", false, err
	}
	return kind, subject, ok, nil
}

// CheckEventChain recomputes the chain. It returns the id of the first event
// that does not match, or 0 when all do.
func CheckEventChain(evs []SecurityEvent) (int64, string) {
	return CheckEventChainFrom(evs, 0, "")
}

// CheckEventChainFrom recomputes the chain over evs, taking them to follow the
// event lastID, whose row hash is prev. Like CheckEventChain, it returns the id
// of the first event that does not match, or 0 when all do.
func CheckEventChainFrom(evs []SecurityEvent, lastID int64, prev string) (int64, string) {
	for _, e := range evs {
		switch {
		case e.ID != lastID+1:
			return e.ID, fmt.Sprintf("event %d follows %d: events are missing", e.ID, lastID)
		case e.PrevHash != prev:
			return e.ID, fmt.Sprintf("event %d does not chain to the event before it", e.ID)
		case !EventIntact(e): // its own hash, or its seal once pseudonymised
			return e.ID, fmt.Sprintf("event %d has been changed", e.ID)
		}
		prev, lastID = e.RowHash, e.ID
	}
	return 0, ""
}
