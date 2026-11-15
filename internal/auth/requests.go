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

// Change requests: a branch's schema changes, offered for review before they are
// applied to another branch.
//
// The store keeps the record — who asked, for what, who decided, and the snapshot
// of statements as they were when the request was made — and knows nothing about
// what the statements mean. The reading and applying live in internal/branch,
// beside the Blackbox they come from. A snapshot rather than a live read is the
// point: a reviewer approves what they were shown, not whatever the branch looks
// like by the time they click.

// Change request states.
const (
	RequestOpen     = "open"
	RequestApproved = "approved"
	RequestRejected = "rejected"
	RequestFailed   = "failed" // approved, but applying it did not finish
)

// ErrNoSuchRequest is returned for an id that is not there.
var ErrNoSuchRequest = errors.New("no such change request")

// ErrRequestDecided is returned when a request has already been approved or
// rejected: a decision is made once.
var ErrRequestDecided = errors.New("that change request has already been decided")

// ChangeRequest is one request, with the emails resolved for display.
type ChangeRequest struct {
	ID          int64  `json:"id"`
	Source      string `json:"source"`
	Target      string `json:"target"`
	CreatedBy   string `json:"created_by"`
	Created     string `json:"created"`
	Status      string `json:"status"`
	ForkAfterID int64  `json:"fork_after_id"`
	Entries     string `json:"entries"` // opaque JSON, written and read by internal/branch
	DecidedBy   string `json:"decided_by,omitempty"`
	Decided     string `json:"decided,omitempty"`
	Note        string `json:"note,omitempty"`
	Applied     int    `json:"applied"`
	// IncludeData is whether the asker chose to carry the source's data
	// changes (INSERT, UPDATE, DELETE, …) as well as its schema changes. Off
	// unless they asked: an agent's test rows on its own branch are not meant
	// for production.
	IncludeData bool `json:"include_data"`
	// Omitted is what the request left out, as opaque JSON written and read by
	// internal/branch, and OmittedCount how many entries that was (the list may
	// be cut short; the count never is).
	Omitted      string `json:"omitted,omitempty"`
	OmittedCount int    `json:"omitted_count"`
}

// requestMetaSchema is what a request carries beside the columns it was first
// made with. A table of its own rather than new columns on change_requests:
// the HA standby is sent change_requests with a fixed set of columns
// (shared.go), and a new column would make an older node refuse the whole
// document mid-upgrade, while a new table rides along as an optional one.
//
// entry_key names the set of source entries a request holds, so a second open
// request for exactly the same changes can be found rather than made.
const requestMetaSchema = `
CREATE TABLE IF NOT EXISTS change_request_meta (
  request_id INTEGER PRIMARY KEY REFERENCES change_requests(id) ON DELETE CASCADE,
  entry_key TEXT NOT NULL DEFAULT '',
  include_data INTEGER NOT NULL DEFAULT 0,
  omitted TEXT NOT NULL DEFAULT '',
  omitted_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS change_request_meta_key ON change_request_meta(entry_key);`

// NewChangeRequest is what a new request is made from.
type NewChangeRequest struct {
	Source, Target string
	ForkAfterID    int64
	Entries        string // opaque JSON, as ChangeRequest.Entries
	// EntryKey names the set of entries (internal/branch.RequestKey). Two open
	// requests from the same source to the same target with the same key ask
	// for the same thing; empty means the caller has no key and nothing is
	// compared.
	EntryKey     string
	IncludeData  bool
	Omitted      string
	OmittedCount int
}

// CreateChangeRequest records a new request and returns it. It compares
// nothing with the requests already open; OpenChangeRequest does.
func (s *Store) CreateChangeRequest(userID int64, source, target string, forkAfterID int64, entriesJSON string) (ChangeRequest, error) {
	c, _, err := s.OpenChangeRequest(userID, NewChangeRequest{Source: source, Target: target,
		ForkAfterID: forkAfterID, Entries: entriesJSON})
	return c, err
}

// OpenChangeRequest records a new request, unless one already open asks for
// exactly the same changes from the same source to the same target, in which
// case it returns that one and existing is true.
//
// Two identical open requests are two chances to apply the same statements:
// approve one and the other still offers them, against a target that now has
// them. The look and the insert share one write transaction, so two callers
// asking at the same moment cannot both decide there is no such request.
func (s *Store) OpenChangeRequest(userID int64, n NewChangeRequest) (c ChangeRequest, existing bool, err error) {
	if strings.TrimSpace(n.Source) == "" || strings.TrimSpace(n.Target) == "" {
		return ChangeRequest{}, false, errors.New("a change request needs a source and a target branch")
	}
	if n.Entries == "" {
		n.Entries = "[]"
	}
	var id int64
	err = retryBusy(func() error {
		var e error
		id, existing, e = s.openChangeRequestOnce(userID, n)
		return e
	})
	if err != nil {
		return ChangeRequest{}, false, err
	}
	c, err = s.ChangeRequest(id)
	return c, existing, err
}

func (s *Store) openChangeRequestOnce(userID int64, n NewChangeRequest) (int64, bool, error) {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return 0, false, err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()
	if n.EntryKey != "" {
		var id int64
		err := conn.QueryRowContext(ctx, `SELECT r.id FROM change_requests r
			JOIN change_request_meta m ON m.request_id = r.id
			WHERE r.source = ? AND r.target = ? AND r.status = ? AND m.entry_key = ?
			ORDER BY r.id LIMIT 1`, n.Source, n.Target, RequestOpen, n.EntryKey).Scan(&id)
		switch {
		case err == nil:
			return id, true, nil // nothing written; the rollback is harmless
		case !errors.Is(err, sql.ErrNoRows):
			return 0, false, err
		}
	}
	res, err := conn.ExecContext(ctx, `INSERT INTO change_requests
		(source, target, created_by, created, status, fork_after_id, entries)
		VALUES (?,?,?,?,?,?,?)`,
		n.Source, n.Target, userID, time.Now().Unix(), RequestOpen, n.ForkAfterID, n.Entries)
	if err != nil {
		return 0, false, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, false, err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO change_request_meta
		(request_id, entry_key, include_data, omitted, omitted_count) VALUES (?,?,?,?,?)`,
		id, n.EntryKey, boolInt(n.IncludeData), n.Omitted, n.OmittedCount); err != nil {
		return 0, false, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return 0, false, err
	}
	commit = true
	return id, false, nil
}

// CLIUser is the user id the CLI records for itself. Whoever has a shell on the
// machine is the operator, and naming that plainly beats inventing an account.
const CLIUser int64 = 0

const cliLabel = "the local CLI"

const requestColumns = `r.id, r.source, r.target,
	CASE WHEN r.created_by = 0 THEN '` + cliLabel + `' ELSE coalesce(u.email,'(deleted account)') END,
	r.created, r.status, r.fork_after_id, r.entries,
	CASE WHEN r.decided_by IS NULL THEN '' WHEN r.decided_by = 0 THEN '` + cliLabel + `'
	     ELSE coalesce(d.email,'(deleted account)') END,
	coalesce(r.decided,0), r.note, r.applied,
	coalesce(m.include_data,0), coalesce(m.omitted,''), coalesce(m.omitted_count,0)`

// requestFrom is the join every read of a request uses. A request made before
// change_request_meta existed has no row there, and reads as schema-only with
// nothing recorded as left out, which is what it was.
const requestFrom = ` FROM change_requests r
	LEFT JOIN users u ON u.id = r.created_by
	LEFT JOIN users d ON d.id = r.decided_by
	LEFT JOIN change_request_meta m ON m.request_id = r.id`

func scanRequest(row interface{ Scan(...any) error }) (ChangeRequest, error) {
	var c ChangeRequest
	var created, decided, includeData int64
	if err := row.Scan(&c.ID, &c.Source, &c.Target, &c.CreatedBy, &created, &c.Status,
		&c.ForkAfterID, &c.Entries, &c.DecidedBy, &decided, &c.Note, &c.Applied,
		&includeData, &c.Omitted, &c.OmittedCount); err != nil {
		return ChangeRequest{}, err
	}
	c.IncludeData = includeData != 0
	c.Created = time.Unix(created, 0).UTC().Format(time.RFC3339)
	if decided > 0 {
		c.Decided = time.Unix(decided, 0).UTC().Format(time.RFC3339)
	}
	return c, nil
}

// ChangeRequest is one request by id.
func (s *Store) ChangeRequest(id int64) (ChangeRequest, error) {
	row := s.db.QueryRow(`SELECT `+requestColumns+requestFrom+` WHERE r.id = ?`, id)
	c, err := scanRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ChangeRequest{}, fmt.Errorf("%w: %d", ErrNoSuchRequest, id)
	}
	return c, err
}

// ChangeRequests lists requests, newest first. An empty status means every state;
// an empty target means every branch.
func (s *Store) ChangeRequests(status, target string) ([]ChangeRequest, error) {
	q := `SELECT ` + requestColumns + requestFrom + ` WHERE 1=1`
	var args []any
	if status != "" {
		q += " AND r.status = ?"
		args = append(args, status)
	}
	if target != "" {
		q += " AND r.target = ?"
		args = append(args, target)
	}
	q += " ORDER BY r.id DESC LIMIT 500"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChangeRequest{}
	for rows.Next() {
		c, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ApprovedRequestsFrom is the approved requests this source has already had
// applied to this target. Promotion needs them: what a branch has already given
// another is not a reason to refuse its next round (internal/branch/promote.go).
func (s *Store) ApprovedRequestsFrom(source, target string) ([]ChangeRequest, error) {
	return s.RequestsFrom(source, target, RequestApproved)
}

// RequestsFrom is this source's requests to this target in any of the given
// states, newest first.
func (s *Store) RequestsFrom(source, target string, statuses ...string) ([]ChangeRequest, error) {
	out := []ChangeRequest{}
	for _, st := range statuses {
		all, err := s.ChangeRequests(st, target)
		if err != nil {
			return nil, err
		}
		for _, c := range all {
			if c.Source == source {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// ClaimChangeRequest moves an open request to a decided state and records who
// decided it. It is the one write that must not race: two approvals of the same
// request would apply its statements twice, so the update is conditional on the
// request still being open and reports ErrRequestDecided when it was not.
func (s *Store) ClaimChangeRequest(id, userID int64, status, note string) (ChangeRequest, error) {
	if status != RequestApproved && status != RequestRejected {
		return ChangeRequest{}, fmt.Errorf("a change request is approved or rejected, not %q", status)
	}
	res, err := s.db.Exec(`UPDATE change_requests SET status=?, decided_by=?, decided=?, note=?
		WHERE id=? AND status=?`, status, userID, time.Now().Unix(), note, id, RequestOpen)
	if err != nil {
		return ChangeRequest{}, err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		// Either there is no such request, or somebody else decided it first.
		if _, err := s.ChangeRequest(id); err != nil {
			return ChangeRequest{}, err
		}
		return ChangeRequest{}, fmt.Errorf("%w: %d", ErrRequestDecided, id)
	}
	return s.ChangeRequest(id)
}

// FinishChangeRequest records the outcome of applying an approved request: how
// many statements went in, and the failure when it did not finish.
func (s *Store) FinishChangeRequest(id int64, applied int, failure string) error {
	status := RequestApproved
	note := ""
	if failure != "" {
		status = RequestFailed
		note = failure
	}
	if note == "" {
		_, err := s.db.Exec(`UPDATE change_requests SET status=?, applied=? WHERE id=?`, status, applied, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE change_requests SET status=?, applied=?, note=? WHERE id=?`, status, applied, note, id)
	return err
}

// ReconcileChangeRequest records that an approved request is in its target
// after all, from the target's own record of it (bb.applied_requests), when
// this store never learned so: the changes committed and noting the outcome
// here failed, or the commit's answer never arrived. Only a request with
// nothing recorded as applied is changed, so a count already written stays.
func (s *Store) ReconcileChangeRequest(id int64, applied int) error {
	_, err := s.db.Exec(`UPDATE change_requests SET status=?, applied=?,
		note = CASE WHEN note = '' THEN ? ELSE note || ' — ' || ? END
		WHERE id=? AND applied=0 AND status IN (?,?)`,
		RequestApproved, applied, reconciledNote, reconciledNote, id, RequestApproved, RequestFailed)
	return err
}

const reconciledNote = "the target's own record shows this request was applied"

// ForgetBranchRequests removes the requests of a branch that no longer exists, so
// a deleted branch does not leave open requests pointing at nothing.
func (s *Store) ForgetBranchRequests(branch string) error {
	_, err := s.db.Exec(`DELETE FROM change_requests WHERE (source=? OR target=?) AND status=?`,
		branch, branch, RequestOpen)
	return err
}
