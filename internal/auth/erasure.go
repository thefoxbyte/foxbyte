// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Erasure requests (point 11.2, F4; docs/FOX_F4_Erasure_Design.md, section
// 16). A request is evidence, so it lives in the install's store, not in a
// branch: a branch can be deleted or restored, and the request must outlive
// both. It keeps no value: refs holds each value's category and last four
// characters; plan is the latest plan, counts and actions with no value and
// no row key; result, once applied, is what changed, with the row keys.
// The engine (internal/branch) writes and reads the JSON.

const erasureSchema = `
CREATE TABLE IF NOT EXISTS erasure_requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  uid         TEXT NOT NULL,
  branch      TEXT NOT NULL,
  state       TEXT NOT NULL CHECK (state IN ('planned', 'applying', 'applied', 'withdrawn')),
  refs        TEXT NOT NULL,
  events      TEXT NOT NULL DEFAULT '{}',
  note        TEXT NOT NULL DEFAULT '',
  plan        TEXT NOT NULL DEFAULT '{}',
  fingerprint TEXT NOT NULL DEFAULT '',
  created_by  TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  planned_by  TEXT NOT NULL,
  planned_at  INTEGER NOT NULL,
  claimed_at  INTEGER,
  applied_by  TEXT NOT NULL DEFAULT '',
  applied_at  INTEGER,
  result      TEXT NOT NULL DEFAULT '{}',
  withdrawn_by TEXT NOT NULL DEFAULT '',
  withdrawn_at INTEGER
);
`

// The states of an erasure request.
const (
	ErasurePlanned   = "planned"
	ErasureApplying  = "applying"
	ErasureApplied   = "applied"
	ErasureWithdrawn = "withdrawn"
)

// ErasureRequest is a request as the store keeps it.
type ErasureRequest struct {
	ID          int64      `json:"id"`
	UID         string     `json:"-"`
	Branch      string     `json:"branch"`
	State       string     `json:"state"`
	Refs        string     `json:"-"`
	Events      string     `json:"-"`
	Note        string     `json:"note"`
	Plan        string     `json:"-"`
	Fingerprint string     `json:"fingerprint"`
	CreatedBy   string     `json:"createdBy"`
	Created     time.Time  `json:"created"`
	PlannedBy   string     `json:"plannedBy"`
	Planned     time.Time  `json:"planned"`
	Claimed     time.Time  `json:"-"`
	AppliedBy   string     `json:"appliedBy,omitempty"`
	Applied     *time.Time `json:"appliedAt,omitempty"`
	Result      string     `json:"-"`
	WithdrawnBy string     `json:"withdrawnBy,omitempty"`
	Withdrawn   *time.Time `json:"withdrawnAt,omitempty"`
}

// NewErasureRequest is what a new request is made from.
type NewErasureRequest struct {
	Branch, Refs, Events, Note, Plan, Fingerprint, Actor string
}

// ErrNoErasure is a request id with no request.
var ErrNoErasure = errors.New("no such erasure request")

// ErrErasureMoved is a change to a request that is no longer in the state the
// caller read: another admin applied, withdrew or planned it again first.
var ErrErasureMoved = errors.New("the request changed meanwhile; read it again")

const erasureCols = `id, uid, branch, state, refs, events, note, plan, fingerprint, created_by, created_at,
	planned_by, planned_at, coalesce(claimed_at, 0), applied_by, applied_at, result, withdrawn_by, withdrawn_at`

func scanErasure(row interface{ Scan(...any) error }) (ErasureRequest, error) {
	var r ErasureRequest
	var created, planned, claimed int64
	var applied, withdrawn sql.NullInt64
	err := row.Scan(&r.ID, &r.UID, &r.Branch, &r.State, &r.Refs, &r.Events, &r.Note, &r.Plan, &r.Fingerprint,
		&r.CreatedBy, &created, &r.PlannedBy, &planned, &claimed, &r.AppliedBy, &applied, &r.Result,
		&r.WithdrawnBy, &withdrawn)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNoErasure
	}
	if err != nil {
		return r, err
	}
	r.Created, r.Planned = time.UnixMilli(created).UTC(), time.UnixMilli(planned).UTC()
	if claimed > 0 {
		r.Claimed = time.UnixMilli(claimed).UTC()
	}
	if applied.Valid {
		t := time.UnixMilli(applied.Int64).UTC()
		r.Applied = &t
	}
	if withdrawn.Valid {
		t := time.UnixMilli(withdrawn.Int64).UTC()
		r.Withdrawn = &t
	}
	return r, nil
}

// CreateErasure records a new request with its first plan.
func (s *Store) CreateErasure(n NewErasureRequest) (ErasureRequest, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ErasureRequest{}, err
	}
	uid := hex.EncodeToString(b)
	now := time.Now().UnixMilli()
	var id int64
	err := retryBusy(func() error {
		res, err := s.db.Exec(`INSERT INTO erasure_requests (uid, branch, state, refs, events, note, plan, fingerprint,
			created_by, created_at, planned_by, planned_at) VALUES (?, ?, 'planned', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			uid, n.Branch, n.Refs, n.Events, n.Note, n.Plan, n.Fingerprint, n.Actor, now, n.Actor, now)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return ErasureRequest{}, err
	}
	return s.Erasure(id)
}

// Erasure reads one request.
func (s *Store) Erasure(id int64) (ErasureRequest, error) {
	return scanErasure(s.db.QueryRow(`SELECT `+erasureCols+` FROM erasure_requests WHERE id = ?`, id))
}

// Erasures reads every request, newest first.
func (s *Store) Erasures() ([]ErasureRequest, error) {
	rows, err := s.db.Query(`SELECT ` + erasureCols + ` FROM erasure_requests ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ErasureRequest{}
	for rows.Next() {
		r, err := scanErasure(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// erasureUpdate runs a conditional update and reads the request back, or says
// why nothing changed.
func (s *Store) erasureUpdate(id int64, q string, args ...any) (ErasureRequest, error) {
	var n int64
	err := retryBusy(func() error {
		res, err := s.db.Exec(q, args...)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return ErasureRequest{}, err
	}
	if n == 0 {
		if _, err := s.Erasure(id); err != nil {
			return ErasureRequest{}, err
		}
		return ErasureRequest{}, ErrErasureMoved
	}
	return s.Erasure(id)
}

// SaveErasurePlan keeps a new plan for a planned request, or one whose apply
// found the plan changed (applying), which is planned again.
func (s *Store) SaveErasurePlan(id int64, plan, fingerprint, actor string) (ErasureRequest, error) {
	return s.erasureUpdate(id, `UPDATE erasure_requests SET plan = ?, fingerprint = ?, planned_by = ?, planned_at = ?,
		state = 'planned', claimed_at = NULL WHERE id = ? AND state IN ('planned', 'applying')`,
		plan, fingerprint, actor, time.Now().UnixMilli(), id)
}

// ClaimErasure marks a planned request as being applied, if its plan is
// still the one with this fingerprint. Two admins applying at once meet here:
// the second is refused.
func (s *Store) ClaimErasure(id int64, fingerprint, actor string) error {
	_, err := s.erasureUpdate(id, `UPDATE erasure_requests SET state = 'applying', claimed_at = ?
		WHERE id = ? AND state = 'planned' AND fingerprint = ?`, time.Now().UnixMilli(), id, fingerprint)
	if errors.Is(err, ErrErasureMoved) {
		return fmt.Errorf("request %d is being applied, or was planned again, meanwhile: %w", id, err)
	}
	return err
}

// ReleaseErasure puts a request whose apply failed, and committed nothing,
// back to planned.
func (s *Store) ReleaseErasure(id int64) error {
	_, err := s.erasureUpdate(id, `UPDATE erasure_requests SET state = 'planned', claimed_at = NULL
		WHERE id = ? AND state = 'applying'`, id)
	return err
}

// FinishErasure records a request applied, with what applying did.
func (s *Store) FinishErasure(id int64, result, actor string) (ErasureRequest, error) {
	return s.erasureUpdate(id, `UPDATE erasure_requests SET state = 'applied', applied_by = ?, applied_at = ?, result = ?
		WHERE id = ? AND state = 'applying'`, actor, time.Now().UnixMilli(), result, id)
}

// SaveErasureResult keeps an applied request's result as its vacuum and
// rewrites go on.
func (s *Store) SaveErasureResult(id int64, result string) (ErasureRequest, error) {
	return s.erasureUpdate(id, `UPDATE erasure_requests SET result = ? WHERE id = ? AND state = 'applied'`, result, id)
}

// WithdrawErasure closes a planned request without applying it.
func (s *Store) WithdrawErasure(id int64, actor string) (ErasureRequest, error) {
	r, err := s.erasureUpdate(id, `UPDATE erasure_requests SET state = 'withdrawn', withdrawn_by = ?, withdrawn_at = ?
		WHERE id = ? AND state = 'planned'`, actor, time.Now().UnixMilli(), id)
	if errors.Is(err, ErrErasureMoved) {
		cur, _ := s.Erasure(id)
		return r, fmt.Errorf("request %d is %s; only a planned request is withdrawn: %w", id, cur.State, err)
	}
	return r, err
}
