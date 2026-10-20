// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"errors"
	"time"
)

// When a branch was last used by the console or the API, for the gateway's idle
// reaper.
//
// The reaper runs in the gateway and judged a branch idle by gateway traffic
// alone. The console's queries do not go through the gateway: each opens its
// own short connection from the control plane, so between two of them the
// branch has no connections at all, and once two minutes had passed without a
// gateway client a sweep landing in that gap stopped the branch under someone
// who was using it. A query about to connect was refused; one in flight hung.
// (Found 20 Oct 2026: the console's UI tests failed with "connection refused"
// once the suite ran long enough to cross the window.)
//
// The control plane writes here when it uses a branch, at most every few
// seconds per branch, and the reaper reads it beside its own clock. This store
// is the one thing both processes already open.

const branchUseSchema = `CREATE TABLE IF NOT EXISTS branch_activity (branch TEXT PRIMARY KEY, at INTEGER NOT NULL);`

// TouchBranch records that a branch is being used now.
func (s *Store) TouchBranch(name string) error {
	return retryBusy(func() error {
		_, err := s.db.Exec(`INSERT INTO branch_activity(branch, at) VALUES(?, ?)
			ON CONFLICT(branch) DO UPDATE SET at = excluded.at`, name, time.Now().UnixMilli())
		return err
	})
}

// BranchUsedAt is when the console or the API last used a branch, if ever.
func (s *Store) BranchUsedAt(name string) (time.Time, bool) {
	var at int64
	err := s.db.QueryRow(`SELECT at FROM branch_activity WHERE branch = ?`, name).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) || err != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(at), true
}
