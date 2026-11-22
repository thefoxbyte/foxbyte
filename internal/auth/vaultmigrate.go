// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Vault migrations (point 13, step 13.3; docs/FOX_P13_Vault_Design.md,
// section 15): each run that moved a branch's Aadhaar numbers into the vault,
// or previewed doing so, and the reference keys each run made. They are kept
// in the install's store, not the branch, because they matter most once the
// branch is gone: a rehearsal branch deleted leaves keys in the vault that no
// table holds, and these rows are how `fox vault orphans` finds them. Only
// reference keys are kept, never a number.

const vaultMigrateSchema = `
CREATE TABLE IF NOT EXISTS vault_migrations (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  branch      TEXT NOT NULL,
  branch_made INTEGER NOT NULL DEFAULT 0,
  parent      TEXT NOT NULL DEFAULT '',
  kind        TEXT NOT NULL,
  actor       TEXT NOT NULL,
  vault_actor TEXT NOT NULL,
  dry         INTEGER NOT NULL DEFAULT 0,
  state       TEXT NOT NULL CHECK (state IN ('running', 'done', 'failed')),
  started_at  INTEGER NOT NULL,
  finished_at INTEGER,
  report      TEXT NOT NULL DEFAULT '{}',
  error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS vault_migrations_branch ON vault_migrations (branch, id);
CREATE TABLE IF NOT EXISTS vault_migration_refs (
  migration_id INTEGER NOT NULL REFERENCES vault_migrations (id),
  ref          TEXT NOT NULL,
  state        TEXT NOT NULL DEFAULT '' CHECK (state IN ('', 'deleted', 'kept')),
  settled_at   INTEGER,
  PRIMARY KEY (migration_id, ref)
);
`

// VaultMigrationRun is one run as the store keeps it. Report is the run's
// report as JSON, which the engine writes and reads (branch.VaultMigration).
type VaultMigrationRun struct {
	ID         int64      `json:"id"`
	Branch     string     `json:"branch"`
	BranchMade int64      `json:"branch_made"` // the branch's data's making, in Unix seconds, when the run began
	Parent     string     `json:"parent"`      // the branch it was made from, when the run began
	Kind       string     `json:"kind"`
	Actor      string     `json:"actor"`
	VaultActor string     `json:"vault_actor"` // the actor the vault knows the run's calls by
	Dry        bool       `json:"dry"`
	State      string     `json:"state"`
	Started    time.Time  `json:"started"`
	Finished   *time.Time `json:"finished,omitempty"`
	Report     string     `json:"-"`
	Error      string     `json:"error,omitempty"`
}

// StartVaultMigration records a run as it begins, and names its actor in the
// vault: the account and the run, so the keys it makes are told apart from
// everyone else's.
func (s *Store) StartVaultMigration(r VaultMigrationRun) (VaultMigrationRun, error) {
	r.Started = time.Now().UTC()
	r.State = "running"
	err := retryBusy(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		res, err := tx.Exec(`INSERT INTO vault_migrations (branch, branch_made, parent, kind, actor, vault_actor, dry, state, started_at)
			VALUES (?, ?, ?, ?, ?, '', ?, 'running', ?)`, r.Branch, r.BranchMade, r.Parent, r.Kind, r.Actor, r.Dry, r.Started.UnixMilli())
		if err != nil {
			return err
		}
		if r.ID, err = res.LastInsertId(); err != nil {
			return err
		}
		r.VaultActor = fmt.Sprintf("%s (vault migration %d)", r.Actor, r.ID)
		if _, err := tx.Exec(`UPDATE vault_migrations SET vault_actor = ? WHERE id = ?`, r.VaultActor, r.ID); err != nil {
			return err
		}
		return tx.Commit()
	})
	return r, err
}

// AddVaultMigrationRefs keeps reference keys a run made (the vault said they
// were new), as it makes them, so a run that stops half way still leaves its
// keys findable.
func (s *Store) AddVaultMigrationRefs(id int64, refs []string) error {
	if len(refs) == 0 {
		return nil
	}
	return retryBusy(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		st, err := tx.Prepare(`INSERT OR IGNORE INTO vault_migration_refs (migration_id, ref) VALUES (?, ?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, r := range refs {
			if _, err := st.Exec(id, r); err != nil {
				return err
			}
		}
		return tx.Commit()
	})
}

// FinishVaultMigration records how a run ended: its report, and the error
// that stopped it ("" for one that finished).
func (s *Store) FinishVaultMigration(id int64, report string, runErr error) error {
	state, msg := "done", ""
	if runErr != nil {
		state, msg = "failed", runErr.Error()
	}
	return retryBusy(func() error {
		_, err := s.db.Exec(`UPDATE vault_migrations SET state = ?, finished_at = ?, report = ?, error = ? WHERE id = ?`,
			state, time.Now().UTC().UnixMilli(), report, msg, id)
		return err
	})
}

const vaultMigrationCols = `id, branch, branch_made, parent, kind, actor, vault_actor, dry, state, started_at, finished_at, report, error`

func scanVaultMigration(sc interface{ Scan(...any) error }) (VaultMigrationRun, error) {
	var r VaultMigrationRun
	var started int64
	var finished sql.NullInt64
	if err := sc.Scan(&r.ID, &r.Branch, &r.BranchMade, &r.Parent, &r.Kind, &r.Actor, &r.VaultActor, &r.Dry, &r.State,
		&started, &finished, &r.Report, &r.Error); err != nil {
		return r, err
	}
	r.Started = time.UnixMilli(started).UTC()
	if finished.Valid {
		t := time.UnixMilli(finished.Int64).UTC()
		r.Finished = &t
	}
	return r, nil
}

// ErrNoVaultMigration is a run the store does not hold.
var ErrNoVaultMigration = errors.New("no such vault migration")

// VaultMigration reads one run.
func (s *Store) VaultMigration(id int64) (VaultMigrationRun, error) {
	r, err := scanVaultMigration(s.db.QueryRow(`SELECT `+vaultMigrationCols+` FROM vault_migrations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNoVaultMigration
	}
	return r, err
}

// VaultMigrations lists runs, newest first: one branch's, or every branch's
// when branch is "".
func (s *Store) VaultMigrations(branch string, limit int) ([]VaultMigrationRun, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT ` + vaultMigrationCols + ` FROM vault_migrations`
	args := []any{}
	if branch != "" {
		q += ` WHERE branch = ?`
		args = append(args, branch)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VaultMigrationRun
	for rows.Next() {
		r, err := scanVaultMigration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// VaultMigrationRefCounts is how many of a run's keys are still to settle,
// deleted, and kept because someone else was handed them.
type VaultMigrationRefCounts struct {
	Made    int `json:"made"`
	Pending int `json:"pending"`
	Deleted int `json:"deleted"`
	Kept    int `json:"kept"`
}

// VaultMigrationRefCounts counts a run's keys by what became of them.
func (s *Store) VaultMigrationRefCounts(id int64) (VaultMigrationRefCounts, error) {
	var c VaultMigrationRefCounts
	err := s.db.QueryRow(`SELECT count(*), coalesce(sum(state = ''), 0), coalesce(sum(state = 'deleted'), 0), coalesce(sum(state = 'kept'), 0)
		FROM vault_migration_refs WHERE migration_id = ?`, id).Scan(&c.Made, &c.Pending, &c.Deleted, &c.Kept)
	return c, err
}

// PendingVaultMigrationRefs lists up to limit of a run's keys not yet
// settled.
func (s *Store) PendingVaultMigrationRefs(id int64, limit int) ([]string, error) {
	rows, err := s.db.Query(`SELECT ref FROM vault_migration_refs WHERE migration_id = ? AND state = '' ORDER BY ref LIMIT ?`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SettleVaultMigrationRefs marks keys of a run deleted (gone from the vault,
// or never there) or kept (someone else was handed them).
func (s *Store) SettleVaultMigrationRefs(id int64, deleted, kept []string) error {
	now := time.Now().UTC().UnixMilli()
	return retryBusy(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for state, refs := range map[string][]string{"deleted": deleted, "kept": kept} {
			for _, r := range refs {
				if _, err := tx.Exec(`UPDATE vault_migration_refs SET state = ?, settled_at = ? WHERE migration_id = ? AND ref = ?`,
					state, now, id, strings.TrimSpace(r)); err != nil {
					return err
				}
			}
		}
		return tx.Commit()
	})
}
