// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"sync"
	"time"
)

// Making a login role when it is first needed, safely when many ask at once.
//
// A console page sends several requests together, and each logs in as the
// signed-in user's own role, so each used to make that role if it was missing
// and set its password: two CREATE ROLEs at once fail with "already exists",
// and two ALTER ROLEs on one role with "tuple concurrently updated". While the
// console fell back to the shared role on any failure nobody saw it; since it
// refuses instead (G1), a person was told they could not be logged in as
// themselves, intermittently. The Gateway and the control plane are different
// processes and provision the same roles, so both layers below are needed:
//
//   - within a process, one provisioning at a time per branch and role, and a
//     second asker finds the first one's work done;
//   - across processes, the SQL itself tolerates the role having just been
//     made or changed by another session, retrying a few times, and the whole
//     statement is tried once more.

// roleLocks is one mutex per branch and role.
var roleLocks sync.Map

func lockRole(key string) func() {
	m, _ := roleLocks.LoadOrStore(key, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// provisionRole runs role-making SQL on a branch, retrying once after a short
// pause: another process may have been changing the same role at that moment.
func provisionRole(branchName, sql string) error {
	err := psqlQuiet(branchName, sql)
	if err == nil {
		return nil
	}
	time.Sleep(150 * time.Millisecond)
	if err2 := psqlQuiet(branchName, sql); err2 != nil {
		return err2
	}
	return nil
}

// retryingRoleDO wraps the statements that make or update one role in a DO
// block that retries them when another session was making or changing the same
// role: duplicate_object or unique_violation for a CREATE ROLE that lost a
// race, internal_error for "tuple concurrently updated" on an ALTER ROLE. decl
// is the block's DECLARE section ("" for none); body its statements.
func retryingRoleDO(decl, body string) string {
	d := ""
	if decl != "" {
		d = "DECLARE " + decl + "\n"
	}
	return fmt.Sprintf(`DO $do$
%sBEGIN
  FOR attempt IN 1..5 LOOP
    BEGIN
%s
      EXIT;
    EXCEPTION WHEN duplicate_object OR unique_violation OR internal_error THEN
      IF attempt = 5 THEN RAISE; END IF;
      PERFORM pg_sleep(0.05 * attempt);
    END;
  END LOOP;
END $do$;`, d, body)
}
