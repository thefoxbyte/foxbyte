// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"
)

// Point 12.5: whose a session is, the maintenance offered, and what is read.

func TestSessionOf(t *testing.T) {
	for _, c := range []struct {
		user, email string
		want        bool
	}{
		{"a@x.io", "A@X.io", true},
		{"agent:a@x.io", "a@x.io", true},
		{"agent-a1", "a@x.io", false},
		{"db_client", "a@x.io", false},
		{"b@x.io", "a@x.io", false},
		{"a@x.io", "", false},
	} {
		if got := SessionOf(c.user, c.email); got != c.want {
			t.Errorf("SessionOf(%q, %q) = %v", c.user, c.email, got)
		}
	}
}

// VACUUM, ANALYZE and both, on a quoted name; never VACUUM FULL, nor anything
// a name could smuggle in.
func TestMaintSQL(t *testing.T) {
	for op, want := range map[string]string{
		MaintVacuum:        `VACUUM "public"."orders"`,
		MaintAnalyze:       `ANALYZE "public"."orders"`,
		MaintVacuumAnalyze: `VACUUM (ANALYZE) "public"."orders"`,
	} {
		if got, err := maintSQL(op, "public", "orders"); err != nil || got != want {
			t.Errorf("%s: %q %v", op, got, err)
		}
	}
	for _, op := range []string{"full", "vacuum full", ""} {
		if _, err := maintSQL(op, "public", "t"); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%q accepted", op)
		}
	}
	if got, _ := maintSQL(MaintAnalyze, "public", `t"; DROP TABLE x; --`); !strings.HasPrefix(got, `ANALYZE "public"."t""; DROP TABLE x; --"`) {
		t.Errorf("a name is quoted whole: %s", got)
	}
}

// Only client sessions on the branch's database, never the one asking; the
// text cut; the engine's own tables left out of the upkeep.
func TestSessionsSQL(t *testing.T) {
	for _, want := range []string{"backend_type = 'client backend'", "datname = current_database()", "pid <> pg_backend_pid()",
		"left(coalesce(query, ''), 4000)", "pg_blocking_pids(pid)", "usename = '" + pgUser + "'"} {
		if !strings.Contains(sessionsSQL, want) {
			t.Errorf("the sessions' query lacks %q", want)
		}
	}
	if !strings.Contains(tableStatsSQL(""), "schemaname NOT IN ('bb', 'bb_mask', 'bb_f1')") {
		t.Error("the engine's tables are listed")
	}
}

func TestParsePID(t *testing.T) {
	if n, err := ParsePID(" 4242 "); err != nil || n != 4242 {
		t.Errorf("4242: %d %v", n, err)
	}
	for _, s := range []string{"0", "-3", "abc", ""} {
		if _, err := ParsePID(s); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := SignalSession("main", 0, false, ""); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("pid 0 signalled: %v", err)
	}
}
