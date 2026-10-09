// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// What a running branch has cost so far: how long it has been up, and how much
// work it has done.
//
// This exists because of a decision made about realtime. A branch nobody is
// querying gets suspended by the reaper, and that is what makes an idle branch
// nearly free — but a branch with a subscriber attached must stay up, or the
// feed would miss what happened while it was away. Staying up is the right
// trade and it is not a free one, so the bill has to be legible: how long it
// has been warm, and whether anything used it in that time.
//
// Two sources, both of which already exist and neither of which needs new
// bookkeeping:
//
//   - the container's own StartedAt, for how long it has been warm. It is the
//     truth, it survives the control plane restarting, and it cannot drift from
//     reality the way a timestamp we wrote down could.
//   - pg_stat_database, for the work. Which is also the honest limit of this:
//     without pg_stat_statements — not loaded, and loading it needs another
//     restart — Postgres counts transactions, not statements. So that is what
//     these fields are called.

// WarmSince is when this branch's container last started, or the zero time when
// it is not running.
//
// "Warm" rather than "started" on purpose: a suspended branch is resumed by the
// gateway on the next connection, and resuming starts the container again. So
// this is the beginning of the current warm period, not of the branch's life.
func WarmSince(name string) (time.Time, error) {
	out, err := capture("docker", "inspect", container(name),
		"--format", "{{.State.Running}} {{.State.StartedAt}}")
	if err != nil {
		return time.Time{}, err
	}
	running, started, ok := strings.Cut(strings.TrimSpace(out), " ")
	if !ok {
		return time.Time{}, fmt.Errorf("could not read %q's state: %q", name, out)
	}
	if running != "true" {
		// Not an error: a suspended branch is the normal, cheap state, and the
		// caller's next question is "for how long has it been warm", whose
		// answer is "it is not".
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, started)
	if err != nil {
		return time.Time{}, fmt.Errorf("could not read %q's start time %q: %w", name, started, err)
	}
	return t.UTC(), nil
}

// Counters is the work a branch's database reports having done.
//
// Cumulative since the statistics were last reset, which is usually never — so
// a single reading says little and two readings say everything. Whoever is
// metering keeps the first one.
type Counters struct {
	// Transactions is commits plus rollbacks. Not statements: without
	// pg_stat_statements loaded, which costs a restart, this is the closest
	// thing Postgres counts, and for a client that autocommits it is one per
	// statement. Named for what it measures rather than for what it is a proxy
	// for, because the difference matters to anyone billing from it.
	Transactions int64 `json:"transactions"`
	Commits      int64 `json:"commits"`
	Rollbacks    int64 `json:"rollbacks"`
	// RowsReturned is tup_returned: rows handed back to clients. A useful
	// second axis, since one transaction can read a row or a million.
	RowsReturned int64 `json:"rows_returned"`
	// StatsReset is when these counters last started from zero, as Unix
	// seconds, and 0 when they never have. A reading taken before a reset
	// cannot be subtracted from one taken after, so a meter has to watch this
	// to know when to start again rather than report a negative delta.
	//
	// Epoch rather than a formatted timestamp deliberately: the format string
	// needed for an ISO-8601 "T" carries nested double quotes through an exec
	// argument, and a number cannot be misread.
	StatsReset int64 `json:"stats_reset,omitempty"`
}

// ReadCounters asks a branch what work it has done.
func ReadCounters(name string) (Counters, error) {
	lines, err := LedgerQuery(ServingBranch(name), `
SELECT xact_commit || '|' || xact_rollback || '|' || tup_returned || '|' ||
       coalesce(extract(epoch FROM stats_reset)::bigint, 0)
  FROM pg_stat_database WHERE datname = current_database()`)
	if err != nil {
		return Counters{}, err
	}
	for _, l := range lines {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) != 4 {
			continue
		}
		c := Counters{
			Commits:      atoi64(f[0]),
			Rollbacks:    atoi64(f[1]),
			RowsReturned: atoi64(f[2]),
			StatsReset:   atoi64(f[3]),
		}
		c.Transactions = c.Commits + c.Rollbacks
		return c, nil
	}
	return Counters{}, fmt.Errorf("no statistics for %q's database", name)
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

// SlotLag is how much write-ahead log a subscriber's bookmark is holding, and
// how close that is to the budget past which Postgres drops the bookmark
// instead of keeping more.
//
// This is the number that turns "a subscriber went away" into something an
// operator can act on before the disk does it for them.
type SlotLag struct {
	Slot      string `json:"slot"`
	Active    bool   `json:"active"`
	Status    string `json:"status"`
	HeldBytes int64  `json:"held_bytes"`
	// SafeBytes is how much the slot may still fall behind before Postgres
	// invalidates it. Negative is not possible; zero means it is at the edge.
	SafeBytes int64 `json:"safe_bytes"`
}

// ReadSlotLag reports every change-feed slot on a branch with the WAL it holds.
func ReadSlotLag(name string) ([]SlotLag, error) {
	lines, err := LedgerQuery(ServingBranch(name), `
SELECT slot_name || '|' || active || '|' || coalesce(wal_status, '') || '|' ||
       coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)::bigint, 0) || '|' ||
       coalesce(safe_wal_size::bigint, 0)
  FROM pg_replication_slots
 WHERE slot_name LIKE '`+SlotPrefix+`%' ORDER BY slot_name`)
	if err != nil {
		return nil, err
	}
	out := make([]SlotLag, 0, len(lines))
	for _, l := range lines {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) != 5 {
			continue
		}
		out = append(out, SlotLag{
			Slot:      f[0],
			Active:    f[1] == "t",
			Status:    f[2],
			HeldBytes: atoi64(f[3]),
			SafeBytes: atoi64(f[4]),
		})
	}
	return out, nil
}
