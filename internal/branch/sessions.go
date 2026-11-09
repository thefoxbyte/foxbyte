// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Sessions and maintenance (point 12.5, pgAdmin's basics in the console):
// who is connected to a branch and what each is running, a running query
// cancelled or a session ended, and a table vacuumed or analysed, with what
// the server knows of when that last happened.
//
// Read as the engine, filtered by who asks (the control plane and the CLI):
// an admin, or a branch's owner, sees every session on it; anyone else their
// own, and their agent keys'. A statement's text can hold real values, so
// another account's is never shown to them. Only client sessions are listed
// and signalled: the server's own processes, a standby's replication and the
// engine's own sessions are not anyone's to end.

// ErrNotFound is a session or a table that is not there.
var ErrNotFound = errors.New("not found")

// Session is one client session on a branch, as pg_stat_activity has it.
type Session struct {
	PID   int    `json:"pid"`
	User  string `json:"user"`  // the login role: an account's email, an agent's, or a shared role
	App   string `json:"app"`   // application_name
	State string `json:"state"` // active, idle, idle in transaction, …
	Wait  string `json:"wait"`  // what it waits on, "" when nothing
	// Started is when the session began; Since when its current query (or
	// its last) began; Xact when its open transaction began, "" when none.
	Started string `json:"started"`
	Since   string `json:"since"`
	Xact    string `json:"xact"`
	Query   string `json:"query"`
	// BlockedBy lists the sessions holding what it waits for.
	BlockedBy []int `json:"blockedBy"`
	// Engine marks FoxByte's own sessions, which nobody may end here.
	Engine bool `json:"engine"`
}

// sessionsSQL lists the client sessions on the branch's database, without
// the one asking. The text is cut at 4,000 characters: enough to recognise a
// statement, not a dump of one.
const sessionsSQL = `SELECT coalesce(json_agg(json_build_object(
    'pid', pid, 'user', coalesce(usename, ''), 'app', coalesce(application_name, ''), 'state', coalesce(state, ''),
    'wait', coalesce(wait_event_type || ': ' || wait_event, ''),
    'started', coalesce(to_char(backend_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), ''),
    'since', coalesce(to_char(query_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), ''),
    'xact', coalesce(to_char(xact_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), ''),
    'query', left(coalesce(query, ''), 4000),
    'blockedBy', to_json(pg_blocking_pids(pid)),
    'engine', usename = '` + pgUser + `') ORDER BY backend_start, pid), '[]'::json)
  FROM pg_stat_activity
 WHERE backend_type = 'client backend' AND datname = current_database() AND pid <> pg_backend_pid()`

// Sessions lists a branch's client sessions. Free.
func Sessions(name string) ([]Session, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if _, err := EnsureRunning(name); err != nil {
		return nil, err
	}
	out, err := QuerySQL(name, sessionsSQL)
	if err != nil {
		return nil, fmt.Errorf("reading the sessions on %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	var ss []Session
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &ss); err != nil {
		return nil, fmt.Errorf("reading the sessions on %s: %w", name, err)
	}
	for i := range ss {
		if ss[i].BlockedBy == nil {
			ss[i].BlockedBy = []int{}
		}
	}
	if ss == nil {
		ss = []Session{}
	}
	return ss, nil
}

// SessionOf reports whether a login role is an account's own: its person's
// role, or its agent keys' (agent:<email>).
func SessionOf(user, email string) bool {
	if email == "" {
		return false
	}
	u := strings.ToLower(user)
	e := strings.ToLower(email)
	return u == e || u == agentKeyRolePrefix+e
}

// SignalSession cancels a session's running query, or with end, ends the
// session. only, when not "", is the account it must belong to (someone who
// may end only their own). It returns the session as it was. A session that is
// not a client's, or is the engine's own, is refused.
func SignalSession(name string, pid int, end bool, only string) (Session, error) {
	if pid <= 0 {
		return Session{}, fmt.Errorf("%w: a session is a process id, a positive number", ErrInvalidRequest)
	}
	ss, err := Sessions(name)
	if err != nil {
		return Session{}, err
	}
	var s *Session
	for i := range ss {
		if ss[i].PID == pid {
			s = &ss[i]
		}
	}
	switch {
	case s == nil:
		return Session{}, fmt.Errorf("%w: there is no client session %d on %s", ErrNotFound, pid, name)
	case only != "" && !SessionOf(s.User, only):
		// Said as not found: whose sessions another account has is not theirs to learn.
		return Session{}, fmt.Errorf("%w: there is no session %d of yours on %s", ErrNotFound, pid, name)
	case s.Engine:
		return *s, fmt.Errorf("%w: session %d is %s's own, and is not ended from here", ErrInvalidRequest, pid, "FoxByte")
	}
	fn := "pg_cancel_backend"
	if end {
		fn = "pg_terminate_backend"
	}
	out, err := QuerySQL(name, fmt.Sprintf("SELECT %s(%d)", fn, pid))
	if err != nil {
		return *s, fmt.Errorf("signalling session %d on %s: %w (%s)", pid, name, err, strings.TrimSpace(out))
	}
	if strings.TrimSpace(out) != "t" {
		return *s, fmt.Errorf("%w: session %d on %s had gone", ErrNotFound, pid, name)
	}
	return *s, nil
}

// TableStats is what the server knows of a table's upkeep.
type TableStats struct {
	Schema          string `json:"schema"`
	Table           string `json:"table"`
	Live            int64  `json:"live"` // estimated rows
	Dead            int64  `json:"dead"` // row versions a vacuum would reclaim
	Bytes           int64  `json:"bytes"`
	LastVacuum      string `json:"lastVacuum"` // "" when never
	LastAutoVacuum  string `json:"lastAutoVacuum"`
	LastAnalyze     string `json:"lastAnalyze"`
	LastAutoAnalyze string `json:"lastAutoAnalyze"`
	Vacuums         int64  `json:"vacuums"`
	Analyzes        int64  `json:"analyzes"`
}

func tableStatsSQL(where string) string {
	ts := func(c string) string {
		return fmt.Sprintf(`coalesce(to_char(%s AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '')`, c)
	}
	return `SELECT coalesce(json_agg(json_build_object('schema', schemaname, 'table', relname, 'live', n_live_tup, 'dead', n_dead_tup,
    'bytes', pg_total_relation_size(relid), 'lastVacuum', ` + ts("last_vacuum") + `, 'lastAutoVacuum', ` + ts("last_autovacuum") + `,
    'lastAnalyze', ` + ts("last_analyze") + `, 'lastAutoAnalyze', ` + ts("last_autoanalyze") + `,
    'vacuums', vacuum_count + autovacuum_count, 'analyzes', analyze_count + autoanalyze_count) ORDER BY schemaname, relname), '[]'::json)
  FROM pg_stat_user_tables
 WHERE schemaname NOT IN ('bb', 'bb_mask', 'bb_f1')` + where
}

// TablesStats lists a branch's tables' upkeep, or one table's when table is
// not "". The engine's own tables are left out. Free.
func TablesStats(name, schema, table string) ([]TableStats, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	if _, err := EnsureRunning(name); err != nil {
		return nil, err
	}
	where := ""
	if table != "" {
		if schema == "" {
			schema = "public"
		}
		where = " AND schemaname = " + quoteLiteral(schema) + " AND relname = " + quoteLiteral(table)
	}
	out, err := QuerySQL(name, tableStatsSQL(where))
	if err != nil {
		return nil, fmt.Errorf("reading the tables' upkeep on %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	var ts []TableStats
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &ts); err != nil {
		return nil, err
	}
	if ts == nil {
		ts = []TableStats{}
	}
	return ts, nil
}

// The maintenance a table can be given.
const (
	MaintVacuum        = "vacuum"
	MaintAnalyze       = "analyze"
	MaintVacuumAnalyze = "vacuum-analyze"
)

// maintSQL is the statement for one of them. VACUUM FULL is not offered: it
// locks the table against reads and writes for as long as it takes.
func maintSQL(op, schema, table string) (string, error) {
	rel := quoteIdent(schema) + "." + quoteIdent(table)
	switch op {
	case MaintVacuum:
		return "VACUUM " + rel, nil
	case MaintAnalyze:
		return "ANALYZE " + rel, nil
	case MaintVacuumAnalyze:
		return "VACUUM (ANALYZE) " + rel, nil
	}
	return "", fmt.Errorf("%w: maintenance is %s, %s or %s, not %q", ErrInvalidRequest, MaintVacuum, MaintAnalyze, MaintVacuumAnalyze, op)
}

// Maintain vacuums or analyses one of a branch's tables, as the engine: a
// table's owner might not be the person asking, and neither statement reads
// or changes what the table holds. It returns the table's upkeep afterwards
// and how long it took. Free.
func Maintain(name, schema, table, op string) (TableStats, time.Duration, error) {
	if err := checkName(name); err != nil {
		return TableStats{}, 0, err
	}
	if schema == "" {
		schema = "public"
	}
	stmt, err := maintSQL(op, schema, table)
	if err != nil {
		return TableStats{}, 0, err
	}
	if _, err := EnsureRunning(name); err != nil {
		return TableStats{}, 0, err
	}
	ok, err := QuerySQL(name, fmt.Sprintf("SELECT count(*) FROM pg_stat_user_tables WHERE schemaname = %s AND relname = %s AND schemaname NOT IN ('bb', 'bb_mask', 'bb_f1')",
		quoteLiteral(schema), quoteLiteral(table)))
	if err != nil {
		return TableStats{}, 0, fmt.Errorf("finding %s.%s on %s: %w", schema, table, name, err)
	}
	if strings.TrimSpace(ok) != "1" {
		return TableStats{}, 0, fmt.Errorf("%w: there is no table %s.%s on %s", ErrNotFound, schema, table, name)
	}
	start := time.Now()
	if out, err := longSQL(name, stmt+";\n", maintTimeout()); err != nil {
		return TableStats{}, 0, fmt.Errorf("%s of %s.%s on %s: %w (%s)", op, schema, table, name, err, strings.TrimSpace(out))
	}
	took := time.Since(start)
	// The statistics collector reports a moment later than the statement ends.
	var ts []TableStats
	for i := 0; i < 20; i++ {
		ts, err = TablesStats(name, schema, table)
		if err != nil || len(ts) != 1 || stampedAfter(ts[0], op, start) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || len(ts) != 1 {
		return TableStats{}, took, err
	}
	return ts[0], took, nil
}

// stampedAfter: the run's timestamp has reached the table's statistics.
func stampedAfter(t TableStats, op string, start time.Time) bool {
	at := t.LastVacuum
	if op == MaintAnalyze {
		at = t.LastAnalyze
	}
	ts, err := time.Parse(time.RFC3339, at)
	return err == nil && !ts.Before(start.Truncate(time.Second))
}

// maintTimeout bounds a vacuum of a large table.
func maintTimeout() time.Duration {
	if v, err := time.ParseDuration(envOr("FOX_MAINTENANCE_TIMEOUT", "")); err == nil && v > 0 {
		return v
	}
	return 2 * time.Hour
}

// longSQL runs a script as the engine, a statement at a time, for as long as
// timeout allows, and returns what it printed.
func longSQL(name, sql string, timeout time.Duration) (string, error) {
	cmd, ctx, cancel := sudoCmd(timeout, "docker", "exec", "-i",
		"--env-file", pgEnvFile(), container(name),
		"psql", "-X", "-q", "-tA", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1")
	defer cancel()
	cmd.Stdin = strings.NewReader("SET client_min_messages = warning;\n" + sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), execErr(ctx, timeout, "psql", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out))))
	}
	return string(out), nil
}

// ParsePID reads a session's process id from the command line or a path.
func ParsePID(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%w: %q is not a session's process id", ErrInvalidRequest, s)
	}
	return n, nil
}
