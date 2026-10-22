// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Row tracking (points 5.1, 5.2 and 6.1): who changed each row of a table,
// whom for, and when, kept by a trigger in the table's own database. The
// rules are in internal/ledger/tracking.sql; this is the engine's half, which
// turns it on and off for `fox track` and the console.
//
// It runs as the superuser, because tracking adds columns to a table that may
// belong to another role, in one transaction that first names the person who
// asked, so the Blackbox records the table's change under their name. Turning
// it off needs the guardrail override, which the trigger's protection asks for;
// the engine gives it to its own statement and to nothing else.

// TrackOptions are the columns a tracked table keeps. An empty name is a column
// it does not keep; at least one is needed.
type TrackOptions struct {
	Created string `json:"created"`
	Updated string `json:"updated"`
	By      string `json:"by"`
	// For is whom the row was last changed for, where the transaction said
	// so (application identity): asserted:<app>:<user>, claimed:<user>, or
	// NULL. Point 5.2.
	For string `json:"for"`
	// LabelExisting gives rows already in the table the moment tracking
	// began, instead of leaving them empty.
	LabelExisting bool `json:"label_existing,omitempty"`
}

// DefaultTrackOptions are the column names unless someone chooses others.
var DefaultTrackOptions = TrackOptions{Created: "created_at", Updated: "updated_at", By: "last_modified_by", For: "last_modified_for"}

// TrackedTable is a table being tracked, and the columns it keeps.
type TrackedTable struct {
	Schema  string `json:"schema"`
	Name    string `json:"name"`
	Created string `json:"created"`
	Updated string `json:"updated"`
	By      string `json:"by"`
	For     string `json:"for"`
}

// TrackSettings is a branch's choice for tables made from now on.
type TrackSettings struct {
	TrackNew bool   `json:"track_new"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
	By       string `json:"by"`
	For      string `json:"for"`
}

// Tracking is a branch's row tracking: the settings and every tracked table.
type Tracking struct {
	Settings TrackSettings  `json:"settings"`
	Tables   []TrackedTable `json:"tables"`
}

// CheckTrackOptions refuses names Postgres could not take.
func CheckTrackOptions(o TrackOptions) error {
	names := []string{o.Created, o.Updated, o.By, o.For}
	seen := map[string]bool{}
	n := 0
	for _, c := range names {
		if c == "" {
			continue
		}
		n++
		if len(c) > 63 {
			return fmt.Errorf("a column name is at most 63 bytes: %q", c)
		}
		if seen[c] {
			return fmt.Errorf("the columns need different names, not %q twice", c)
		}
		seen[c] = true
	}
	if n == 0 {
		return errors.New("tracking keeps at least one column")
	}
	return nil
}

// trackSQL wraps a tracking change: one transaction, the person who asked
// named for the Blackbox, and the override only where the change needs it.
func trackSQL(actor, tool, body string, override bool) string {
	var b strings.Builder
	b.WriteString("BEGIN;\n")
	fmt.Fprintf(&b, "SELECT set_config('bb.actor', %s, true), set_config('application_name', %s, true);\n",
		QuoteLiteral(actor), QuoteLiteral(tool))
	if override {
		b.WriteString("SET LOCAL bb.allow_destructive = on;\n")
	}
	b.WriteString(body + "\n")
	b.WriteString("COMMIT;\n")
	return b.String()
}

// tableRef is a table as a regclass, from its schema and name, quoted.
func tableRef(schema, table string) string {
	if schema == "" {
		schema = "public"
	}
	return fmt.Sprintf("format('%%I.%%I', %s, %s)::regclass", QuoteLiteral(schema), QuoteLiteral(table))
}

// TrackTable starts tracking a table. A table tracked already gains the for
// column, if it is asked for and the table lacks it; nothing else changes.
func TrackTable(target, schema, table string, o TrackOptions, actor, tool string) error {
	if err := CheckTrackOptions(o); err != nil {
		return err
	}
	return trackExec(target, trackSQL(actor, tool, trackTableSQL(tableRef(schema, table), o), false))
}

// trackTableSQL calls bb.track_table: the five-argument form when there is no
// for column, which every branch has, and the six-argument one otherwise.
func trackTableSQL(rel string, o TrackOptions) string {
	if o.For == "" {
		return fmt.Sprintf("SELECT bb.track_table(%s, %s, %s, %s, %t);",
			rel, QuoteLiteral(o.Created), QuoteLiteral(o.Updated), QuoteLiteral(o.By), o.LabelExisting)
	}
	return fmt.Sprintf("SELECT bb.track_table(%s, %s, %s, %s, %s, %t);",
		rel, QuoteLiteral(o.Created), QuoteLiteral(o.Updated), QuoteLiteral(o.By), QuoteLiteral(o.For), o.LabelExisting)
}

// UntrackTable stops tracking a table; its columns, and what they hold, stay.
func UntrackTable(target, schema, table, actor, tool string) error {
	return trackExec(target, trackSQL(actor, tool, fmt.Sprintf("SELECT bb.untrack_table(%s);", tableRef(schema, table)), true))
}

// SetTrackNew turns tracking of tables made from now on on or off, and the
// names their columns get.
func SetTrackNew(target string, on bool, o TrackOptions, actor, tool string) error {
	if err := CheckTrackOptions(o); err != nil {
		return err
	}
	return trackExec(target, trackSQL(actor, tool, setTrackNewSQL(on, o), false))
}

// setTrackNewSQL writes the settings. for_col is named only when there is one,
// so a branch whose settings predate it can still be turned on and off.
func setTrackNewSQL(on bool, o TrackOptions) string {
	forCol := ""
	if o.For != "" {
		forCol = ", for_col = " + QuoteLiteral(o.For)
	}
	return fmt.Sprintf("UPDATE bb.track_settings SET track_new = %t, created_col = %s, updated_col = %s, by_col = %s%s;",
		on, QuoteLiteral(o.Created), QuoteLiteral(o.Updated), QuoteLiteral(o.By), forCol)
}

// TrackingOf reads a branch's row tracking.
func TrackingOf(target string) (Tracking, error) {
	// for_col through to_jsonb: '' on a branch whose tracking predates it,
	// rather than an error.
	out, err := QuerySQL(target, `SELECT json_build_object(
		'settings', (SELECT json_build_object('track_new', track_new, 'created', created_col, 'updated', updated_col, 'by', by_col,
		    'for', coalesce(to_jsonb(s) ->> 'for_col', '')) FROM bb.track_settings s),
		'tables', coalesce((SELECT json_agg(json_build_object('schema', n.nspname, 'name', c.relname,
		    'created', t.created_col, 'updated', t.updated_col, 'by', t.by_col, 'for', coalesce(to_jsonb(t) ->> 'for_col', ''))
		    ORDER BY n.nspname, c.relname)
		  FROM bb.tracked_tables() t JOIN pg_class c ON c.oid = t.rel JOIN pg_namespace n ON n.oid = c.relnamespace), '[]'::json))`)
	if err != nil {
		return Tracking{}, fmt.Errorf("reading row tracking on %s: %w (%s)", target, err, strings.TrimSpace(out))
	}
	var t Tracking
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &t); err != nil {
		return Tracking{}, fmt.Errorf("reading row tracking on %s: %w", target, err)
	}
	if t.Tables == nil {
		t.Tables = []TrackedTable{}
	}
	return t, nil
}

// trackExec is psqlStdin with Postgres's complaint as the error rather than
// on this process's stderr: the console shows why a table could not be
// tracked ("column created_at of public.orders is date").
func trackExec(name, sql string) error {
	cmd := exec.Command("sudo", "docker", "exec", "-i",
		"--env-file", pgEnvFile(), container(name),
		"psql", "-U", pgUser, "-d", pgDatabase, "-v", "ON_ERROR_STOP=1", "-q", "-o", "/dev/null")
	cmd.Stdin = strings.NewReader(sql)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := psqlError(stderr.String()); msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

var rePsqlError = regexp.MustCompile(`(?m)^(?:psql:[^:]*:\d+: )?ERROR:\s+(.*)$`)

// psqlError is the first ERROR line psql wrote, without its prefix.
func psqlError(stderr string) string {
	if m := rePsqlError.FindStringSubmatch(stderr); m != nil {
		return strings.TrimSpace(m[1])
	}
	return strings.TrimSpace(stderr)
}
