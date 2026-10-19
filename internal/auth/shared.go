// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The accounts, credentials and authorisation a second machine needs — read out
// of this store, and read back into another one.
//
// Phase 2 of docs/FOX_HA_Plan.md asks for state "every node can reach". The
// decision recorded in §3.2 is that it must not live in `main`: this package
// imports exactly one package of ours (internal/brand), never internal/branch,
// so signing in, verifying a key and appending to the security log all work
// while the database engine is down — and that window is precisely the one the
// phase exists to protect. Putting the accounts inside the thing that fails
// over would guarantee nobody could sign in during it.
//
// So each node keeps its own store and the rows are carried between them. This
// file is the half that belongs to the store: a document out, a document in,
// and a digest that says whether anything that matters has changed. It knows
// nothing about how the document travels — that is internal/branch/statesync.go,
// which may import this package and not the other way round.
//
// What is carried, and what is not:
//
//   - users, api_keys, oauth_identities, branch_owners — who exists, what they
//     may use, and which credential proves it. Without these a failover leaves
//     nobody able to sign in, which is the phase's stated unlock.
//   - pipelines, pipeline_targets, change_requests — authored records. Small,
//     slow-changing, and losing them to a machine failure would be losing
//     somebody's work.
//   - sessions: deliberately not. A browser session is minutes old and cheap to
//     replace; carrying tokens between machines would widen what a stolen
//     document is worth, for the convenience of not signing in again.
//   - pipeline_runs, realtime_activity: deliberately not. Both are append-only
//     logs that grow without bound, and this mechanism carries a whole document
//     each time it changes. Neither is needed to sign in or to serve a client.
//   - query_history, saved_queries, history_optout, history_settings:
//     deliberately not. The SQL people type is the last thing to replicate
//     (history.go, saved.go), and the settings are this node's.
//   - security_events: deliberately not. It is a hash chain, and a chain is a
//     per-writer structure — two nodes' chains cannot be merged into one, and
//     overwriting one node's chain with another's would destroy the evidence
//     the chain exists to keep. Each node keeps its own, which is the honest
//     reading: the log records what *that* node did.

// SharedStateVersion is the document's shape. A node that is sent a shape it
// does not know refuses the document rather than guessing at the columns, so an
// upgrade in progress cannot half-apply somebody's accounts.
const SharedStateVersion = 1

// mirror is one table carried between nodes.
type mirror struct {
	table string
	cols  []string
	pk    []string
	// volatile columns ride along but are left out of the digest. api_keys has
	// last_used, bumped on every authenticated request: counted, it would make
	// the document "changed" every few seconds for ever, and the node would
	// ship accounts in a permanent loop to say that somebody used a key.
	volatile []string
}

// mirrored is the carried set, in an order that satisfies the foreign keys:
// parents before children on the way in, and the reverse on the way out.
var mirrored = []mirror{
	{table: "users", cols: []string{"id", "email", "pw_hash", "created"}, pk: []string{"id"}},
	{table: "api_keys", cols: []string{"id", "user_id", "name", "key_hash", "prefix", "created", "last_used", "scope", "kind"},
		pk: []string{"id"}, volatile: []string{"last_used"}},
	{table: "oauth_identities", cols: []string{"provider", "subject", "user_id"}, pk: []string{"provider", "subject"}},
	{table: "branch_owners", cols: []string{"branch", "user_id", "created"}, pk: []string{"branch"}},
	{table: "pipelines", cols: []string{"id", "user_id", "name", "spec", "created", "updated"}, pk: []string{"id"}},
	{table: "pipeline_targets", cols: []string{"branch", "pipeline_id"}, pk: []string{"branch"}},
	{table: "change_requests", cols: []string{"id", "source", "target", "created_by", "created", "status",
		"fork_after_id", "entries", "decided_by", "decided", "note", "applied"}, pk: []string{"id"}},
}

// sharedDoc is what crosses between machines.
//
// Values are text or null, every one of them, because a round trip through
// anything else is a round trip through a guess: the driver decides whether an
// integer column arrives as int64, a float or a string, and JSON turns a []byte
// into base64 that would be written back as the literal characters of the
// encoding. SQLite's column affinity converts text back to the column's type on
// the way in, so text is both the safest and the simplest form.
type sharedDoc struct {
	Version int                    `json:"version"`
	Tables  map[string]*sharedRows `json:"tables"`
}

type sharedRows struct {
	Cols []string    `json:"cols"`
	Rows [][]*string `json:"rows"`
}

// SharedState reads the carried tables out of this store as one document, with
// a digest of everything in it that is worth noticing a change in.
func (s *Store) SharedState() (doc []byte, digest string, err error) {
	d := sharedDoc{Version: SharedStateVersion, Tables: map[string]*sharedRows{}}
	for _, m := range mirrored {
		rows, err := s.readMirror(m)
		if err != nil {
			return nil, "", fmt.Errorf("reading %s: %w", m.table, err)
		}
		d.Tables[m.table] = rows
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, "", err
	}
	return b, sharedDigest(d), nil
}

// SharedStateDigest is the digest alone, for a caller asking only whether
// anything has changed.
func (s *Store) SharedStateDigest() (string, error) {
	d := sharedDoc{Version: SharedStateVersion, Tables: map[string]*sharedRows{}}
	for _, m := range mirrored {
		rows, err := s.readMirror(m)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", m.table, err)
		}
		d.Tables[m.table] = rows
	}
	return sharedDigest(d), nil
}

func (s *Store) readMirror(m mirror) (*sharedRows, error) {
	// Ordered by the primary key, so two stores holding the same rows produce
	// the same document and therefore the same digest. Without this the digest
	// would change whenever SQLite happened to return rows differently.
	q := fmt.Sprintf("SELECT %s FROM %s ORDER BY %s",
		castText(m.cols), m.table, strings.Join(m.pk, ", "))
	rs, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := &sharedRows{Cols: m.cols, Rows: [][]*string{}}
	for rs.Next() {
		vals := make([]*string, len(m.cols))
		into := make([]any, len(m.cols))
		for i := range vals {
			into[i] = &vals[i]
		}
		if err := rs.Scan(into...); err != nil {
			return nil, err
		}
		out.Rows = append(out.Rows, vals)
	}
	return out, rs.Err()
}

// castText asks SQLite for every value as text, including the integers. A NULL
// stays NULL: CAST(NULL AS TEXT) is NULL, which is what keeps "never used" and
// "used at epoch 0" different things.
func castText(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = fmt.Sprintf("CAST(%s AS TEXT)", c)
	}
	return strings.Join(q, ", ")
}

// sharedDigest is a hash of the carried rows, leaving out the volatile columns.
// Pure, so the rule about what counts as a change is a test rather than a
// property of whichever node happened to run.
func sharedDigest(d sharedDoc) string {
	h := sha256.New()
	fmt.Fprintf(h, "foxbyte-shared-state/%d\n", d.Version)
	names := make([]string, 0, len(d.Tables))
	for n := range d.Tables {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		skip := map[int]bool{}
		for _, m := range mirrored {
			if m.table != n {
				continue
			}
			for i, c := range d.Tables[n].Cols {
				for _, v := range m.volatile {
					if c == v {
						skip[i] = true
					}
				}
			}
		}
		fmt.Fprintf(h, "table %s\n", n)
		for _, row := range d.Tables[n].Rows {
			for i, v := range row {
				if skip[i] {
					continue
				}
				switch {
				case v == nil:
					h.Write([]byte("\x00null\x00"))
				default:
					fmt.Fprintf(h, "\x00%d:%s", len(*v), *v)
				}
			}
			h.Write([]byte("\n"))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SharedApply is what applying a document changed.
type SharedApply struct {
	Written int // rows inserted or updated
	Removed int // rows deleted because the document no longer has them
	Digest  string
}

// Changed reports whether applying the document altered this store.
func (a SharedApply) Changed() bool { return a.Written > 0 || a.Removed > 0 }

// ApplySharedState writes a document from another node into this store.
//
// One transaction, so a node is never left with half of somebody's accounts:
// either the whole document applies or none of it does. Rows are upserted and
// rows the document no longer carries are deleted, in an order that satisfies
// the foreign keys. A table is never emptied and refilled — `pipelines` has
// children that are deliberately not carried (`pipeline_runs`, ON DELETE
// CASCADE), and emptying it would delete this node's run history every time the
// document arrived.
func (s *Store) ApplySharedState(doc []byte) (SharedApply, error) {
	var d sharedDoc
	if err := json.Unmarshal(doc, &d); err != nil {
		return SharedApply{}, fmt.Errorf("the shared-state document is not readable: %w", err)
	}
	if d.Version != SharedStateVersion {
		return SharedApply{}, fmt.Errorf("the shared-state document is version %d and this node understands %d — "+
			"upgrade this node before it applies the other's accounts", d.Version, SharedStateVersion)
	}
	for _, m := range mirrored {
		t, ok := d.Tables[m.table]
		if !ok {
			return SharedApply{}, fmt.Errorf("the shared-state document carries no %s", m.table)
		}
		if strings.Join(t.Cols, ",") != strings.Join(m.cols, ",") {
			return SharedApply{}, fmt.Errorf("the shared-state document's %s has columns %v and this node expects %v",
				m.table, t.Cols, m.cols)
		}
		for _, r := range t.Rows {
			if len(r) != len(m.cols) {
				return SharedApply{}, fmt.Errorf("a %s row in the shared-state document has %d values for %d columns",
					m.table, len(r), len(m.cols))
			}
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return SharedApply{}, err
	}
	defer func() { _ = tx.Rollback() }()

	out := SharedApply{}
	// Children first on the way out: a row whose parent is about to go has to
	// go first, or the foreign key refuses it.
	for i := len(mirrored) - 1; i >= 0; i-- {
		n, err := deleteMissing(tx, mirrored[i], d.Tables[mirrored[i].table])
		if err != nil {
			return SharedApply{}, fmt.Errorf("removing %s rows this node no longer has: %w", mirrored[i].table, err)
		}
		out.Removed += n
	}
	// Parents first on the way in, for the same reason in reverse.
	for _, m := range mirrored {
		n, err := upsertRows(tx, m, d.Tables[m.table])
		if err != nil {
			return SharedApply{}, fmt.Errorf("writing %s: %w", m.table, err)
		}
		out.Written += n
	}
	if err := tx.Commit(); err != nil {
		return SharedApply{}, err
	}
	out.Digest = sharedDigest(d)
	return out, nil
}

func upsertRows(tx *sql.Tx, m mirror, rows *sharedRows) (int, error) {
	if len(rows.Rows) == 0 {
		return 0, nil
	}
	set := make([]string, 0, len(m.cols))
	for _, c := range m.cols {
		if !contains(m.pk, c) {
			set = append(set, fmt.Sprintf("%s = excluded.%s", c, c))
		}
	}
	q := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s",
		m.table, strings.Join(m.cols, ", "), placeholders(len(m.cols)),
		strings.Join(m.pk, ", "), strings.Join(set, ", "))
	if len(set) == 0 {
		// Every column is part of the key, so there is nothing to update.
		q = fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING",
			m.table, strings.Join(m.cols, ", "), placeholders(len(m.cols)), strings.Join(m.pk, ", "))
	}
	st, err := tx.Prepare(q)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	n := 0
	for _, r := range rows.Rows {
		args := make([]any, len(r))
		for i, v := range r {
			if v == nil {
				args[i] = nil
			} else {
				args[i] = *v
			}
		}
		if _, err := st.Exec(args...); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func deleteMissing(tx *sql.Tx, m mirror, rows *sharedRows) (int, error) {
	// Built from the document's keys rather than compared row by row, so one
	// statement does it however many rows there are. An empty document means
	// the other node has none of this table, and then every local row goes.
	idx := make([]int, 0, len(m.pk))
	for _, k := range m.pk {
		for i, c := range m.cols {
			if c == k {
				idx = append(idx, i)
			}
		}
	}
	keyExpr := make([]string, len(m.pk))
	for i, k := range m.pk {
		keyExpr[i] = fmt.Sprintf("CAST(%s AS TEXT)", k)
	}
	key := strings.Join(keyExpr, " || '\x1f' || ")

	args := []any{}
	for _, r := range rows.Rows {
		parts := make([]string, 0, len(idx))
		for _, i := range idx {
			if r[i] == nil {
				parts = nil
				break
			}
			parts = append(parts, *r[i])
		}
		if parts == nil {
			continue // a null key is not a key; such a row cannot be matched
		}
		args = append(args, strings.Join(parts, "\x1f"))
	}
	q := fmt.Sprintf("DELETE FROM %s WHERE %s NOT IN (%s)", m.table, key, placeholders(len(args)))
	if len(args) == 0 {
		q = fmt.Sprintf("DELETE FROM %s", m.table)
	}
	res, err := tx.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func placeholders(n int) string {
	if n == 0 {
		return "NULL"
	}
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}
