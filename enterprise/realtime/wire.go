//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import "sort"

// What a subscriber receives, and why it is shaped this way.
//
// The decisions here are the ones that are expensive to change later, because
// every client that has ever read the feed depends on them.
//
// **Values are Postgres text, as JSON strings — never JSON numbers.** A bigint
// and a numeric do not survive a JavaScript number: 9007199254740993 comes back
// as 9007199254740992, and 0.1+0.2 arithmetic quietly corrupts money. The type
// OID is on the schema event, so a client that wants a number can parse one
// knowing what it is.
//
// **NULL and the empty string stay distinguishable.** nil marshals to JSON null
// and an empty string to "", which a map[string]string could not express.
//
// **An unchanged TOASTed column is reported, not guessed.** Postgres does not
// send the value of a large column that an UPDATE did not touch, so it is
// absent from `new` entirely. A decoder that wrote null there would silently
// overwrite a good value in the subscriber's copy — the quietest data loss this
// design could produce. Those columns are named in `unchanged` instead.

// Value is one column's value: nil for SQL NULL, otherwise Postgres text.
type Value = *string

// ColumnKind is how pgoutput reports a column in a tuple.
const (
	KindNull      byte = 'n' // SQL NULL
	KindUnchanged byte = 'u' // a TOASTed value the update did not touch
	KindText      byte = 't' // the value, as Postgres renders it
)

// ColumnValue is one column as the stream carried it.
type ColumnValue struct {
	Kind byte
	Text string
}

// Column describes one column of a relation.
type Column struct {
	Name    string `json:"name"`
	TypeOID uint32 `json:"type_oid"`
	// Key is whether this column is part of the replica identity — the row
	// locator the subscriber can rely on.
	Key bool `json:"key"`
}

// Relation is a table's shape, as the stream most recently described it.
type Relation struct {
	Schema          string   `json:"schema"`
	Name            string   `json:"table"`
	Columns         []Column `json:"columns"`
	ReplicaIdentity byte     `json:"-"` // d default, f full, n nothing, i index
}

// Qualified is the table as a person writes it.
func (r Relation) Qualified() string { return r.Schema + "." + r.Name }

// Schema is sent when a subscriber attaches and again whenever a table's shape
// changes, so a client never has to guess what a row's columns mean.
type Schema struct {
	Type    string   `json:"type"` // "schema"
	Table   string   `json:"table"`
	Columns []Column `json:"columns"`
}

// Change is one row-level change.
type Change struct {
	Type   string `json:"type"`   // "change"
	Table  string `json:"table"`  // schema-qualified
	Action string `json:"action"` // insert | update | delete | truncate
	// CommitLSN is where to resume from: pass it back as ?since= and the feed
	// replays everything after it, within the WAL budget.
	CommitLSN string `json:"commit_lsn"`
	// Identity is always present: the replica-identity columns, which are the
	// only row locator that can be promised across every identity setting.
	Identity map[string]Value `json:"identity"`
	// New is the row after the change, for insert and update.
	New map[string]Value `json:"new,omitempty"`
	// Old is the row before it, and only when Postgres actually sent one —
	// which it does for an update or delete under REPLICA IDENTITY FULL.
	Old map[string]Value `json:"old,omitempty"`
	// Changed names the columns whose value differs, and only under FULL, where
	// it can be computed truthfully. Under the default identity there is no old
	// row to compare against and a guess would be worse than silence.
	Changed []string `json:"changed,omitempty"`
	// Unchanged names TOASTed columns the update did not touch, which are
	// therefore absent from New. A client must leave its own copy of these
	// alone rather than treat them as null.
	Unchanged []string `json:"unchanged,omitempty"`
}

// Notice is anything that is not a row: a resync, or a reason the stream ended.
type Notice struct {
	Type   string `json:"type"` // "resync" | "error"
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Reasons a stream says something other than a row.
const (
	CodeOverflow      = "overflow"       // this subscriber could not keep up
	CodeDecoderFailed = "decoder_failed" // the decoder gave up after repeated failures
	CodeSlotLost      = "slot_invalid"   // the WAL budget was exceeded; refetch and resubscribe
	CodeMaxDuration   = "max_duration"   // the stream's time limit; reconnect with ?since=
)

// BuildChange turns one decoded tuple into what a subscriber receives.
//
// Pure, and the whole of the wire format's judgement: what counts as the row's
// identity, when an old row may be reported, when a change list can be computed
// truthfully, and which columns were not sent at all.
func BuildChange(rel Relation, action, commitLSN string, oldTuple, newTuple []ColumnValue) Change {
	c := Change{
		Type: "change", Table: rel.Qualified(), Action: action, CommitLSN: commitLSN,
		Identity: map[string]Value{},
	}

	newVals, unchanged := values(rel, newTuple)
	oldVals, _ := values(rel, oldTuple)

	switch action {
	case "delete":
		// A delete under the default identity carries the key and nothing else:
		// Postgres sent only the identity columns. Under FULL it carries the
		// whole row, which is the only way a subscriber can reconstruct what
		// was lost — said plainly in the docs, because a client that needs the
		// old row must either keep its own copy or ask for FULL.
		if len(oldVals) > 0 {
			c.Identity = keyValues(rel, oldVals)
			if rel.ReplicaIdentity == 'f' {
				c.Old = oldVals
			}
		}
	case "insert":
		c.New = newVals
		c.Identity = keyValues(rel, newVals)
		c.Unchanged = unchanged
	default: // update
		c.New = newVals
		c.Unchanged = unchanged
		// The identity comes from the old tuple when there is one, because an
		// update may have changed the key itself and the subscriber needs the
		// row it used to know about.
		if len(oldVals) > 0 {
			c.Identity = keyValues(rel, oldVals)
			if rel.ReplicaIdentity == 'f' {
				c.Old = oldVals
				c.Changed = changedColumns(rel, oldVals, newVals, unchanged)
			}
		} else {
			c.Identity = keyValues(rel, newVals)
		}
	}
	return c
}

// values renders a tuple, and names the columns Postgres did not send.
func values(rel Relation, t []ColumnValue) (map[string]Value, []string) {
	if len(t) == 0 {
		return nil, nil
	}
	out := make(map[string]Value, len(t))
	var unchanged []string
	for i, cv := range t {
		if i >= len(rel.Columns) {
			break // the relation changed under us; the next schema event fixes it
		}
		name := rel.Columns[i].Name
		switch cv.Kind {
		case KindNull:
			out[name] = nil
		case KindUnchanged:
			// Deliberately not added to the map at all. Absent means "we were
			// not told"; null would mean "it is null", and writing one for the
			// other is how a subscriber's copy quietly loses data.
			unchanged = append(unchanged, name)
		default:
			text := cv.Text
			out[name] = &text
		}
	}
	sort.Strings(unchanged)
	return out, unchanged
}

// keyValues is the replica-identity columns of a rendered tuple.
func keyValues(rel Relation, vals map[string]Value) map[string]Value {
	out := map[string]Value{}
	for _, col := range rel.Columns {
		if !col.Key {
			continue
		}
		if v, ok := vals[col.Name]; ok {
			out[col.Name] = v
		}
	}
	return out
}

// changedColumns names the columns whose value differs between the old and new
// rows. Only meaningful under REPLICA IDENTITY FULL, and a column Postgres did
// not send is never called changed — it is unchanged by definition.
func changedColumns(rel Relation, oldVals, newVals map[string]Value, unchanged []string) []string {
	skip := map[string]bool{}
	for _, n := range unchanged {
		skip[n] = true
	}
	var out []string
	for _, col := range rel.Columns {
		if skip[col.Name] {
			continue
		}
		o, inOld := oldVals[col.Name]
		n, inNew := newVals[col.Name]
		if !inOld || !inNew {
			continue
		}
		switch {
		case o == nil && n == nil:
		case o == nil || n == nil, *o != *n:
			out = append(out, col.Name)
		}
	}
	sort.Strings(out)
	return out
}
