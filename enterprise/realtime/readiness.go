//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"fmt"
	"strings"
)

// Whether a table can stream, and what it would take.
//
// Preflight answers yes or no. That was enough while a person enabled one table
// at a time and could go and write the SQL themselves; it is not enough for an
// application with a hundred tables, where "no" without a path is the same as
// "this feature is not for you".
//
// So the question becomes a verdict: ready, fixable with these exact
// statements, or impossible for this reason. Preflight still exists and still
// refuses — Enable calls it — but it is now derived from the verdict rather
// than a second opinion, so the two cannot disagree about a table.

// State is what can be done with a table right now.
type State int

const (
	// Impossible is the zero value deliberately. A verdict nobody has computed
	// must not read as permission: the same reasoning as license.Invalid.
	Impossible State = iota
	Fixable
	Ready
	Streaming
)

func (s State) String() string {
	switch s {
	case Streaming:
		return "streaming"
	case Ready:
		return "ready"
	case Fixable:
		return "needs changes"
	}
	return "cannot stream"
}

// Fix is one statement that would move a table towards streaming.
//
// Cost is empty when the change is free. It is not empty for exactly one rung
// of the ladder, and that is the point of carrying it: the fix a person will
// click without reading is the one with a permanent bill.
type Fix struct {
	SQL  string `json:"sql"`
	Why  string `json:"why"`
	Cost string `json:"cost,omitempty"`
}

// Free reports whether this change costs nothing beyond running it.
func (c Fix) Free() bool { return c.Cost == "" }

// Verdict is everything known about one table's readiness.
type Verdict struct {
	Table  Table  `json:"table"`
	State  State  `json:"-"`
	Status string `json:"status"`
	Fixes  []Fix  `json:"fixes,omitempty"`
	// Alternatives are ways forward that change the subscription rather than
	// the database — streaming inserts only, say. They are offered, never
	// applied: nothing here decides that a table's updates do not matter.
	Alternatives []string `json:"alternatives,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// Costly reports whether any change in this verdict has an ongoing price.
// `prepare --all` uses it to leave those tables alone.
func (v Verdict) Costly() bool {
	for _, c := range v.Fixes {
		if !c.Free() {
			return true
		}
	}
	return false
}

// Assess walks the ladder: a table takes the cheapest rung that works.
//
//  1. a primary key, or an identity already set   nothing to do
//  2. a unique index that could be the identity   USING INDEX — costs what a key costs
//  3. append-only                                 stream inserts; no identity needed
//  4. nothing unique                              REPLICA IDENTITY FULL, and only here
//
// Rung 2 is the one that matters. Postgres will use any unique, valid,
// non-partial index on NOT NULL columns as the replica identity, at the same
// price as a primary key and with no schema change — so "no primary key" almost
// never has to mean "pay double". It only does when a table has nothing unique
// about it at all.
func Assess(t Table, events []string, published bool) Verdict {
	v := Verdict{Table: t}
	defer func() { v.Status = v.State.String() }()

	// The refusals, in the order that gives the most useful answer first.
	switch {
	case t.IsSystem || t.systemSchema():
		v.Reason = fmt.Sprintf("%s belongs to FoxByte or to Postgres, not to this application. "+
			"Streaming %s would hand a subscriber the database's own bookkeeping", t.Qualified(), t.Schema)
		return v
	case t.IsExtensionOwned:
		v.Reason = fmt.Sprintf("%s was created by an extension and is its to manage", t.Qualified())
		return v
	case t.Kind == "v" || t.Kind == "m":
		v.Reason = fmt.Sprintf("%s is a view: a change feed streams the tables a view reads, "+
			"so enable those instead", t.Qualified())
		return v
	case t.Kind != "r" && t.Kind != "p":
		v.Reason = fmt.Sprintf("%s is not a table", t.Qualified())
		return v
	case t.RLSEnabled:
		v.Reason = fmt.Sprintf("%s has row-level security, and a change feed cannot apply it: "+
			"decoded WAL has had no policy evaluated against it, so every subscriber would "+
			"receive every row. There is no override — this one is a data breach rather than "+
			"an inconvenience", t.Qualified())
		return v
	}

	// Everything below here is fixable, so collect the changes rather than
	// returning at the first one: a table that needs a grant and an identity
	// should say so once.
	if !t.ClientCanUseSchema {
		v.Fixes = append(v.Fixes, Fix{
			SQL: fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO db_client;", quoteIdent(t.Schema)),
			Why: "db_client cannot reach the " + t.Schema + " schema at all. A table grant is not " +
				"enough on its own: the default privileges the engine sets up cover public only",
		})
	}
	if !t.ClientCanSelect {
		v.Fixes = append(v.Fixes, Fix{
			SQL: fmt.Sprintf("GRANT SELECT ON %s TO db_client;", t.Qualified()),
			Why: "a change feed carries whole rows, so it may only stream what db_client could " +
				"already read — every client session is logged in as that role",
		})
	} else if len(t.ColumnsHidden) > 0 {
		v.Fixes = append(v.Fixes, Fix{
			SQL: fmt.Sprintf("GRANT SELECT (%s) ON %s TO db_client;",
				strings.Join(t.ColumnsHidden, ", "), t.Qualified()),
			Why: "db_client cannot read these columns, and a change feed carries whole rows",
		})
	}

	if needsIdentity(events) && !t.Identifiable() {
		switch {
		case t.UniqueIndex != "":
			v.Fixes = append(v.Fixes, Fix{
				SQL: fmt.Sprintf("ALTER TABLE %s REPLICA IDENTITY USING INDEX %s;",
					t.Qualified(), quoteIdent(t.UniqueIndex)),
				Why: fmt.Sprintf("updates and deletes need a way to name the row they changed, and %s "+
					"is unique and NOT NULL — it costs what a primary key costs", t.UniqueIndex),
			})
		default:
			v.Fixes = append(v.Fixes, Fix{
				SQL: fmt.Sprintf("ALTER TABLE %s REPLICA IDENTITY FULL;", t.Qualified()),
				Why: "updates and deletes need a way to name the row they changed, and this table has " +
					"no primary key and no unique index to name it by",
				Cost: t.FullCost(),
			})
			if ins, upd, del := t.Inserts, t.Updates, t.Deletes; upd == 0 && del == 0 && ins > 0 {
				v.Alternatives = append(v.Alternatives, "this table has only ever been inserted into: "+
					"streaming inserts alone needs no replica identity and costs nothing extra")
			}
			v.Alternatives = append(v.Alternatives,
				"a primary key, or any unique NOT NULL index, would cost the same as this table costs today")
		}
	}

	switch {
	case published:
		v.State = Streaming
	case len(v.Fixes) == 0:
		v.State = Ready
	default:
		v.State = Fixable
	}
	return v
}

// systemSchema applies the cheap half of the rule again, in Go, over the name
// alone.
//
// IsSystem is computed by the catalog query and is the authoritative version:
// it also catches a table an extension created wherever it put it. This repeats
// the part that can be checked without a database, so the decision never
// depends on a caller having remembered to fill in a field. "Never stream the
// Blackbox" is a rule worth holding in two places.
func (t Table) systemSchema() bool {
	return t.Schema == "bb" ||
		t.Schema == "pg_catalog" || t.Schema == "information_schema" ||
		strings.HasPrefix(t.Schema, "pg_")
}

// Identifiable reports whether Postgres can already name the row an update or
// delete touched: a primary key, or a replica identity someone has set.
func (t Table) Identifiable() bool {
	return t.HasPrimaryKey || t.ReplicaIdentity == 'f' || t.ReplicaIdentity == 'i'
}

// needsIdentity reports whether the requested events include one that has to
// name a row that already existed.
func needsIdentity(events []string) bool {
	if len(events) == 0 {
		return true // the default is all three
	}
	for _, e := range events {
		if e == "update" || e == "delete" {
			return true
		}
	}
	return false
}

// quoteIdent is the local half of branch.QuoteIdent, kept here so the pure
// decisions in this file need nothing from the engine.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
