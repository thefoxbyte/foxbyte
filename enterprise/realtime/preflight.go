//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package realtime is the row-level change feed.
package realtime

import (
	"fmt"
	"sort"
	"strings"
)

// What a table has to be before it may be streamed.
//
// Decoded WAL carries no authorization: the decoder sees every row of every
// table in the publication, whoever is subscribed. So the checks have to happen
// when a table is enabled, once, rather than per row — and they have to be
// refusals rather than warnings, because there is nothing downstream to catch
// what gets through.
//
// This is deliberately a pure function over a struct. The facts come from the
// catalog, but the decisions are the part worth being able to read and test
// without a database.

// Table is what the catalog says about one relation.
type Table struct {
	Schema          string
	Name            string
	Kind            string   // pg_class.relkind: r ordinary, p partitioned, v view, m matview
	HasPrimaryKey   bool     //
	ReplicaIdentity string   // pg_class.relreplident: d default, f full, n nothing, i index
	RLSEnabled      bool     // relrowsecurity
	ClientCanSelect bool     // db_client has SELECT on the relation
	ColumnsHidden   []string // columns db_client may not read
}

// Request is one `fox realtime enable`.
type Request struct {
	Table  Table
	Events []string // insert, update, delete; empty means all three
	// FullIdentity is --replica-identity=full: the caller accepting the extra
	// WAL per update in exchange for streaming a table with no primary key.
	FullIdentity bool
}

// Qualified is the table as a person wrote it.
func (t Table) Qualified() string { return t.Schema + "." + t.Name }

// Events is the request's events, defaulted and ordered.
func (r Request) EventList() []string {
	if len(r.Events) == 0 {
		return []string{"insert", "update", "delete"}
	}
	out := append([]string(nil), r.Events...)
	sort.Strings(out)
	return out
}

// Publishes reports whether this request would publish an event that needs a
// row to be identifiable afterwards.
func (r Request) PublishesChanges() bool {
	for _, e := range r.EventList() {
		if e == "update" || e == "delete" {
			return true
		}
	}
	return false
}

// Preflight returns nil when a table may be streamed, and the reason it may not
// otherwise. Every reason names what to do instead, because every one of them
// has a way forward and a refusal that does not say so reads as a bug.
func Preflight(r Request) error {
	t := r.Table

	for _, e := range r.EventList() {
		switch e {
		case "insert", "update", "delete":
		default:
			return fmt.Errorf("%q is not an event: use insert, update or delete", e)
		}
	}

	// Row-level security is the one case where a feed would widen access.
	//
	// Everyone who can reach a branch can already SELECT every public table —
	// ledger.sql grants db_client exactly that — so a feed over those tables
	// gives away nothing new. RLS is the exception: db_client is NOBYPASSRLS
	// and the gateway logs clients in so their sessions obey policies, but
	// decoded WAL has had no policy applied to it. Every subscriber would see
	// every row.
	//
	// There is no --force for this, and that is deliberate: an override here is
	// a data breach with an audit trail. Per-subscriber row filters are a
	// separate feature with their own security argument to make.
	if t.RLSEnabled {
		return fmt.Errorf("%s has row-level security, and a change feed cannot apply it: "+
			"decoded WAL has had no policy evaluated against it, so every subscriber would "+
			"receive every row. There is no override — this one is a data breach rather than "+
			"an inconvenience", t.Qualified())
	}

	// Anything db_client cannot already read is not ours to stream.
	if !t.ClientCanSelect {
		return fmt.Errorf("db_client cannot SELECT %s, so a change feed would hand out rows "+
			"nobody could otherwise read. Grant SELECT first, or leave it out", t.Qualified())
	}
	if len(t.ColumnsHidden) > 0 {
		return fmt.Errorf("db_client cannot read %s on %s, and a change feed carries whole rows: "+
			"grant SELECT on those columns, or leave this table out",
			strings.Join(t.ColumnsHidden, ", "), t.Qualified())
	}

	// Only ordinary and partitioned tables have a WAL story worth decoding.
	switch t.Kind {
	case "r", "p":
	case "v", "m":
		return fmt.Errorf("%s is a view: a change feed streams the tables a view reads, "+
			"so enable those instead", t.Qualified())
	default:
		return fmt.Errorf("%s is not a table", t.Qualified())
	}

	// Only public, and never the Blackbox.
	//
	// bb.schema_ledger holds the recorded text of every statement, so streaming
	// it would hand a subscriber the DDL history of the database. The feed is
	// never FOR ALL TABLES for the same reason.
	if t.Schema != "public" {
		return fmt.Errorf("only tables in the public schema can be streamed; %s is in %s",
			t.Qualified(), t.Schema)
	}

	// The trap this function exists for.
	//
	// Adding a table with no replica identity to a publication that publishes
	// updates makes every later UPDATE and DELETE on it *fail* — "cannot update
	// table … because it does not have a replica identity". Enabling a feed
	// would break queries that work today, which is exactly what the additive
	// rule forbids. So it is refused, and both ways forward are named.
	if r.PublishesChanges() && !t.HasPrimaryKey && t.ReplicaIdentity != "f" && !r.FullIdentity {
		return fmt.Errorf("%s has no primary key, and publishing updates or deletes for a table "+
			"without one makes every later UPDATE and DELETE on it fail. Either "+
			"--replica-identity=full (more WAL per update, and the change is recorded in the "+
			"Blackbox like any other DDL) or --events=insert", t.Qualified())
	}
	return nil
}
