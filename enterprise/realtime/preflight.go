//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package realtime is the row-level change feed.
package realtime

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/brand"
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
	Schema          string `json:"schema"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`              // pg_class.relkind: r ordinary, p partitioned, v view, m matview
	HasPrimaryKey   bool   `json:"has_primary_key"`   //
	ReplicaIdentity byte   `json:"-"`                 // pg_class.relreplident: d default, f full, n nothing, i index
	RLSEnabled      bool   `json:"rls_enabled"`       // relrowsecurity
	ClientCanSelect bool   `json:"client_can_select"` // db_client has SELECT on the relation
	// ClientCanUseSchema is separate from the table grant and easy to miss:
	// has_table_privilege answers about the table's own ACL and says nothing
	// about reaching it. A table in a schema db_client has no USAGE on reports
	// SELECT and is unreadable, which would only show up once the feed was on.
	ClientCanUseSchema bool     `json:"client_can_use_schema"`
	ColumnsHidden      []string `json:"columns_hidden,omitempty"` // columns db_client may not read

	// IsSystem is FoxByte's own schema or Postgres's. Only tables an
	// application made are streamable: bb holds the recorded text of every
	// statement, and a subscriber has no business reading the catalog.
	IsSystem bool `json:"is_system"`
	// IsExtensionOwned catches what the schema test cannot — an extension may
	// create its tables anywhere, including in public, where the old
	// public-only rule let them through.
	IsExtensionOwned bool `json:"is_extension_owned"`

	// UniqueIndex is an index Postgres would accept as the replica identity:
	// unique, valid, not partial, every column NOT NULL. Empty when there is
	// none, which is the only case that has to pay for REPLICA IDENTITY FULL.
	UniqueIndex string `json:"unique_index,omitempty"`

	// What the table has done since statistics were last reset, from
	// pg_stat_user_tables. Postgres counts these already, so the cost of a
	// change can be stated as a measured number rather than an adjective.
	Inserts     int64   `json:"inserts"`
	Updates     int64   `json:"updates"`
	Deletes     int64   `json:"deletes"`
	StatsDays   float64 `json:"stats_days"`    // how long those counts cover
	AvgRowBytes int64   `json:"avg_row_bytes"` // total size / live rows
}

// FullCost is what REPLICA IDENTITY FULL would add, in the user's own numbers.
//
// FULL writes the whole old row to the WAL on every UPDATE, so the extra is
// roughly one row per update. Measured rather than guessed, and said as an
// estimate because the average row size is exactly that.
func (t Table) FullCost() string {
	if t.StatsDays <= 0 || t.Updates <= 0 || t.AvgRowBytes <= 0 {
		return "every UPDATE would write the whole old row to the WAL as well as the new one"
	}
	perDay := float64(t.Updates) / t.StatsDays * float64(t.AvgRowBytes)
	return fmt.Sprintf("about %s of extra WAL a day at this table's current rate (%s updates/day), "+
		"and the same again in your backup archive", humanBytes(int64(perDay)),
		humanCount(float64(t.Updates)/t.StatsDays))
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f kB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func humanCount(n float64) string {
	if n >= 1000 {
		return fmt.Sprintf("%.0fk", n/1000)
	}
	return fmt.Sprintf("%.0f", n)
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
	for _, e := range r.EventList() {
		switch e {
		case "insert", "update", "delete":
		default:
			return fmt.Errorf("%q is not an event: use insert, update or delete", e)
		}
	}

	// One source of truth. Assess decides; this turns a verdict into the
	// refusal a command prints. They used to be separate implementations of the
	// same rules, which is two places to forget the same thing.
	t := r.Table
	if r.FullIdentity {
		// The caller has asked for the identity this check would otherwise
		// demand, and Enable sets it moments from now.
		t.ReplicaIdentity = 'f'
	}
	v := Assess(t, r.Events, false)
	switch v.State {
	case Ready, Streaming:
		return nil
	case Impossible:
		return errors.New(v.Reason)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s is not ready to stream:\n", t.Qualified())
	identity := false
	for _, f := range v.Fixes {
		fmt.Fprintf(&b, "  %s\n      %s\n", f.Why, f.SQL)
		if f.Cost != "" {
			fmt.Fprintf(&b, "      %s\n", f.Cost)
		}
		if strings.Contains(f.SQL, "REPLICA IDENTITY") {
			identity = true
		}
	}
	fmt.Fprintf(&b, "\n%s realtime prepare %s   makes these changes, recorded in the Blackbox",
		brand.CLI, t.Qualified())
	if identity {
		// Named explicitly because they are the two answers a person reaches
		// for, and a refusal that does not say the way out reads as a bug.
		fmt.Fprintf(&b, "\n--replica-identity=full   accept it here instead"+
			"\n--events=insert           stream inserts only; no identity needed")
	}
	return errors.New(strings.TrimRight(b.String(), "\n"))
}
