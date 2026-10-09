//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"strings"
	"testing"
)

// ok is a table that may be streamed: an ordinary public table with a primary
// key, no RLS, readable by db_client.
func ok() Table {
	return Table{Schema: "public", Name: "orders", Kind: "r",
		HasPrimaryKey: true, ReplicaIdentity: 'd', ClientCanSelect: true, ClientCanUseSchema: true}
}

func TestPreflightAcceptsAnOrdinaryTable(t *testing.T) {
	if err := Preflight(Request{Table: ok()}); err != nil {
		t.Errorf("an ordinary table was refused: %v", err)
	}
}

// The trap this function exists for. Adding a table with no replica identity to
// a publication that publishes updates makes every later UPDATE and DELETE on
// it fail — so enabling a feed would break queries that work today.
func TestPreflightRefusesATableWithNoPrimaryKey(t *testing.T) {
	tbl := ok()
	tbl.HasPrimaryKey = false

	err := Preflight(Request{Table: tbl})
	if err == nil {
		t.Fatal("a table with no primary key was accepted for updates")
	}
	// A refusal that does not say the way out reads as a bug.
	for _, want := range []string{"--replica-identity=full", "--events=insert"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not offer %s: %v", want, err)
		}
	}

	// Both ways forward work.
	if err := Preflight(Request{Table: tbl, FullIdentity: true}); err != nil {
		t.Errorf("--replica-identity=full was still refused: %v", err)
	}
	if err := Preflight(Request{Table: tbl, Events: []string{"insert"}}); err != nil {
		t.Errorf("--events=insert was still refused: %v", err)
	}
	// And a table already set to FULL needs neither.
	tbl.ReplicaIdentity = 'f'
	if err := Preflight(Request{Table: tbl}); err != nil {
		t.Errorf("a table already at REPLICA IDENTITY FULL was refused: %v", err)
	}
}

// The only case where a feed would widen access, and the only one with no
// override. Everyone who can reach a branch can already SELECT every public
// table; RLS is the exception, and decoded WAL has had no policy applied to it.
func TestPreflightRefusesRLSWithNoWayRound(t *testing.T) {
	tbl := ok()
	tbl.RLSEnabled = true
	err := Preflight(Request{Table: tbl})
	if err == nil {
		t.Fatal("an RLS table was accepted")
	}
	// Not even with the escapes that work for the primary-key case.
	for _, r := range []Request{
		{Table: tbl, FullIdentity: true},
		{Table: tbl, Events: []string{"insert"}},
	} {
		if err := Preflight(r); err == nil {
			t.Errorf("an RLS table was accepted with %+v", r)
		}
	}
	if !strings.Contains(err.Error(), "no override") {
		t.Errorf("the refusal does not say there is no way round: %v", err)
	}
}

// Anything db_client cannot already read is not ours to stream — whole table or
// a single column.
func TestPreflightRefusesWhatTheClientCannotRead(t *testing.T) {
	noSelect := ok()
	noSelect.ClientCanSelect = false
	if err := Preflight(Request{Table: noSelect}); err == nil {
		t.Error("a table db_client cannot SELECT was accepted")
	}

	hidden := ok()
	hidden.ColumnsHidden = []string{"salary"}
	err := Preflight(Request{Table: hidden})
	if err == nil {
		t.Fatal("a table with an unreadable column was accepted")
	}
	if !strings.Contains(err.Error(), "salary") {
		t.Errorf("the refusal does not name the column: %v", err)
	}
}

func TestPreflightRefusesWhatIsNotAnApplicationTable(t *testing.T) {
	for name, mutate := range map[string]func(*Table){
		"a view":              func(t *Table) { t.Kind = "v" },
		"a materialised view": func(t *Table) { t.Kind = "m" },
		"a sequence":          func(t *Table) { t.Kind = "S" },
		"the Blackbox":        func(t *Table) { t.Schema = "bb"; t.Name = "schema_ledger" },
		"a Postgres schema":   func(t *Table) { t.Schema = "pg_catalog"; t.Name = "pg_class" },
		"an extension's own":  func(t *Table) { t.IsExtensionOwned = true },
		"something the catalog called a system table": func(t *Table) { t.IsSystem = true },
	} {
		tbl := ok()
		mutate(&tbl)
		if err := Preflight(Request{Table: tbl}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A table in the application's own schema is now allowed. The rule used to
	// be "public only", which refused this and — because an extension may
	// create its tables anywhere, including in public — let an extension's
	// table through. It is "any schema the application made" now, which is both
	// more permissive and stricter.
	other := ok()
	other.Schema = "billing"
	if err := Preflight(Request{Table: other}); err != nil {
		t.Errorf("a table in the application's own schema was refused: %v", err)
	}

	// A partitioned table is an ordinary case, not an exclusion.
	part := ok()
	part.Kind = "p"
	if err := Preflight(Request{Table: part}); err != nil {
		t.Errorf("a partitioned table was refused: %v", err)
	}
}

func TestPreflightRefusesAnEventItDoesNotKnow(t *testing.T) {
	if err := Preflight(Request{Table: ok(), Events: []string{"truncate"}}); err == nil {
		t.Error("an unknown event was accepted")
	}
}

// An empty event list means all three, so a plain enable is checked as though
// it had asked for updates — which is what makes the primary-key refusal fire
// on the default path rather than only when someone spells it out.
func TestNoEventsMeansAllThree(t *testing.T) {
	if got := (Request{}).EventList(); len(got) != 3 {
		t.Fatalf("EventList() = %v, want all three", got)
	}
	if !(Request{}).PublishesChanges() {
		t.Error("a default request must count as publishing changes")
	}
	if (Request{Events: []string{"insert"}}).PublishesChanges() {
		t.Error("insert-only must not count as publishing changes")
	}
}
