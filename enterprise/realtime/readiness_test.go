//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"strings"
	"testing"
)

// app is a table an application made: ordinary, readable, with a primary key.
func app() Table {
	return Table{Schema: "public", Name: "orders", Kind: "r",
		HasPrimaryKey: true, ReplicaIdentity: 'd', ClientCanSelect: true, ClientCanUseSchema: true}
}

// The ladder, rung by rung. Each case is a table that differs from a ready one
// in exactly one way, so a failure names the rung rather than the fixture.
func TestAssessTakesTheCheapestRung(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*Table)
		events   []string
		want     State
		wantSQL  string // a substring of the fix, "" when there should be none
		wantFree bool
	}{
		{name: "a primary key needs nothing", mutate: func(*Table) {}, want: Ready},
		{name: "an identity already set needs nothing",
			mutate: func(t *Table) { t.HasPrimaryKey = false; t.ReplicaIdentity = 'f' }, want: Ready},
		{name: "an index identity already set needs nothing",
			mutate: func(t *Table) { t.HasPrimaryKey = false; t.ReplicaIdentity = 'i' }, want: Ready},

		// Rung 2, the one that matters: a unique index costs what a key costs.
		{name: "a unique index is used before FULL",
			mutate:  func(t *Table) { t.HasPrimaryKey = false; t.UniqueIndex = "ix_orders_ref" },
			want:    Fixable,
			wantSQL: "REPLICA IDENTITY USING INDEX \"ix_orders_ref\"", wantFree: true},

		// Rung 4, and only when there is nothing unique at all.
		{name: "nothing unique falls through to FULL",
			mutate:  func(t *Table) { t.HasPrimaryKey = false },
			want:    Fixable,
			wantSQL: "REPLICA IDENTITY FULL", wantFree: false},

		// Inserts need no identity, so no table ever has to pay for them.
		{name: "inserts only need no identity",
			mutate: func(t *Table) { t.HasPrimaryKey = false },
			events: []string{"insert"}, want: Ready},

		{name: "a missing grant is a fix, not a refusal",
			mutate:  func(t *Table) { t.ClientCanSelect = false },
			want:    Fixable,
			wantSQL: "GRANT SELECT ON public.orders TO db_client", wantFree: true},
		{name: "hidden columns are a fix, and are named",
			mutate:  func(t *Table) { t.ColumnsHidden = []string{"salary", "ssn"} },
			want:    Fixable,
			wantSQL: "GRANT SELECT (salary, ssn)", wantFree: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tbl := app()
			c.mutate(&tbl)
			v := Assess(tbl, c.events, false)
			if v.State != c.want {
				t.Fatalf("state = %v, want %v (fixes %+v, reason %q)", v.State, c.want, v.Fixes, v.Reason)
			}
			if c.wantSQL == "" {
				if len(v.Fixes) != 0 {
					t.Fatalf("expected no fixes, got %+v", v.Fixes)
				}
				return
			}
			found := false
			for _, f := range v.Fixes {
				if strings.Contains(f.SQL, c.wantSQL) {
					found = true
					if f.Free() != c.wantFree {
						t.Errorf("fix %q free = %v, want %v (cost %q)", f.SQL, f.Free(), c.wantFree, f.Cost)
					}
				}
			}
			if !found {
				t.Fatalf("no fix contained %q; got %+v", c.wantSQL, v.Fixes)
			}
		})
	}
}

// A table that needs two things should say so once, not refuse twice.
func TestAssessCollectsEveryFix(t *testing.T) {
	tbl := app()
	tbl.HasPrimaryKey = false
	tbl.ClientCanSelect = false
	v := Assess(tbl, nil, false)
	if v.State != Fixable || len(v.Fixes) != 2 {
		t.Fatalf("want two fixes, got state %v and %+v", v.State, v.Fixes)
	}
}

// The rule that protects the Blackbox is held twice: once by the catalog query
// and once here, over the schema name alone, so it cannot be lost by a caller
// who forgot to fill in a field.
func TestAssessRefusesWhatTheApplicationDidNotMake(t *testing.T) {
	for name, mutate := range map[string]func(*Table){
		"the Blackbox, by name":          func(t *Table) { t.Schema = "bb" },
		"the Blackbox, by flag":          func(t *Table) { t.IsSystem = true },
		"pg_catalog":                     func(t *Table) { t.Schema = "pg_catalog" },
		"information_schema":             func(t *Table) { t.Schema = "information_schema" },
		"a pg_ schema":                   func(t *Table) { t.Schema = "pg_toast" },
		"an extension's table":           func(t *Table) { t.IsExtensionOwned = true },
		"an extension's table in public": func(t *Table) { t.Schema = "public"; t.IsExtensionOwned = true },
		"a view":                         func(t *Table) { t.Kind = "v" },
		"row-level security":             func(t *Table) { t.RLSEnabled = true },
	} {
		t.Run(name, func(t *testing.T) {
			tbl := app()
			mutate(&tbl)
			v := Assess(tbl, nil, false)
			if v.State != Impossible {
				t.Fatalf("state = %v, want Impossible", v.State)
			}
			if v.Reason == "" {
				t.Error("refused without saying why")
			}
			if len(v.Fixes) != 0 {
				t.Errorf("offered fixes for something that cannot stream: %+v", v.Fixes)
			}
		})
	}
	// And the application's own schema is allowed, which the old public-only
	// rule refused.
	tbl := app()
	tbl.Schema = "billing"
	if v := Assess(tbl, nil, false); v.State != Ready {
		t.Errorf("a table in the application's own schema: %v (%s)", v.State, v.Reason)
	}
}

// The zero value must not read as permission. An unevaluated verdict is the
// same mistake as an unevaluated licence Status, and that one shipped once.
func TestZeroVerdictIsImpossible(t *testing.T) {
	var v Verdict
	if v.State != Impossible {
		t.Fatalf("the zero Verdict is %v; it must be Impossible", v.State)
	}
	if v.Costly() {
		t.Error("an empty verdict reported an ongoing cost")
	}
}

// A bulk action must never be able to double someone's WAL.
func TestCostlyMarksOnlyTheExpensiveRung(t *testing.T) {
	cheap := app()
	cheap.HasPrimaryKey = false
	cheap.UniqueIndex = "ix"
	if Assess(cheap, nil, false).Costly() {
		t.Error("USING INDEX was reported as costly")
	}
	dear := app()
	dear.HasPrimaryKey = false
	if !Assess(dear, nil, false).Costly() {
		t.Error("REPLICA IDENTITY FULL was not reported as costly")
	}
}

// The cost is a measured number when the statistics allow one, and an honest
// sentence when they do not.
func TestFullCostUsesMeasuredNumbers(t *testing.T) {
	t.Run("with statistics", func(t *testing.T) {
		tbl := app()
		tbl.HasPrimaryKey = false
		tbl.Updates, tbl.StatsDays, tbl.AvgRowBytes = 86400, 1, 1024 // 1/s, 1 kB rows
		cost := Assess(tbl, nil, false).Fixes[0].Cost
		if !strings.Contains(cost, "MB") || !strings.Contains(cost, "a day") {
			t.Errorf("cost is not a measured number: %q", cost)
		}
	})
	t.Run("without statistics", func(t *testing.T) {
		tbl := app()
		tbl.HasPrimaryKey = false
		cost := Assess(tbl, nil, false).Fixes[0].Cost
		if cost == "" || strings.Contains(cost, "a day") {
			t.Errorf("want an honest sentence with no invented number, got %q", cost)
		}
	})
}

// A table already in a publication is streaming, whatever else is true of it.
func TestAssessReportsStreaming(t *testing.T) {
	if v := Assess(app(), nil, true); v.State != Streaming {
		t.Fatalf("state = %v, want Streaming", v.State)
	}
}

// A table grant is not enough on its own outside public. has_table_privilege
// answers about the table's ACL and says nothing about reaching it, so a table
// in a schema db_client cannot use reports SELECT and is unreadable — a gap
// that would only have shown up once the feed was already on.
func TestAssessGrantsSchemaUsageBeforeTheTableGrant(t *testing.T) {
	tbl := app()
	tbl.Schema = "billing"
	tbl.ClientCanUseSchema = false

	v := Assess(tbl, nil, false)
	if v.State != Fixable {
		t.Fatalf("state = %v, want Fixable", v.State)
	}
	if len(v.Fixes) == 0 || !strings.Contains(v.Fixes[0].SQL, `GRANT USAGE ON SCHEMA "billing"`) {
		t.Fatalf("the schema grant is missing or not first: %+v", v.Fixes)
	}
	if !v.Fixes[0].Free() {
		t.Error("a grant was reported as having an ongoing cost")
	}
	// public is covered by the engine's default privileges, so an ordinary
	// table never collects this fix.
	pub := app()
	for _, f := range Assess(pub, nil, false).Fixes {
		if strings.Contains(f.SQL, "GRANT USAGE ON SCHEMA") {
			t.Errorf("a public table was given a schema grant: %q", f.SQL)
		}
	}
}
