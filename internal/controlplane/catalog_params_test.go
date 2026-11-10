// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"strings"
	"testing"
)

// The last inputs take the defaults, skipping OUT and TABLE arguments, which
// pronargdefaults does not count (point 12.4).
func TestMarkDefaults(t *testing.T) {
	ps := []FuncParam{{Name: "a", Mode: "in"}, {Name: "b", Mode: "inout"}, {Name: "o", Mode: "out"}, {Name: "c", Mode: "variadic"}, {Name: "r", Mode: "table"}}
	markDefaults(ps, 2)
	var got []string
	for _, p := range ps {
		if p.Default {
			got = append(got, p.Name)
		}
	}
	if strings.Join(got, ",") != "b,c" {
		t.Errorf("defaults on %v", got)
	}
	none := []FuncParam{{Name: "a", Mode: "in"}}
	markDefaults(none, 0)
	if none[0].Default {
		t.Error("a default with none declared")
	}
}

// Every argument, its mode and name, an empty list for none.
func TestParamsSQL(t *testing.T) {
	for _, want := range []string{"proallargtypes", "proargmodes", "proargnames", "WITH ORDINALITY", "FILTER (WHERE a.o IS NOT NULL)", "pronargdefaults"} {
		if !strings.Contains(paramsSQL, want) {
			t.Errorf("the arguments' query lacks %q", want)
		}
	}
}

// A trigger's parts, from its type bits and its definition (point 12.3).
func TestTriggerInfo(t *testing.T) {
	def := `CREATE TRIGGER trg BEFORE INSERT OR UPDATE OF v, w ON public.t FOR EACH ROW WHEN (old.v IS DISTINCT FROM new.v) EXECUTE FUNCTION public.f('a', 'b)')`
	got := triggerInfo(tgRow|tgBefore|tgInsert|tgUpdate, []string{"v", "w"}, "public.f", false, def)
	if got.Timing != "BEFORE" || got.ForEach != "ROW" || strings.Join(got.Events, ",") != "INSERT,UPDATE" || got.When != "old.v IS DISTINCT FROM new.v" || got.Args != "'a', 'b)'" || strings.Join(got.Columns, ",") != "v,w" {
		t.Errorf("%+v", got)
	}
	ref := `CREATE TRIGGER s AFTER DELETE ON t REFERENCING OLD TABLE AS gone FOR EACH STATEMENT EXECUTE FUNCTION f()`
	got = triggerInfo(tgDelete, nil, "public.f", false, ref)
	if got.Timing != "AFTER" || got.ForEach != "STATEMENT" || got.Referencing != "OLD TABLE AS gone" || got.When != "" || got.Args != "" {
		t.Errorf("%+v", got)
	}
	if got := triggerInfo(tgInstead|tgRow|tgInsert, nil, "f", false, "x"); got.Timing != "INSTEAD OF" {
		t.Errorf("%+v", got)
	}
}

// The SET clauses of a function's definition, and none from its body.
func TestSetClauses(t *testing.T) {
	def := "CREATE OR REPLACE FUNCTION public.f()\n RETURNS integer\n LANGUAGE sql\n SET search_path TO 'public', 'pg_temp'\n SET work_mem TO '1MB'\nAS $function$\nSET x TO 1;\n$function$\n"
	if got := setClauses(def); strings.Join(got, "|") != "SET search_path TO 'public', 'pg_temp'|SET work_mem TO '1MB'" {
		t.Errorf("%q", got)
	}
}
