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
