//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package pipeline

import (
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// renderSQL resolves {{ ref() }} / {{ source() }} to schema-qualified identifiers.
func TestRenderSQL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT * FROM {{ source('buildings') }}", `SELECT * FROM raw."buildings"`},
		{"SELECT * FROM {{ ref('stg_orders') }}", `SELECT * FROM public."stg_orders"`},
		{`SELECT * FROM {{ source("orders") }} JOIN {{ ref('dim_users') }} u`, `SELECT * FROM raw."orders" JOIN public."dim_users" u`},
		{"{{ref('a')}}+{{source('b')}}", `public."a"+raw."b"`}, // tight whitespace
		// case is preserved exactly (schema fidelity), not folded to lowercase:
		{"SELECT * FROM {{ source('leaseAiChats') }}", `SELECT * FROM raw."leaseAiChats"`},
		{"no templates here", "no templates here"},
	}
	for _, c := range cases {
		if got := renderSQL(c.in); got != c.want {
			t.Errorf("renderSQL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// testQuery builds the correct "count of violating rows" SQL per assertion type.
func TestTestQuery(t *testing.T) {
	cases := []struct {
		name string
		test branch.PipelineTest
		want string
		err  bool
	}{
		{"not_null", branch.PipelineTest{Type: "not_null", Model: "stg", Column: "name"},
			`SELECT count(*) FROM public."stg" WHERE "name" IS NULL`, false},
		{"unique", branch.PipelineTest{Type: "unique", Model: "users", Column: "email"},
			`SELECT count(*) FROM (SELECT "email" FROM public."users" GROUP BY "email" HAVING count(*)>1) x`, false},
		{"accepted_values", branch.PipelineTest{Type: "accepted_values", Model: "orders", Column: "status", Values: []string{"new", "paid"}},
			`SELECT count(*) FROM public."orders" WHERE "status" NOT IN ('new','paid')`, false},
		{"row_count_min", branch.PipelineTest{Type: "row_count_min", Model: "m", Min: 5},
			`SELECT CASE WHEN count(*)>=5 THEN 0 ELSE 1 END FROM public."m"`, false},
		{"custom", branch.PipelineTest{Type: "custom", SQL: "SELECT 1 FROM {{ ref('m') }} WHERE x<0"},
			`SELECT count(*) FROM (SELECT 1 FROM public."m" WHERE x<0) x`, false},
		{"accepted_values empty", branch.PipelineTest{Type: "accepted_values", Model: "m", Column: "c"}, "", true},
		{"unknown type", branch.PipelineTest{Type: "bogus", Model: "m"}, "", true},
	}
	for _, c := range cases {
		got, err := testQuery(c.test)
		if c.err {
			if err == nil {
				t.Errorf("%s: expected an error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		} else if got != c.want {
			t.Errorf("%s: testQuery = %q, want %q", c.name, got, c.want)
		}
	}
}
