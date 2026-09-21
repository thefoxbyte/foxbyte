// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ETL pipelines (ELT). Because FoxByte *is* Postgres, a pipeline extracts a
// source, lands it raw, then transforms it with SQL models run on the branch's
// own Postgres, and validates the result with data-quality tests:
//
//	Extract (existing connectors) → land raw → Transform (SQL models) → Test → Load
//
// Each run targets a fresh branch (safe, reversible staging). Raw source tables
// live in schema `raw`; transformed models land in `public`. NoSQL is handled by
// the Extract step's relationalization (keys → columns, nesting → jsonb), so the
// SQL models operate on ordinary relational tables + jsonb columns.

// PipelineModel is one named SQL transform, materialized as a table or view.
type PipelineModel struct {
	Name         string `json:"name"`
	SQL          string `json:"sql"`
	Materialized string `json:"materialized"` // "table" (default) | "view"
}

// PipelineTest is a data-quality assertion that must hold after the transform.
type PipelineTest struct {
	Name   string   `json:"name"`
	Model  string   `json:"model"`
	Type   string   `json:"type"` // not_null | unique | accepted_values | row_count_min | custom
	Column string   `json:"column"`
	Values []string `json:"values"` // accepted_values
	Min    int      `json:"min"`    // row_count_min
	SQL    string   `json:"sql"`    // custom: a query that must return zero rows
}

// PipelineSpec is a re-runnable ETL definition.
type PipelineSpec struct {
	Source string          `json:"source"` // a connection string (postgres/mysql/mongodb)
	Models []PipelineModel `json:"models"`
	Tests  []PipelineTest  `json:"tests"`
}

// TestResult is the outcome of one assertion.
type TestResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// RunResult summarizes a pipeline run.
type RunResult struct {
	Branch string       `json:"branch"`
	Tables int          `json:"tables"`
	Models []string     `json:"models"`
	Tests  []TestResult `json:"tests"`
	Failed bool         `json:"failed"` // true if any test failed (data is still kept)
}

var (
	reRef    = regexp.MustCompile(`\{\{\s*ref\(\s*['"]([^'"]+)['"]\s*\)\s*\}\}`)
	reSource = regexp.MustCompile(`\{\{\s*source\(\s*['"]([^'"]+)['"]\s*\)\s*\}\}`)
)

// renderSQL resolves {{ ref('m') }} → public."m" and {{ source('t') }} → raw."t",
// preserving the exact name (case-sensitive) so it matches the schema-faithful
// tables the extract created.
func renderSQL(sql string) string {
	sql = reRef.ReplaceAllStringFunc(sql, func(m string) string {
		return "public." + sqlIdent(reRef.FindStringSubmatch(m)[1])
	})
	sql = reSource.ReplaceAllStringFunc(sql, func(m string) string {
		return "raw." + sqlIdent(reSource.FindStringSubmatch(m)[1])
	})
	return sql
}

// RunPipeline runs a pipeline into a fresh branch (refreshing it if it exists):
// extract + land raw, move the raw tables to a `raw` schema, run the SQL models
// into `public`, then run the tests. Test failures set RunResult.Failed but the
// data is left in place for inspection.
func RunPipeline(p *Progress, spec PipelineSpec, branch string) (RunResult, error) {
	res := RunResult{Branch: branch}
	if strings.TrimSpace(spec.Source) == "" {
		return res, fmt.Errorf("pipeline needs a source connection string")
	}

	// 1. Extract + land raw (into a fresh branch's public schema).
	p.Logf("== Extract ==\n")
	_ = Delete(branch) // refresh the target instance if a previous run left one
	if _, err := ImportTo(p, spec.Source, branch); err != nil {
		return res, fmt.Errorf("extract: %w", err)
	}

	// From here on we issue our own DDL; relax the destructive-DDL guard (the
	// ledger still records everything). ImportTo re-armed it when it returned.
	setGuard(branch, false)
	defer setGuard(branch, true)

	// 2. Move the extracted tables aside into schema `raw`, leaving a clean public
	// for the transformed models (avoids threading a schema arg through every loader).
	p.Logf("== Stage raw ==\n")
	if err := psqlExec(branch, `DROP SCHEMA IF EXISTS raw CASCADE; ALTER SCHEMA public RENAME TO raw; CREATE SCHEMA public;`); err != nil {
		return res, fmt.Errorf("stage raw: %w", err)
	}

	// 3. Transform: materialize each model in order.
	p.Logf("== Transform (%d model%s) ==\n", len(spec.Models), plural(len(spec.Models)))
	for i, m := range spec.Models {
		name := strings.TrimSpace(m.Name) // model names are kept verbatim (quoted), like ref()
		if name == "" {
			return res, fmt.Errorf("model %d has no name", i+1)
		}
		mat := "TABLE"
		if strings.EqualFold(strings.TrimSpace(m.Materialized), "view") {
			mat = "VIEW"
		}
		p.Logf("  model %q (%s)…\n", name, strings.ToLower(mat))
		p.step(i+1, len(spec.Models), "model "+name)
		ddl := fmt.Sprintf(`CREATE %s public.%s AS %s;`, mat, sqlIdent(name), renderSQL(m.SQL))
		if err := psqlExec(branch, ddl); err != nil {
			return res, fmt.Errorf("model %q: %w", name, err)
		}
		res.Models = append(res.Models, name)
	}

	// 4. Test.
	if len(spec.Tests) > 0 {
		p.Logf("== Test (%d) ==\n", len(spec.Tests))
	}
	for _, t := range spec.Tests {
		tr := runTest(branch, t)
		res.Tests = append(res.Tests, tr)
		if tr.Passed {
			p.Logf("  [PASS] %s\n", tr.Name)
		} else {
			res.Failed = true
			p.Logf("  [FAIL] %s — %s\n", tr.Name, tr.Detail)
		}
	}

	res.Tables = TableCount(branch)
	if res.Failed {
		p.Logf("\n✗ Pipeline finished with test failures — data kept in %q for inspection.\n", branch)
	} else {
		p.Logf("\n✓ Pipeline complete → %q (%d table%s, %d test%s passed).\n",
			branch, res.Tables, plural(res.Tables), len(res.Tests), plural(len(res.Tests)))
	}
	return res, nil
}

// testName returns a human-readable label for an assertion.
func testName(t PipelineTest) string {
	if n := strings.TrimSpace(t.Name); n != "" {
		return n
	}
	return strings.TrimSpace(fmt.Sprintf("%s %s %s", t.Type, t.Model, t.Column))
}

// testQuery builds the scalar "count of violating rows" query for an assertion
// (0 = pass). It is pure (no DB access), so it can be unit-tested.
func testQuery(t PipelineTest) (string, error) {
	model := "public." + sqlIdent(t.Model)
	col := sqlIdent(t.Column)
	switch t.Type {
	case "not_null":
		return fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s IS NULL`, model, col), nil
	case "unique":
		return fmt.Sprintf(`SELECT count(*) FROM (SELECT %s FROM %s GROUP BY %s HAVING count(*)>1) x`, col, model, col), nil
	case "accepted_values":
		if len(t.Values) == 0 {
			return "", fmt.Errorf("accepted_values needs a values list")
		}
		vals := make([]string, len(t.Values))
		for i, v := range t.Values {
			vals[i] = sqlQuote(v)
		}
		return fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s NOT IN (%s)`, model, col, strings.Join(vals, ",")), nil
	case "row_count_min":
		return fmt.Sprintf(`SELECT CASE WHEN count(*)>=%d THEN 0 ELSE 1 END FROM %s`, t.Min, model), nil
	case "custom":
		return fmt.Sprintf(`SELECT count(*) FROM (%s) x`, renderSQL(t.SQL)), nil
	default:
		return "", fmt.Errorf("unknown test type %q", t.Type)
	}
}

// runTest evaluates one assertion against the branch (0 violating rows = pass).
func runTest(branch string, t PipelineTest) TestResult {
	name := testName(t)
	query, err := testQuery(t)
	if err != nil {
		return TestResult{Name: name, Passed: false, Detail: err.Error()}
	}
	out, err := capture("docker", "exec", container(branch),
		"psql", "-U", pgUser, "-d", pgDatabase, "-tAc", query)
	if err != nil {
		return TestResult{Name: name, Passed: false, Detail: "query error: " + strings.TrimSpace(out)}
	}
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	if n == 0 {
		return TestResult{Name: name, Passed: true}
	}
	return TestResult{Name: name, Passed: false, Detail: fmt.Sprintf("%d violating row(s)", n)}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
