//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package pipeline is the ETL engine: extract, land raw, transform with SQL
// models, test, load. It is the paid half of `fox pipeline`; the types it works
// on stay in internal/branch, where untagged code in cmd/fox and the control
// plane names them.
package pipeline

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// init registers the engine with internal/branch, which is how the free half
// reaches it without importing this package — the dependency only ever points
// inwards. A blank import from the tagged files in cmd/fox and the control
// plane is what causes this to run; in a Standard build neither exists.
func init() { branch.SetPipelineRunner(run) }

// renderSQL resolves {{ ref('m') }} → public."m" and {{ source('t') }} → raw."t",
// preserving the exact name (case-sensitive) so it matches the schema-faithful
// tables the extract created.
func renderSQL(sql string) string {
	sql = reRef.ReplaceAllStringFunc(sql, func(m string) string {
		return "public." + branch.QuoteIdent(reRef.FindStringSubmatch(m)[1])
	})
	sql = reSource.ReplaceAllStringFunc(sql, func(m string) string {
		return "raw." + branch.QuoteIdent(reSource.FindStringSubmatch(m)[1])
	})
	return sql
}

var (
	reRef    = regexp.MustCompile(`\{\{\s*ref\(\s*['"]([^'"]+)['"]\s*\)\s*\}\}`)
	reSource = regexp.MustCompile(`\{\{\s*source\(\s*['"]([^'"]+)['"]\s*\)\s*\}\}`)
)

// run is the engine. branch.RunPipeline checks the licence and calls this.
func run(p *branch.Progress, spec branch.PipelineSpec, branchName string) (branch.RunResult, error) {
	res := branch.RunResult{Branch: branchName}
	if strings.TrimSpace(spec.Source) == "" {
		return res, fmt.Errorf("pipeline needs a source connection string")
	}

	// 1. Extract + land raw (into a fresh branchName's public schema).
	p.Logf("== Extract ==\n")
	_ = branch.Delete(branchName) // refresh the target instance if a previous run left one
	if _, err := branch.ImportTo(p, spec.Source, branchName); err != nil {
		return res, fmt.Errorf("extract: %w", err)
	}

	// From here on we issue our own DDL; relax the destructive-DDL guard (the
	// ledger still records everything). ImportTo re-armed it when it returned.
	branch.SetGuard(branchName, false)
	defer branch.SetGuard(branchName, true)

	// 2. Move the extracted tables aside into schema `raw`, leaving a clean public
	// for the transformed models (avoids threading a schema arg through every loader).
	p.Logf("== Stage raw ==\n")
	if err := branch.ExecSQL(branchName, `DROP SCHEMA IF EXISTS raw CASCADE; ALTER SCHEMA public RENAME TO raw; CREATE SCHEMA public;`); err != nil {
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
		p.Report(i+1, len(spec.Models), "model "+name)
		ddl := fmt.Sprintf(`CREATE %s public.%s AS %s;`, mat, branch.QuoteIdent(name), renderSQL(m.SQL))
		if err := branch.ExecSQL(branchName, ddl); err != nil {
			return res, fmt.Errorf("model %q: %w", name, err)
		}
		res.Models = append(res.Models, name)
	}

	// 4. Test.
	if len(spec.Tests) > 0 {
		p.Logf("== Test (%d) ==\n", len(spec.Tests))
	}
	for _, t := range spec.Tests {
		tr := runTest(branchName, t)
		res.Tests = append(res.Tests, tr)
		if tr.Passed {
			p.Logf("  [PASS] %s\n", tr.Name)
		} else {
			res.Failed = true
			p.Logf("  [FAIL] %s — %s\n", tr.Name, tr.Detail)
		}
	}

	res.Tables = branch.TableCount(branchName)
	if res.Failed {
		p.Logf("\n✗ Pipeline finished with test failures — data kept in %q for inspection.\n", branchName)
	} else {
		p.Logf("\n✓ Pipeline complete → %q (%d table%s, %d test%s passed).\n",
			branchName, res.Tables, plural(res.Tables), len(res.Tests), plural(len(res.Tests)))
	}
	return res, nil
}

// testName returns a human-readable label for an assertion.
func testName(t branch.PipelineTest) string {
	if n := strings.TrimSpace(t.Name); n != "" {
		return n
	}
	return strings.TrimSpace(fmt.Sprintf("%s %s %s", t.Type, t.Model, t.Column))
}

// testQuery builds the scalar "count of violating rows" query for an assertion
// (0 = pass). It is pure (no DB access), so it can be unit-tested.
func testQuery(t branch.PipelineTest) (string, error) {
	model := "public." + branch.QuoteIdent(t.Model)
	col := branch.QuoteIdent(t.Column)
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
			vals[i] = branch.QuoteLiteral(v)
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

// runTest evaluates one assertion against the branchName (0 violating rows = pass).
func runTest(branchName string, t branch.PipelineTest) branch.TestResult {
	name := testName(t)
	query, err := testQuery(t)
	if err != nil {
		return branch.TestResult{Name: name, Passed: false, Detail: err.Error()}
	}
	out, err := branch.QuerySQL(branchName, query)
	if err != nil {
		return branch.TestResult{Name: name, Passed: false, Detail: "query error: " + strings.TrimSpace(out)}
	}
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	if n == 0 {
		return branch.TestResult{Name: name, Passed: true}
	}
	return branch.TestResult{Name: name, Passed: false, Detail: fmt.Sprintf("%d violating row(s)", n)}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
