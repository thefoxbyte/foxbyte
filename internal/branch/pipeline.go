// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import "github.com/thefoxbyte/foxbyte/internal/edition"

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

// runPipeline is the engine, supplied by enterprise/pipeline in an Enterprise
// build and nil in a Standard one — where that code is not compiled in at all.
//
// This indirection is the seam. internal/branch may not import enterprise/, so
// the paid half registers itself here instead, and the free half keeps the
// types because they are named by untagged code in cmd/fox and the control
// plane. A struct definition is not the feature; the engine is.
var runPipeline func(*Progress, PipelineSpec, string) (RunResult, error)

// SetPipelineRunner installs the engine. Called from enterprise/pipeline's
// init, and from nowhere else.
func SetPipelineRunner(fn func(*Progress, PipelineSpec, string) (RunResult, error)) {
	runPipeline = fn
}

// RunPipeline runs a pipeline into a fresh branch (refreshing it if it exists):
// extract + land raw, move the raw tables to a `raw` schema, run the SQL models
// into `public`, then run the tests. Test failures set RunResult.Failed but the
// data is left in place for inspection.
func RunPipeline(p *Progress, spec PipelineSpec, branch string) (RunResult, error) {
	// `fox import` is deliberately not gated: migrating data in is onboarding,
	// not ETL, and charging for the way in is a bad trade for both sides.
	if err := requireFeature(edition.Pipelines); err != nil {
		return RunResult{}, err
	}
	// Licensed, but this is a Standard binary, so the engine is not here. The
	// licence check above cannot reach this in practice — edition.Has is false
	// in a Standard build whatever a licence says — but an entitlement is a
	// run-time thing and a missing engine should say so rather than panic.
	if runPipeline == nil {
		return RunResult{}, ErrPipelinesNotLicensed
	}
	return runPipeline(p, spec, branch)
}
