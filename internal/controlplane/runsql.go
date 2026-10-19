// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"errors"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// SQLResult is one statement's outcome, as `fox sql` prints it.
type SQLResult struct {
	Columns []string
	Rows    [][]any
	Command string
	Error   string
	Detail  string
	Hint    string
}

// SQLOutput is what running some SQL gave: a result per statement, and a note
// when a script failed and nothing it did was kept.
type SQLOutput struct {
	Results []SQLResult
	Error   string // a failure that is not one statement's
	Hint    string
	Detail  string
	Note    string
}

// RowCap is how many rows one statement returns, here as in the console.
const RowCap = 1000

// RunSQL runs sql on a branch the way the console does: as the shared client
// role, bound by row-level security, the guardrails and the append-only
// Blackbox, with the same rendering of every value. label names who ran it,
// for the Blackbox, and the tool is `fox sql`.
func RunSQL(branchName, sql, label string) (SQLOutput, error) {
	addr, err := branch.EnsureRunning(branchName)
	if err != nil {
		return SQLOutput{}, err
	}
	m := runQuery(addr, sql, queryAs{Branch: branchName, Label: label, App: "fox sql"})
	return sqlOutput(m), nil
}

// Outcome is what history keeps of a run: how many rows came back across every
// statement, and the first failure, if there was one.
func (o SQLOutput) Outcome() (rows int64, err error) {
	msg := o.Error
	for _, r := range o.Results {
		rows += int64(len(r.Rows))
		if msg == "" && r.Error != "" {
			msg = r.Error
		}
	}
	if msg != "" {
		return rows, errors.New(msg)
	}
	return rows, nil
}

// sqlOutput reads runQuery's map into SQLOutput.
func sqlOutput(m map[string]any) SQLOutput {
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	one := func(m map[string]any) SQLResult {
		r := SQLResult{Command: str(m, "command"), Error: str(m, "error"), Detail: str(m, "detail"), Hint: str(m, "hint")}
		if c, ok := m["columns"].([]string); ok {
			r.Columns = c
		}
		if rows, ok := m["rows"].([][]any); ok {
			r.Rows = rows
		}
		return r
	}
	out := SQLOutput{Note: str(m, "note")}
	if rs, ok := m["results"].([]map[string]any); ok {
		for _, r := range rs {
			out.Results = append(out.Results, one(r))
		}
	}
	if len(out.Results) == 0 {
		r := one(m)
		if r.Error != "" && r.Columns == nil {
			out.Error, out.Hint, out.Detail = r.Error, r.Hint, r.Detail
		} else {
			out.Results = []SQLResult{r}
		}
	} else if e := str(m, "error"); e != "" {
		out.Error, out.Hint, out.Detail = e, str(m, "hint"), str(m, "detail")
	}
	return out
}
