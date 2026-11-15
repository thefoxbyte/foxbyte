//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"errors"
	"fmt"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Enabling a table: ask the catalog what it is, refuse it if the preflight says
// so, and only then add it to the publication.
//
// In that order, deliberately. Postgres will happily add a table with no
// replica identity to a publication and only fail later, on the first UPDATE —
// by which time the feed has broken queries that worked before it existed.

// Facts asks the catalog everything Preflight needs about one table.
//
// One query, shared with Survey. There used to be a second one here, and
// keeping two in step lasted exactly as long as the first new column: a field
// this one did not select defaulted to false, and every ordinary table was
// told it needed a grant it already had. The rules live in Assess and the
// facts live in factsSQL, and neither has a second opinion.
func Facts(branchName, schema, table string) (Table, error) {
	v, err := Look(branchName, schema, table, nil)
	if err != nil {
		return Table{}, err
	}
	return v.Table, nil
}

// Enable adds a table to the branch's publication, after the preflight, with
// the columns the request names (all of them when it names none). Enabling a
// table that already streams replaces its column choice and its events.
func Enable(branchName string, req Request) (Result, error) {
	// Resolved once, here: after a failover the container serving "main" is the
	// promoted standby, and every statement below reaches Postgres by container
	// name. See branch.ServingBranch.
	branchName = branch.ServingBranch(branchName)
	t, err := Facts(branchName, req.Table.Schema, req.Table.Name)
	if err != nil {
		return Result{}, err
	}
	// The refusals that do not depend on columns come first: a system table
	// should be told it is one, not that it has no column called x.
	if v := Assess(t, req.Events, false); v.State == Impossible {
		return Result{}, errors.New(v.Reason)
	}
	cols, err := readTableColumns(branchName, t.Schema, t.Name)
	if err != nil {
		return Result{}, err
	}
	pii, err := personalData(branchName, t.Schema, t.Name)
	if err != nil {
		// Not knowing is not the same as knowing there is none, so this
		// refuses rather than streams.
		return Result{}, fmt.Errorf("checking %s for confirmed personal data: %w", t.Qualified(), err)
	}
	plan, err := planEnable(t, cols, pii[t.Qualified()], req)
	if err != nil {
		return Result{}, err
	}
	// The preflight sees the columns that will stream, so a column db_client
	// cannot read is only a problem when it is one of them.
	t.StreamColumns = plan.Columns
	req.Table = t
	if err := Preflight(req); err != nil {
		return Result{}, err
	}
	if err := branch.ExecSQL(branchName, plan.SQL); err != nil {
		return Result{}, fmt.Errorf("enabling %s: %w", t.Qualified(), err)
	}
	return plan.Result, nil
}

// Disable takes a table back out of the publication. It does not undo a REPLICA
// IDENTITY FULL: that is a schema change somebody asked for, it costs only WAL,
// and reverting it silently would be a second change nobody asked for.
// The column choice in bb.realtime_columns stays too: it applies only to a
// table that is published, and the next enable replaces it.
//
// Disable takes a table out of whichever publication carries it. A table can
// only be in one of them -- Enable adds it to the one for its event set -- but
// the caller does not have to remember which, so this looks.
func Disable(branchName, schema, table string) error {
	branchName = branch.ServingBranch(branchName)
	pubs, err := branch.Publications(branchName)
	if err != nil {
		return err
	}
	var last error
	found := false
	for _, pub := range pubs {
		in, err := branch.LedgerQuery(branchName, fmt.Sprintf(
			`SELECT 1 FROM pg_publication_tables WHERE pubname = %s AND schemaname = %s AND tablename = %s`,
			branch.QuoteLiteral(pub), branch.QuoteLiteral(schema), branch.QuoteLiteral(table)))
		if err != nil || len(in) == 0 {
			continue
		}
		found = true
		if err := branch.ExecSQL(branchName, fmt.Sprintf("ALTER PUBLICATION %s DROP TABLE %s.%s",
			branch.QuoteIdent(pub), branch.QuoteIdent(schema), branch.QuoteIdent(table))); err != nil {
			last = err
		}
	}
	if !found {
		return fmt.Errorf("%s.%s is not being streamed on %q", schema, table, branchName)
	}
	return last
}
