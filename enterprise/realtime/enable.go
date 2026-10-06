//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"fmt"
	"strings"

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
// One query rather than several, because the answers have to describe the same
// moment: a table that gains RLS between two of them would pass a check that
// was true a second ago.
func Facts(branchName, schema, table string) (Table, error) {
	q := fmt.Sprintf(`SELECT
	  c.relkind::text
	  || '|' || (c.relreplident)::text
	  || '|' || c.relrowsecurity::text
	  || '|' || EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisprimary)::text
	  || '|' || has_table_privilege('db_client', c.oid, 'SELECT')::text
	  || '|' || coalesce((
	       SELECT string_agg(a.attname, ',' ORDER BY a.attname)
	       FROM pg_attribute a
	       WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
	         AND NOT has_column_privilege('db_client', c.oid, a.attnum, 'SELECT')), '')
	FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	WHERE n.nspname = %s AND c.relname = %s`, branch.QuoteLiteral(schema), branch.QuoteLiteral(table))

	lines, err := branch.LedgerQuery(branchName, q)
	if err != nil {
		return Table{}, err
	}
	if len(lines) == 0 {
		return Table{}, fmt.Errorf("there is no table %s.%s on %q", schema, table, branchName)
	}
	f := strings.Split(lines[0], "|")
	if len(f) < 6 {
		return Table{}, fmt.Errorf("could not read the catalog for %s.%s", schema, table)
	}
	t := Table{Schema: schema, Name: table, Kind: f[0], RLSEnabled: isTrue(f[2]),
		HasPrimaryKey: isTrue(f[3]), ClientCanSelect: isTrue(f[4])}
	if f[1] != "" {
		t.ReplicaIdentity = f[1][0]
	}
	if f[5] != "" {
		t.ColumnsHidden = strings.Split(f[5], ",")
	}
	return t, nil
}

func isTrue(s string) bool { return strings.HasPrefix(strings.ToLower(s), "t") }

// Enable adds a table to the branch's publication, after the preflight.
func Enable(branchName string, req Request) error {
	t, err := Facts(branchName, req.Table.Schema, req.Table.Name)
	if err != nil {
		return err
	}
	req.Table = t
	if err := Preflight(req); err != nil {
		return err
	}
	// REPLICA IDENTITY FULL is a schema change like any other, and is recorded
	// in the Blackbox as one. Done before the publication, so a failure here
	// leaves nothing half-enabled.
	if req.FullIdentity && t.ReplicaIdentity != 'f' {
		if err := branch.ExecSQL(branchName, fmt.Sprintf("ALTER TABLE %s.%s REPLICA IDENTITY FULL",
			branch.QuoteIdent(t.Schema), branch.QuoteIdent(t.Name))); err != nil {
			return fmt.Errorf("setting REPLICA IDENTITY FULL on %s: %w", t.Qualified(), err)
		}
	}
	pub := branch.PublicationName()
	// Never FOR ALL TABLES: that would publish bb.schema_ledger, and with it the
	// recorded text of every statement ever run.
	if err := branch.ExecSQL(branchName, fmt.Sprintf(
		`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = %s) THEN
		   EXECUTE format('CREATE PUBLICATION %%I WITH (publish = %%L)', %s, %s);
		 END IF; END $$`,
		branch.QuoteLiteral(pub), branch.QuoteLiteral(pub),
		branch.QuoteLiteral(strings.Join(req.EventList(), ",")))); err != nil {
		return fmt.Errorf("creating the publication: %w", err)
	}
	return branch.ExecSQL(branchName, fmt.Sprintf("ALTER PUBLICATION %s ADD TABLE %s.%s",
		branch.QuoteIdent(pub), branch.QuoteIdent(t.Schema), branch.QuoteIdent(t.Name)))
}

// Disable takes a table back out of the publication. It does not undo a REPLICA
// IDENTITY FULL: that is a schema change somebody asked for, it costs only WAL,
// and reverting it silently would be a second change nobody asked for.
func Disable(branchName, schema, table string) error {
	return branch.ExecSQL(branchName, fmt.Sprintf("ALTER PUBLICATION %s DROP TABLE %s.%s",
		branch.QuoteIdent(branch.PublicationName()),
		branch.QuoteIdent(schema), branch.QuoteIdent(table)))
}
