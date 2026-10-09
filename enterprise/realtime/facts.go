//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"encoding/json"
	"fmt"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// What the catalog says about the tables on a branch.
//
// One query for every table rather than one query per table: `doctor` asks
// about all of them, and a hundred round trips through `docker exec psql` is a
// noticeably different experience from one.
//
// The rows come back as JSON rather than as delimited text. The engine's other
// catalog reads split on '|', which is fine for slot names and publication
// names because Postgres generates those — but a table or an index may be named
// anything a person can quote, including a pipe, and a readiness report that
// mis-parses a table is worse than one that is slow.

// factsSQL selects everything Assess needs. The CTE keeps the unique-index
// search readable: an index Postgres will accept as a replica identity is
// unique, valid, immediate, not partial, and over columns that are all NOT NULL.
const factsSQL = `
WITH ident AS (
  SELECT i.indrelid, ci.relname,
         row_number() OVER (PARTITION BY i.indrelid ORDER BY i.indnatts, ci.relname) AS rank
  FROM pg_index i
  JOIN pg_class ci ON ci.oid = i.indexrelid
  WHERE i.indisunique AND i.indisvalid AND i.indimmediate
    AND i.indpred IS NULL
    AND NOT i.indisprimary
    AND NOT EXISTS (
      SELECT 1 FROM unnest(i.indkey) AS k(attnum)
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
      WHERE NOT a.attnotnull)
    AND 0 <> ALL (i.indkey)          -- no expression columns
),
stats AS (
  SELECT relid, n_tup_ins, n_tup_upd, n_tup_del, n_live_tup FROM pg_stat_user_tables
)
SELECT json_build_object(
  'schema', n.nspname,
  'name', c.relname,
  'kind', c.relkind::text,
  'has_primary_key', EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisprimary),
  'replica_identity', c.relreplident::text,
  'rls_enabled', c.relrowsecurity,
  'client_can_select', has_table_privilege('db_client', c.oid, 'SELECT'),
  'client_can_use_schema', has_schema_privilege('db_client', n.nspname, 'USAGE'),
  'columns_hidden', coalesce((
      SELECT json_agg(a.attname ORDER BY a.attname)
      FROM pg_attribute a
      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
        AND NOT has_column_privilege('db_client', c.oid, a.attnum, 'SELECT')), '[]'::json),
  'is_system', (n.nspname = 'bb'
                OR n.nspname IN ('pg_catalog','information_schema')
                OR n.nspname LIKE 'pg\_%'),
  'is_extension_owned', EXISTS (
      SELECT 1 FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'),
  'unique_index', (SELECT relname FROM ident WHERE ident.indrelid = c.oid AND rank = 1),
  'inserts', coalesce((SELECT n_tup_ins FROM stats WHERE relid = c.oid), 0),
  'updates', coalesce((SELECT n_tup_upd FROM stats WHERE relid = c.oid), 0),
  'deletes', coalesce((SELECT n_tup_del FROM stats WHERE relid = c.oid), 0),
  'stats_days', GREATEST(extract(epoch FROM (now() - coalesce(
      (SELECT stats_reset FROM pg_stat_database WHERE datname = current_database()),
      now() - interval '1 day'))) / 86400.0, 0.0001),
  'avg_row_bytes', CASE
      WHEN coalesce((SELECT n_live_tup FROM stats WHERE relid = c.oid), 0) > 0
      THEN (pg_total_relation_size(c.oid) / (SELECT n_live_tup FROM stats WHERE relid = c.oid))::bigint
      ELSE 0 END,
  'published', EXISTS (
      SELECT 1 FROM pg_publication_tables pt
      WHERE pt.pubname LIKE '` + branch.PublicationPrefix + `%'
        AND pt.schemaname = n.nspname AND pt.tablename = c.relname)
)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p','v','m')`

// factsRow is the JSON above, before it becomes a Table.
type factsRow struct {
	Table
	ReplicaIdentityText string `json:"replica_identity"`
	Published           bool   `json:"published"`
}

func decodeFacts(lines []string) ([]factsRow, error) {
	out := make([]factsRow, 0, len(lines))
	for _, l := range lines {
		if l == "" {
			continue
		}
		var r factsRow
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			return nil, fmt.Errorf("reading the catalog: %w", err)
		}
		if r.ReplicaIdentityText != "" {
			r.ReplicaIdentity = r.ReplicaIdentityText[0]
		}
		out = append(out, r)
	}
	return out, nil
}

// Survey is every relation on a branch, with its verdict. System tables are
// included rather than filtered out: a person looking for one deserves to be
// told why it is not there, and the caller can hide them.
func Survey(branchName string, events []string) ([]Verdict, error) {
	lines, err := branch.LedgerQuery(branch.ServingBranch(branchName),
		factsSQL+" ORDER BY n.nspname, c.relname")
	if err != nil {
		return nil, err
	}
	rows, err := decodeFacts(lines)
	if err != nil {
		return nil, err
	}
	out := make([]Verdict, 0, len(rows))
	for _, r := range rows {
		out = append(out, Assess(r.Table, events, r.Published))
	}
	return out, nil
}

// Look is Survey for one table.
func Look(branchName, schema, table string, events []string) (Verdict, error) {
	lines, err := branch.LedgerQuery(branch.ServingBranch(branchName),
		factsSQL+fmt.Sprintf(" AND n.nspname = %s AND c.relname = %s",
			branch.QuoteLiteral(schema), branch.QuoteLiteral(table)))
	if err != nil {
		return Verdict{}, err
	}
	rows, err := decodeFacts(lines)
	if err != nil {
		return Verdict{}, err
	}
	if len(rows) == 0 {
		return Verdict{}, fmt.Errorf("there is no table %s.%s on %q", schema, table, branchName)
	}
	return Assess(rows[0].Table, events, rows[0].Published), nil
}
