// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Marking tables for the audit log (F6 Gate 1, step 2; design, section 8).
//
// pgAudit's object audit works through grants, not through anything FoxByte
// keeps: a statement is logged when the audit role holds the privilege it
// uses on a table it touches. So a mark is a grant.
//
//   - Writes: bb_audit holds INSERT, UPDATE and DELETE, so every write to the
//     table is logged, by every login.
//   - Reads: bb_audit holds SELECT too, so every read is logged. Until masking
//     exists (point 7), reads are audited per table, for everyone; after, for
//     the logins that may unmask (section 8).
//   - bb_audit_read holds all four on every marked table, for the logins
//     given it as their audit role, whose reads are logged then.
//
// Grants are in the catalog, so a mark travels with a branch made from the
// table's branch. A mark can be made with audit off: it takes effect when
// audit is turned on, and turning audit off keeps it.
//
// A table's owner can REVOKE the grant, as for any grant on a table they own:
// the superuser's grant is recorded as the owner's. That is not silent:
// pgAudit logs the REVOKE (ROLE class, for everyone), and the Blackbox records
// it with who ran it. Step 4 compares marks with what was set.

// AuditMark is one table and what of it is audited.
type AuditMark struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Writes bool   `json:"writes"`
	Reads  bool   `json:"reads"`
}

// auditRolesSQL makes the two roles if this branch has not got them: a mark
// can be made before audit was ever turned on.
func auditRolesSQL() string {
	var b strings.Builder
	for _, role := range []string{AuditRole, AuditReadRole} {
		fmt.Fprintf(&b, "DO $$ BEGIN CREATE ROLE %s NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;\n", role)
	}
	return b.String()
}

// ensureAuditRolesBestEffort makes the audit roles on a running database that
// lacks them, for what replays another branch's marks there (promotion). A
// failure is left for the replay to report, which says what failed.
func ensureAuditRolesBestEffort(name string) {
	if ContainerState(name) != "running" {
		return
	}
	_ = psqlQuiet(name, auditRolesSQL())
}

// markSQL grants what a mark is, on a table only: a view's reads and writes
// are logged on the tables under it, which are what to mark.
func markSQL(rel string, reads bool) string {
	sel := fmt.Sprintf("REVOKE SELECT ON %%s FROM %s", AuditRole)
	if reads {
		sel = fmt.Sprintf("GRANT SELECT ON %%s TO %s", AuditRole)
	}
	return fmt.Sprintf(`DO $$
DECLARE rel regclass := %s;
BEGIN
  IF (SELECT relkind FROM pg_class WHERE oid = rel) NOT IN ('r', 'p') THEN
    RAISE EXCEPTION '%% is not a table: mark the tables it reads and writes', rel;
  END IF;
  EXECUTE format('GRANT INSERT, UPDATE, DELETE ON %%s TO %s', rel);
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %%s TO %s', rel);
  EXECUTE format('%s', rel);
END $$;`, rel, AuditRole, AuditReadRole, sel)
}

// unmarkSQL takes every privilege of both audit roles off the table.
func unmarkSQL(rel string) string {
	return fmt.Sprintf(`DO $$
DECLARE rel regclass := %s;
BEGIN
  EXECUTE format('REVOKE ALL ON %%s FROM %s, %s', rel);
END $$;`, rel, AuditRole, AuditReadRole)
}

// MarkAudited marks a table: its writes logged, and its reads if reads is
// set. Marking a marked table again sets reads as asked.
func MarkAudited(target, schema, table string, reads bool, actor, tool string) error {
	if err := checkName(target); err != nil {
		return err
	}
	if err := checkTableName(schema, table); err != nil {
		return err
	}
	return trackExec(target, auditRolesSQL()+trackSQL(actor, tool, markSQL(tableRef(schema, table), reads), false))
}

// UnmarkAudited stops auditing a table's reads and writes.
func UnmarkAudited(target, schema, table, actor, tool string) error {
	if err := checkName(target); err != nil {
		return err
	}
	if err := checkTableName(schema, table); err != nil {
		return err
	}
	return trackExec(target, auditRolesSQL()+trackSQL(actor, tool, unmarkSQL(tableRef(schema, table)), false))
}

// auditMarksSQL lists the marked tables from their access lists, by name, so
// a branch where the roles were never made answers with none rather than an
// error (has_table_privilege refuses a role that does not exist).
const auditMarksSQL = `SELECT coalesce(json_agg(json_build_object('schema', schema, 'name', name, 'writes', writes, 'reads', reads)
    ORDER BY schema, name), '[]'::json)
  FROM (SELECT n.nspname AS schema, c.relname AS name,
          bool_or(a.privilege_type IN ('INSERT', 'UPDATE', 'DELETE')) AS writes,
          bool_or(a.privilege_type = 'SELECT') AS reads
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(c.relacl) a
        JOIN pg_roles r ON r.oid = a.grantee AND r.rolname = 'bb_audit'
        WHERE c.relkind IN ('r', 'p')
        GROUP BY 1, 2) m`

// AuditMarks lists a branch's marked tables.
func AuditMarks(target string) ([]AuditMark, error) {
	if err := checkName(target); err != nil {
		return nil, err
	}
	out, err := QuerySQL(target, auditMarksSQL)
	if err != nil {
		return nil, fmt.Errorf("reading the audited tables on %s: %w (%s)", target, err, strings.TrimSpace(out))
	}
	return parseAuditMarks(out)
}

func parseAuditMarks(out string) ([]AuditMark, error) {
	var m []AuditMark
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &m); err != nil {
		return nil, fmt.Errorf("reading the audited tables: %w", err)
	}
	if m == nil {
		m = []AuditMark{}
	}
	return m, nil
}

// MarkWhat is a mark as a sentence, for the security log and the CLI.
func MarkWhat(m AuditMark) string {
	switch {
	case m.Writes && m.Reads:
		return "writes and reads"
	case m.Reads:
		return "reads"
	case m.Writes:
		return "writes"
	}
	return "nothing"
}
