// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"fmt"
	"sort"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/edition"
)

// Automatic marks (F6 Gate 1, step 6; design, section 8). In Enterprise, a
// table that holds personal data a reviewer confirmed (point 4.6) has its
// writes audited without anyone marking it: confirming a finding marks its
// table, and `fox audit-log table --personal-data` marks the tables confirmed
// before this existed. Enterprise supplies both (enterprise/pii).
//
// An automatic mark is a mark like any other: a grant, recorded in the
// security log, and a finding when it is taken off outside FoxByte. It only
// ever adds: it audits writes and leaves reads as they were, and rejecting or
// reopening a finding takes nothing off, because a mark that disappears on
// its own is a gap nobody chose. `fox audit-log table <t> --off` takes it off,
// on the record.
//
// Which tables hold confirmed personal data and are not audited is read in
// every edition, as the findings are: the status says so.

var (
	autoMarkPII func(name, schema, table, actor string) (bool, error)
	markAllPII  func(name, actor string) ([]string, error)
)

// SetPIIAuditMarker installs the automatic marks: one table, when its finding
// is confirmed, and every table, for those confirmed before. Called from
// enterprise/pii's init, and from nowhere else.
func SetPIIAuditMarker(one func(name, schema, table, actor string) (bool, error), all func(name, actor string) ([]string, error)) {
	autoMarkPII, markAllPII = one, all
}

// MarkPersonalDataTables marks, for their writes, every table on a branch
// that holds confirmed personal data and is not audited yet. It returns the
// tables it marked, as schema.table.
func MarkPersonalDataTables(name, actor string) ([]string, error) {
	if err := requireFeature(edition.PersonalData); err != nil {
		return nil, err
	}
	if markAllPII == nil {
		return nil, ErrPersonalDataNotLicensed
	}
	if err := checkName(name); err != nil {
		return nil, err
	}
	return markAllPII(name, actor)
}

// PersonalTablesUnmarked lists the tables on a branch that hold personal data
// a reviewer confirmed and whose writes are not audited.
func PersonalTablesUnmarked(name string) ([]string, error) {
	rep, err := PersonalDataFindings(name)
	if err != nil || len(rep.Findings) == 0 {
		return nil, err
	}
	marks, err := AuditMarks(name)
	if err != nil {
		return nil, err
	}
	want := UnmarkedPersonalTables(rep.Findings, marks)
	if len(want) == 0 {
		return nil, nil
	}
	exist, err := tablesThatExist(name, want)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range want {
		if exist[t] {
			out = append(out, t)
		}
	}
	return out, nil
}

// UnmarkedPersonalTables is the tables, as schema.table and sorted, that have
// a confirmed finding and no mark on their writes.
func UnmarkedPersonalTables(findings []PIIFinding, marks []AuditMark) []string {
	marked := map[string]bool{}
	for _, m := range marks {
		if m.Writes {
			marked[m.Schema+"."+m.Name] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		t := f.Schema + "." + f.Table
		if f.State != PIIConfirmed || marked[t] || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// tablesThatExist reports which of tables (schema.table) a branch has: a
// finding outlives the table it was found in.
func tablesThatExist(name string, tables []string) (map[string]bool, error) {
	var lits []string
	for _, t := range tables {
		lits = append(lits, QuoteLiteral(t))
	}
	out, err := QuerySQL(name, "SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "+
		"WHERE c.relkind IN ('r', 'p') AND n.nspname || '.' || c.relname = ANY (ARRAY["+strings.Join(lits, ", ")+"]::text[])")
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, strings.TrimSpace(out))
	}
	ex := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ex[l] = true
		}
	}
	return ex, nil
}

// MarkAuditedWrites marks a table's writes and leaves its reads as they are:
// what an automatic mark does.
func MarkAuditedWrites(target, schema, table, actor, tool string) error {
	if err := checkName(target); err != nil {
		return err
	}
	if err := checkTableName(schema, table); err != nil {
		return err
	}
	return trackExec(target, auditRolesSQL()+trackSQL(actor, tool, markWritesSQL(tableRef(schema, table)), false))
}

// markWritesSQL is markSQL without touching SELECT.
func markWritesSQL(rel string) string {
	return fmt.Sprintf(`DO $$
DECLARE rel regclass := %s;
BEGIN
  IF (SELECT relkind FROM pg_class WHERE oid = rel) NOT IN ('r', 'p') THEN
    RAISE EXCEPTION '%% is not a table: mark the tables it reads and writes', rel;
  END IF;
  EXECUTE format('GRANT INSERT, UPDATE, DELETE ON %%s TO %s', rel);
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %%s TO %s', rel);
END $$;`, rel, AuditRole, AuditReadRole)
}
