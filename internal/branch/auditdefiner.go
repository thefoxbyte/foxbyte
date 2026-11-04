// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SECURITY DEFINER functions (F6 Gate 1, step 6; design, sections 12 and 19).
//
// The prototype found that pgAudit's object audit does not see the statements
// inside a SECURITY DEFINER function, whoever owns it: a definer function that
// writes a marked table writes it unaudited. Of the three options section 19
// gave, this is the one that costs nothing and is honest either way: say so.
// Each definer function whose body names a marked table is a finding, in
// `fox audit-log status`, `fox check` and the console, until it is made
// SECURITY INVOKER (whose statements are audited) or the table is unmarked.
// Nothing is refused, and logging such functions' calls, or refusing to mark
// their tables, can still come later.
//
// "Names" is a word match on the function's source, so it can say too much
// (a comment, a column called the same) and too little (a table name built at
// run time for EXECUTE). It says which, so a person can look. Functions in the
// Blackbox's own schemas (bb, and F1's bb_f1), and those an extension
// installed, are left out.

// DefinerFunc is one SECURITY DEFINER function whose body names a marked table.
type DefinerFunc struct {
	Function string   `json:"function"` // its signature, as regprocedure writes it
	Owner    string   `json:"owner"`    // whom it runs as
	Tables   []string `json:"tables"`   // the marked tables it names, schema.table
}

const definerSQL = `WITH marked AS (
  SELECT DISTINCT n.nspname, c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN LATERAL aclexplode(c.relacl) a
    JOIN pg_roles r ON r.oid = a.grantee AND r.rolname = 'bb_audit'
   WHERE c.relkind IN ('r', 'p'))
SELECT coalesce(json_agg(json_build_object('function', f, 'owner', owner, 'tables', tables) ORDER BY f), '[]'::json)
  FROM (SELECT p.oid::regprocedure::text AS f, pg_get_userbyid(p.proowner) AS owner,
               array_agg(m.nspname || '.' || m.relname ORDER BY m.nspname, m.relname) AS tables
          FROM pg_proc p
          JOIN pg_namespace pn ON pn.oid = p.pronamespace
          JOIN marked m ON p.prosrc ~* ('\m' || regexp_replace(m.relname, '([^[:alnum:]_])', '\\\1', 'g') || '\M')
         WHERE p.prosecdef
           AND pn.nspname NOT IN ('pg_catalog', 'information_schema', 'bb', 'bb_f1')
           AND NOT EXISTS (SELECT 1 FROM pg_depend d
                            WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
         GROUP BY p.oid, p.proowner) x`

// DefinerFunctions lists a branch's SECURITY DEFINER functions that name a
// marked table.
func DefinerFunctions(name string) ([]DefinerFunc, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	out, err := QuerySQL(name, definerSQL)
	if err != nil {
		return nil, fmt.Errorf("reading the definer functions on %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	var fs []DefinerFunc
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &fs); err != nil {
		return nil, fmt.Errorf("reading the definer functions: %w", err)
	}
	return fs, nil
}

// definerFinding is one definer function as a finding.
func definerFinding(branch string, f DefinerFunc) AuditFinding {
	return AuditFinding{Kind: "definer", Branch: branch, Detail: fmt.Sprintf(
		"%s runs as %s (SECURITY DEFINER) and its body names %s: what it does to them is not in the audit log, because pgAudit does not see inside definer functions",
		f.Function, f.Owner, strings.Join(f.Tables, ", "))}
}
