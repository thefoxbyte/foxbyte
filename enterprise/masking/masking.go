//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package masking

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

func init() {
	branch.SetMasker(&branch.Masker{Setup: setup, SetRule: setRule, DropRule: dropRule, MaskTables: maskTables,
		Rotate: rotate, UseDomain: useDomain, AuditReads: auditReads, MaskBranch: maskBranch})
}

// setup makes the install's default key if it has none, then the branch's
// roles, schema, rules table and a masked reader's rights. It runs again
// safely: a table already masked is masked again from its rules.
func setup(b, actor string) error {
	if err := branch.EnsureMaskKey(branch.DefaultMaskDomain); err != nil {
		return fmt.Errorf("making the masking key: %w", err)
	}
	if err := branch.RunMaskSQL(b, actor, setupSQL(), false); err != nil {
		return fmt.Errorf("setting masking up on %s: %w", b, err)
	}
	rules, err := branch.MaskRulesOn(b)
	if err != nil {
		return err
	}
	for _, t := range tablesOf(rules) {
		if err := remask(b, t[0], t[1], actor, rules); err != nil {
			return err
		}
	}
	return closePaths(b, actor)
}

// tablesOf is the tables rules are on, each once.
func tablesOf(rules []branch.MaskRule) [][2]string {
	seen := map[[2]string]bool{}
	var out [][2]string
	for _, r := range rules {
		k := [2]string{r.Schema, r.Table}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// confirmedCategory is the category of the confirmed finding at a place: a
// rule is set only on personal data a reviewer confirmed (point 4.6).
func confirmedCategory(b string, r branch.MaskRule) (string, error) {
	// A branch never scanned has no findings, and so nothing confirmed.
	if ok, err := branch.RelationExists(b, "bb.pii_findings"); err != nil || !ok {
		return "", err
	}
	out, err := branch.QuerySQL(b, fmt.Sprintf(`SELECT coalesce((SELECT category FROM bb.pii_findings WHERE schema_name = %s
     AND table_name = %s AND column_name = %s AND json_path = %s AND state = 'confirmed' ORDER BY id LIMIT 1), '')`,
		lit(r.Schema), lit(r.Table), lit(r.Column), lit(r.Path)))
	if err != nil {
		return "", fmt.Errorf("reading the findings on %s: %w (%s)", b, err, strings.TrimSpace(out))
	}
	return strings.TrimSpace(out), nil
}

func setRule(b string, r branch.MaskRule) error {
	if !hasSetup(b) {
		return fmt.Errorf("%w: masking is not set up on %s: %s mask setup --branch %s", branch.ErrInvalidRequest, b, brand.CLI, b)
	}
	cat, err := confirmedCategory(b, r)
	if err != nil {
		return err
	}
	if cat == "" {
		return fmt.Errorf("%w: no confirmed personal data at %s: a rule is set on a finding a reviewer confirmed (%s pii --branch %s, then %s pii mark <id> confirm)",
			branch.ErrInvalidRequest, r.Where(), brand.CLI, b, brand.CLI)
	}
	r.Category = cat
	if r.Rule == "" {
		r.Rule = branch.DefaultMaskRule(cat)
	}
	if err := branch.CheckMaskRule(r.Rule, cat); err != nil {
		return err
	}
	// Checked against the table before the rule is kept: a rule that cannot
	// be made is refused, not left waiting.
	rules, err := branch.MaskRulesOn(b)
	if err != nil {
		return err
	}
	rules = replaceRule(rules, r)
	cols, err := branch.MaskColumns(b, r.Schema, r.Table)
	if err != nil {
		return err
	}
	if _, err := maskTable(r.Schema, r.Table, cols, rulesFor(rules, r.Schema, r.Table), branch.DefaultMaskDomain); err != nil {
		return err
	}
	if err := branch.RunMaskSQL(b, r.By, []string{fmt.Sprintf(`INSERT INTO bb.mask_rules (schema_name, table_name, column_name, json_path, rule, category, set_by)
  VALUES (%s, %s, %s, %s, %s, %s, %s)
  ON CONFLICT (schema_name, table_name, column_name, json_path) DO UPDATE SET rule = EXCLUDED.rule, category = EXCLUDED.category,
    set_by = EXCLUDED.set_by, set_at = now()`, lit(r.Schema), lit(r.Table), lit(r.Column), lit(r.Path), lit(r.Rule), lit(cat), lit(r.By))}, false); err != nil {
		return err
	}
	return remask(b, r.Schema, r.Table, r.By, rules)
}

func dropRule(b, schema, table, column, path, actor string) error {
	if !hasSetup(b) {
		return fmt.Errorf("%w: masking is not set up on %s", branch.ErrInvalidRequest, b)
	}
	if err := branch.RunMaskSQL(b, actor, []string{fmt.Sprintf(
		"DELETE FROM bb.mask_rules WHERE schema_name = %s AND table_name = %s AND column_name = %s AND json_path = %s",
		lit(schema), lit(table), lit(column), lit(path))}, false); err != nil {
		return err
	}
	rules, err := branch.MaskRulesOn(b)
	if err != nil {
		return err
	}
	return remask(b, schema, table, actor, rules)
}

// remask makes a table's masks again from its rules: the old ones and the
// masked reader's rights taken away first, so between the two a masked reader
// is refused the table, never shown it half masked.
func remask(b, schema, table, actor string, all []branch.MaskRule) error {
	cols, err := branch.MaskColumns(b, schema, table)
	if err != nil {
		return err
	}
	domain, err := tableDomain(b, schema, table)
	if err != nil {
		return err
	}
	m, err := maskTable(schema, table, cols, rulesFor(all, schema, table), domain)
	if err != nil {
		return err
	}
	// Made under the domain's key now.
	k, _ := branch.MaskKeyFor(domain)
	m.View = append(m.View, tableKeySQL(schema, table, domain, max(k.Gen, 1)))
	if err := branch.RunMaskSQL(b, actor, append(m.Drop, m.Build...), true); err != nil {
		return fmt.Errorf("making %s.%s's masks: %w", schema, table, err)
	}
	if m.Fill != "" {
		if err := branch.RunMaskScript(b, m.Fill); err != nil {
			return fmt.Errorf("filling %s.%s's masks: %w (a masked reader is refused the table until it is masked again)", schema, table, err)
		}
	}
	if len(m.View) > 0 {
		// The view's grants name bb_audit_read, which a branch set up before
		// step 3 may not have.
		if err := branch.RunMaskSQL(b, actor, append(lookupSQL()[:1], m.View...), false); err != nil {
			return fmt.Errorf("making %s.%s's view: %w", schema, table, err)
		}
	}
	return closePaths(b, actor)
}

// closePaths runs the guard on the paths around the views (closeSQL) after
// the masks changed: what a new rule closes is closed, and what a rule taken
// off closed is open again. A branch set up before step 4 gets the guard
// first.
func closePaths(b, actor string) error {
	if ok, err := branch.RelationExists(b, "bb.mask_closed"); err != nil {
		return err
	} else if !ok {
		if err := branch.RunMaskSQL(b, actor, closeSQL(), false); err != nil {
			return fmt.Errorf("making the masks' guard on %s: %w", b, err)
		}
	}
	if err := branch.RunMaskSQL(b, actor, []string{closePathsSQL}, false); err != nil {
		return fmt.Errorf("closing the paths around %s's masks: %w", b, err)
	}
	return nil
}

func replaceRule(rules []branch.MaskRule, r branch.MaskRule) []branch.MaskRule {
	out := []branch.MaskRule{r}
	for _, x := range rules {
		if x.Schema == r.Schema && x.Table == r.Table && x.Column == r.Column && x.Path == r.Path {
			continue
		}
		out = append(out, x)
	}
	return out
}

func rulesFor(rules []branch.MaskRule, schema, table string) []branch.MaskRule {
	var out []branch.MaskRule
	for _, r := range rules {
		if r.Schema == schema && r.Table == table {
			out = append(out, r)
		}
	}
	return out
}

// tableKeySQL records a table's domain and the key its masks are made under.
func tableKeySQL(schema, table, domain string, gen int) string {
	return fmt.Sprintf(`INSERT INTO bb.mask_tables (schema_name, table_name, key_domain, key_gen) VALUES (%s, %s, %s, %d)
  ON CONFLICT (schema_name, table_name) DO UPDATE SET key_domain = EXCLUDED.key_domain, key_gen = EXCLUDED.key_gen`,
		lit(schema), lit(table), lit(domain), gen)
}

// tableDomain is the domain a table's masks are under: the default unless one
// was chosen for it.
func tableDomain(b, schema, table string) (string, error) {
	if err := ensureKeysTable(b); err != nil {
		return "", err
	}
	out, err := branch.QuerySQL(b, fmt.Sprintf(`SELECT coalesce((SELECT key_domain FROM bb.mask_tables WHERE schema_name = %s AND table_name = %s), %s)`,
		lit(schema), lit(table), lit(branch.DefaultMaskDomain)))
	if err != nil {
		return "", fmt.Errorf("reading %s.%s's key domain on %s: %w (%s)", schema, table, b, err, strings.TrimSpace(out))
	}
	return strings.TrimSpace(out), nil
}

// ensureKeysTable adds the table of keys to a branch set up before step 2.
func ensureKeysTable(b string) error {
	if ok, err := branch.RelationExists(b, "bb.mask_tables"); err != nil || ok {
		return err
	}
	return branch.RunMaskSQL(b, "system", []string{maskTablesDDL, "REVOKE ALL ON bb.mask_tables FROM PUBLIC"}, false)
}

func hasSetup(b string) bool {
	out, err := branch.QuerySQL(b, "SELECT to_regclass('bb.mask_rules') IS NOT NULL AND to_regrole('"+branch.MaskedRole+"') IS NOT NULL")
	return err == nil && strings.TrimSpace(out) == "t"
}

// maskTables lists the tables whose masks are made: the views in bb_mask.
func maskTables(b string) ([]string, error) {
	out, err := branch.QuerySQL(b, `SELECT coalesce(json_agg(c.relname ORDER BY c.relname), '[]'::json)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '`+branch.MaskSchema+`' AND c.relkind = 'v'`)
	if err != nil {
		return nil, err
	}
	var names []string
	err = json.Unmarshal([]byte(strings.TrimSpace(out)), &names)
	return names, err
}

// auditReads gives bb_audit_read SELECT on a branch's tables with rules, so an
// unmask holder's reads of them are logged: tables masked since step 3 have it
// from their view, older ones get it here. The lookup is made too, if the
// branch was set up before it existed.
func auditReads(b string) error {
	if !hasSetup(b) {
		return fmt.Errorf("%w: masking is not set up on %s: %s mask setup --branch %s", branch.ErrInvalidRequest, b, brand.CLI, b)
	}
	if ok, err := branch.RelationExists(b, branch.MaskSchema+".lookups"); err != nil {
		return err
	} else if !ok {
		if err := ensureKeysTable(b); err != nil {
			return err
		}
		if err := branch.RunMaskSQL(b, "system", lookupSQL(), false); err != nil {
			return fmt.Errorf("making the lookup on %s: %w", b, err)
		}
	}
	rules, err := branch.MaskRulesOn(b)
	if err != nil {
		return err
	}
	return branch.RunMaskSQL(b, "system", auditReadsSQL(tablesOf(rules)), false)
}
