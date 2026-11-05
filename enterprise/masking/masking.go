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
	branch.SetMasker(&branch.Masker{Setup: setup, SetRule: setRule, DropRule: dropRule, MaskTables: maskTables})
}

// setup makes the install's default key if it has none, then the branch's
// roles, schema, rules table and a masked reader's rights. It runs again
// safely: a table already masked is masked again from its rules.
func setup(b, actor string) error {
	if err := branch.EnsureMaskKey(keyDomain); err != nil {
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
	return nil
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
	if _, err := maskTable(r.Schema, r.Table, cols, rulesFor(rules, r.Schema, r.Table)); err != nil {
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
	m, err := maskTable(schema, table, cols, rulesFor(all, schema, table))
	if err != nil {
		return err
	}
	if err := branch.RunMaskSQL(b, actor, append(m.Drop, m.Build...), true); err != nil {
		return fmt.Errorf("making %s.%s's masks: %w", schema, table, err)
	}
	if m.Fill != "" {
		if err := branch.RunMaskScript(b, m.Fill); err != nil {
			return fmt.Errorf("filling %s.%s's masks: %w (a masked reader is refused the table until it is masked again)", schema, table, err)
		}
	}
	if len(m.View) > 0 {
		if err := branch.RunMaskSQL(b, actor, m.View, false); err != nil {
			return fmt.Errorf("making %s.%s's view: %w", schema, table, err)
		}
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
