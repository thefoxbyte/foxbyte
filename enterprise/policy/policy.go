//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

// Package policy is authoring Blackbox policy rules: adding one, changing
// whether it blocks or warns, and removing it.
//
// Only the authoring. Reading the rules, checking a statement against them and
// the evaluations log stay in internal/branch, free in every edition — a rule
// written before an install changed edition keeps enforcing, and being unable
// to read the rule that just blocked you would be worse than useless. The two
// default guardrails are enforced in SQL and are not rules at all.
//
// IsAdmin stays there too, and not by accident: internal/access resolves
// authorization through it, so moving this file wholesale would have taken
// authorization out of the Standard build.
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

var commandTagRe = regexp.MustCompile(`^[A-Z][A-Z ]{1,62}[A-Z]$`)

// init registers the three with internal/branch.
func init() { branch.SetPolicyAuthoring(add, update, remove) }

func validatePolicyRule(r branch.PolicyRule) error {
	switch {
	case !ledger.ValidRuleID(r.RuleID):
		return fmt.Errorf("%w: rule id %q must be lowercase letters, digits and dashes", branch.ErrInvalidRequest, r.RuleID)
	case !commandTagRe.MatchString(r.CommandTag):
		return fmt.Errorf("%w: command %q must be a command tag such as \"ALTER TABLE\"", branch.ErrInvalidRequest, r.CommandTag)
	case r.Action != "warn" && r.Action != "block":
		return fmt.Errorf("%w: action must be warn or block", branch.ErrInvalidRequest)
	case strings.TrimSpace(r.Reason) == "":
		return fmt.Errorf("%w: a reason is required", branch.ErrInvalidRequest)
	}
	return nil
}

func policyActor(actor string) string {
	if actor == "" {
		return brand.CLI
	}
	return actor
}

// Rule changes run in one psql -c transaction that first sets bb.actor, which
// the rule-history trigger records.
func withActor(actor, sql string) string {
	return fmt.Sprintf("SELECT set_config('bb.actor', %s, true) IS NOT NULL;\n%s", branch.QuoteLiteral(policyActor(actor)), sql)
}

func addRuleSQL(r branch.PolicyRule, actor string) string {
	return withActor(actor, fmt.Sprintf(`WITH ins AS (
  INSERT INTO bb.policy_rules (rule_id, command_tag, pattern, action, reason, hint, enabled, updated_by)
  VALUES (%s, %s, %s, %s, %s, %s, true, %s)
  ON CONFLICT (rule_id) DO NOTHING RETURNING rule_id)
SELECT 'added' FROM ins;`,
		branch.QuoteLiteral(r.RuleID), branch.QuoteLiteral(r.CommandTag), branch.QuoteLiteralOrNull(r.Pattern), branch.QuoteLiteral(r.Action),
		branch.QuoteLiteral(r.Reason), branch.QuoteLiteralOrNull(r.Hint), branch.QuoteLiteral(policyActor(actor))))
}

func updateRuleSQL(ruleID string, action *string, enabled *bool, actor string) string {
	a, e := "NULL::text", "NULL::boolean"
	if action != nil {
		a = branch.QuoteLiteral(*action)
	}
	if enabled != nil {
		e = fmt.Sprintf("%t", *enabled)
	}
	return withActor(actor, fmt.Sprintf(`WITH u AS (
  UPDATE bb.policy_rules SET action = coalesce(%s, action), enabled = coalesce(%s, enabled),
         updated_at = clock_timestamp(), updated_by = %s
  WHERE rule_id = %s RETURNING 1)
SELECT 'updated' FROM u;`, a, e, branch.QuoteLiteral(policyActor(actor)), branch.QuoteLiteral(ruleID)))
}

func removeRuleSQL(ruleID, actor string) string {
	return withActor(actor, fmt.Sprintf(`WITH d AS (DELETE FROM bb.policy_rules WHERE rule_id = %[1]s AND NOT builtin RETURNING 1)
SELECT 'removed' FROM d
UNION ALL SELECT 'builtin' FROM bb.policy_rules WHERE rule_id = %[1]s AND builtin;`, branch.QuoteLiteral(ruleID)))
}

func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// AddPolicyRule adds a custom rule.
func add(name string, r branch.PolicyRule, actor string) error {
	name, err := branch.ResolveBranch(name)
	if err != nil {
		return err
	}
	if err := validatePolicyRule(r); err != nil {
		return err
	}
	lines, err := branch.PolicyQuery(name, addRuleSQL(r, actor))
	if err != nil {
		return err
	}
	if !hasLine(lines, "added") {
		return fmt.Errorf("%w: %q", branch.ErrRuleExists, r.RuleID)
	}
	return nil
}

// UpdatePolicyRule changes a rule's action and/or whether it is enabled.
func update(name, ruleID string, action *string, enabled *bool, actor string) error {
	name, err := branch.ResolveBranch(name)
	if err != nil {
		return err
	}
	if action != nil && *action != "warn" && *action != "block" {
		return fmt.Errorf("%w: action must be warn or block", branch.ErrInvalidRequest)
	}
	if action == nil && enabled == nil {
		return fmt.Errorf("%w: nothing to change (send action and/or enabled)", branch.ErrInvalidRequest)
	}
	lines, err := branch.PolicyQuery(name, updateRuleSQL(ruleID, action, enabled, actor))
	if err != nil {
		return err
	}
	if !hasLine(lines, "updated") {
		return fmt.Errorf("%w: %q", branch.ErrRuleNotFound, ruleID)
	}
	return nil
}

// RemovePolicyRule removes a custom rule. Built-in rules can only be disabled.
func remove(name, ruleID, actor string) error {
	name, err := branch.ResolveBranch(name)
	if err != nil {
		return err
	}
	lines, err := branch.PolicyQuery(name, removeRuleSQL(ruleID, actor))
	if err != nil {
		return err
	}
	switch {
	case hasLine(lines, "removed"):
		return nil
	case hasLine(lines, "builtin"):
		return fmt.Errorf("%w — disable it instead: fox policy disable %s", branch.ErrBuiltinRule, ruleID)
	}
	return fmt.Errorf("%w: %q", branch.ErrRuleNotFound, ruleID)
}
