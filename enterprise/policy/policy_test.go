//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

func TestValidatePolicyRule(t *testing.T) {
	good := branch.PolicyRule{RuleID: "no-drop-orders", CommandTag: "ALTER TABLE", Action: "block", Reason: "orders is shared"}
	if err := validatePolicyRule(good); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	bad := []branch.PolicyRule{
		{RuleID: "Bad", CommandTag: "ALTER TABLE", Action: "warn", Reason: "r"},
		{RuleID: "x", CommandTag: "alter table", Action: "warn", Reason: "r"},
		{RuleID: "x", CommandTag: "ALTER TABLE;", Action: "warn", Reason: "r"},
		{RuleID: "x", CommandTag: "ALTER TABLE", Action: "deny", Reason: "r"},
		{RuleID: "x", CommandTag: "ALTER TABLE", Action: "warn", Reason: "  "},
	}
	for _, r := range bad {
		if err := validatePolicyRule(r); !errors.Is(err, branch.ErrInvalidRequest) {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestPolicyRuleSQL(t *testing.T) {
	p, h := `o'rders\s`, ""
	q := addRuleSQL(branch.PolicyRule{RuleID: "r1", CommandTag: "DROP INDEX", Pattern: &p, Hint: &h, Action: "warn", Reason: "it's risky"}, "a@x.com")
	for _, want := range []string{
		"set_config('bb.actor', 'a@x.com', true)",
		`'o''rders\s'`, // quoted, backslash kept
		"'it''s risky'",
		"ON CONFLICT (rule_id) DO NOTHING",
		"SELECT 'added' FROM ins",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("add SQL lost %q:\n%s", want, q)
		}
	}
	if !strings.Contains(q, "'warn', 'it''s risky', NULL, true") {
		t.Errorf("an empty hint should be NULL:\n%s", q)
	}

	block, on := "block", false
	q = updateRuleSQL("drop-column", &block, nil, "")
	if !strings.Contains(q, "coalesce('block', action)") || !strings.Contains(q, "coalesce(NULL::boolean, enabled)") ||
		!strings.Contains(q, "set_config('bb.actor', 'fox', true)") {
		t.Errorf("update SQL:\n%s", q)
	}
	q = updateRuleSQL("drop-column", nil, &on, "cli")
	if !strings.Contains(q, "coalesce(NULL::text, action)") || !strings.Contains(q, "coalesce(false, enabled)") {
		t.Errorf("update SQL:\n%s", q)
	}
	q = removeRuleSQL("x'y", "cli")
	if !strings.Contains(q, "AND NOT builtin") || strings.Count(q, "'x''y'") != 2 {
		t.Errorf("remove SQL:\n%s", q)
	}
}
