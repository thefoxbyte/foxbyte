// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

func TestValidatePolicyRule(t *testing.T) {
	good := PolicyRule{RuleID: "no-drop-orders", CommandTag: "ALTER TABLE", Action: "block", Reason: "orders is shared"}
	if err := validatePolicyRule(good); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	bad := []PolicyRule{
		{RuleID: "Bad", CommandTag: "ALTER TABLE", Action: "warn", Reason: "r"},
		{RuleID: "x", CommandTag: "alter table", Action: "warn", Reason: "r"},
		{RuleID: "x", CommandTag: "ALTER TABLE;", Action: "warn", Reason: "r"},
		{RuleID: "x", CommandTag: "ALTER TABLE", Action: "deny", Reason: "r"},
		{RuleID: "x", CommandTag: "ALTER TABLE", Action: "warn", Reason: "  "},
	}
	for _, r := range bad {
		if err := validatePolicyRule(r); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestPolicyRuleSQL(t *testing.T) {
	p, h := `o'rders\s`, ""
	q := addRuleSQL(PolicyRule{RuleID: "r1", CommandTag: "DROP INDEX", Pattern: &p, Hint: &h, Action: "warn", Reason: "it's risky"}, "a@x.com")
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

func TestFriendlyPolicyErr(t *testing.T) {
	err := friendlyPolicyErr("main", errors.New(`ERROR:  new row for relation "policy_rules" violates check constraint "policy_rules_pattern_check"`))
	if !errors.Is(err, ErrInvalidRequest) || !strings.Contains(err.Error(), "invalid pattern") {
		t.Errorf("pattern error: %v", err)
	}
	err = friendlyPolicyErr("qa", errors.New(`ERROR:  relation "bb.policy_rules" does not exist`))
	if !strings.Contains(err.Error(), "fox blackbox upgrade qa") {
		t.Errorf("not installed: %v", err)
	}
	other := errors.New("boom")
	if friendlyPolicyErr("main", other) != other {
		t.Error("other errors must pass through")
	}
}

func TestFormatPolicy(t *testing.T) {
	if got := FormatPolicyCheck("CREATE TABLE", nil); !strings.Contains(got, "no policy rule matches") {
		t.Errorf("no match: %q", got)
	}
	out := FormatPolicyCheck("ALTER TABLE", []ledger.PolicyDetail{
		{RuleID: "drop-column", Action: "block", Reason: "dropping a column deletes its data"},
		{RuleID: "alter-column-type", Action: "warn", Reason: "rewrites"},
	})
	lines := strings.Split(out, "\n")
	if len(lines) != 3 || lines[0] != "command: ALTER TABLE" || !strings.HasPrefix(lines[1], "BLOCK") || !strings.Contains(lines[1], "drop-column") {
		t.Errorf("check output:\n%s", out)
	}
	pat := `\mto\s+public\M`
	rules := FormatPolicyRules([]PolicyRule{{RuleID: "grant-to-public", Action: "warn", Enabled: true, Builtin: true, CommandTag: "GRANT", Pattern: &pat, Reason: "r"}})
	if !strings.Contains(rules, "grant-to-public (built-in)") || !strings.Contains(rules, pat) {
		t.Errorf("rules output:\n%s", rules)
	}
	id := int64(9)
	evs := FormatPolicyEvaluations([]PolicyEvaluation{{ID: 1, RuleID: "drop-column", Action: "block", BlackboxID: &id}})
	if !strings.Contains(evs, "drop-column") || !strings.HasSuffix(strings.TrimSpace(evs), "9") {
		t.Errorf("evaluations output:\n%s", evs)
	}
}
