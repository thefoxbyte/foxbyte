// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"errors"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

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
