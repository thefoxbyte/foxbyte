// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/thefoxbyte/foxbyte/internal/edition"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Blackbox policy gate: rules checked on every DDL statement before it runs,
// by the event trigger installed from internal/ledger/policy.sql. The gate runs
// entirely inside Postgres; these helpers read and change the rules on a branch.
// What clients receive is specified in docs/policy-errors.md.

var (
	ErrRuleNotFound = errors.New("policy rule not found")
	ErrRuleExists   = errors.New("policy rule already exists")
	ErrBuiltinRule  = errors.New("built-in policy rules can't be removed")
)

// PolicyRule is one rule of the policy gate.
type PolicyRule struct {
	RuleID     string  `json:"rule_id"`
	CommandTag string  `json:"command_tag"`
	Pattern    *string `json:"pattern"`
	Action     string  `json:"action"` // warn | block
	Reason     string  `json:"reason"`
	Hint       *string `json:"hint"`
	Enabled    bool    `json:"enabled"`
	Builtin    bool    `json:"builtin"`
	UpdatedAt  string  `json:"updated_at"`
	UpdatedBy  *string `json:"updated_by"`
}

// PolicyEvaluation is one recorded warning, block or override.
type PolicyEvaluation struct {
	ID         int64   `json:"id"`
	At         string  `json:"at"`
	XID        *int64  `json:"xid"`
	RuleID     string  `json:"rule_id"`
	Action     string  `json:"action"` // warn | block | allowed
	CommandTag *string `json:"command_tag"`
	Actor      *string `json:"actor"`
	BlackboxID *int64  `json:"blackbox_id"`
}

// friendlyPolicyErr turns database errors into messages a person can act on.
// sqlTextOrNull renders an optional string as a SQL literal or NULL. Shared:
// the provenance record uses it too, which is why it stayed when authoring
// moved out.
func sqlTextOrNull(p *string) string {
	if p == nil || *p == "" {
		return "NULL"
	}
	return quoteLiteral(*p)
}

func friendlyPolicyErr(name string, err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "policy_rules_pattern_check"):
		return fmt.Errorf("%w: invalid pattern — it must be a valid PostgreSQL regular expression", ErrInvalidRequest)
	case strings.Contains(s, "bb.policy_rules") && strings.Contains(s, "does not exist"),
		strings.Contains(s, "bb.ledger_policy_evaluations") && strings.Contains(s, "does not exist"),
		strings.Contains(s, "function bb.policy_check") && strings.Contains(s, "does not exist"):
		return fmt.Errorf("the Blackbox policy gate isn't installed on %q — run: fox blackbox upgrade %s", name, name)
	}
	return err
}

func policyLines(name, sql string) ([]string, error) {
	lines, err := ledgerLines(name, sql)
	if err != nil {
		return nil, friendlyPolicyErr(name, err)
	}
	return lines, nil
}

// PolicyRules lists a branch's policy rules.
func PolicyRules(name string) ([]PolicyRule, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return nil, err
	}
	lines, err := policyLines(name, `SELECT row_to_json(r) FROM (
  SELECT rule_id, command_tag, pattern, action, reason, hint, enabled, builtin,
         to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at, updated_by
  FROM bb.policy_rules ORDER BY rule_id) r`)
	if err != nil {
		return nil, err
	}
	rules := make([]PolicyRule, 0, len(lines))
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") {
			continue
		}
		var r PolicyRule
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			return nil, fmt.Errorf("reading policy rules: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// PolicyCheck previews the rules a statement would trigger on a branch without
// running it. It returns the command tag it assumed and the matches, blocks first.
func PolicyCheck(name, statement string) (string, []ledger.PolicyDetail, error) {
	return PolicyCheckTag(name, ledger.CommandTag(statement), statement)
}

// PolicyCheckTag is PolicyCheck for a caller that already knows the command tag —
// a promotion, where the tag is the one the Blackbox recorded when the statement
// ran. Deriving it again from the text would read a script's first command
// instead: a statement recorded as `SET …; DROP TABLE x` is a DROP, and asking the
// gate about a SET would let it through.
func PolicyCheckTag(name, tag, statement string) (string, []ledger.PolicyDetail, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return "", nil, err
	}
	if tag == "" {
		tag = ledger.CommandTag(statement)
	}
	if tag == "" {
		return "", nil, fmt.Errorf("%w: sql is required", ErrInvalidRequest)
	}
	lines, err := policyLines(name, fmt.Sprintf("SELECT bb.policy_check(%s, %s)::text", quoteLiteral(tag), quoteLiteral(statement)))
	if err != nil {
		return "", nil, err
	}
	matches := make([]ledger.PolicyDetail, 0, len(lines))
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") {
			continue
		}
		d, err := ledger.ParsePolicyDetail(l)
		if err != nil {
			return "", nil, err
		}
		matches = append(matches, d)
	}
	return tag, matches, nil
}

// PolicyEvaluations returns a branch's newest evaluations (default 20, at most 1000).
func PolicyEvaluations(name string, limit int) ([]PolicyEvaluation, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 1000 {
		limit = 1000
	}
	lines, err := policyLines(name, fmt.Sprintf(`SELECT row_to_json(e) FROM (
  SELECT id, to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS at, xid, rule_id, action,
         command_tag, actor, blackbox_id
  FROM bb.ledger_policy_evaluations ORDER BY id DESC LIMIT %d) e`, limit))
	if err != nil {
		return nil, err
	}
	evs := make([]PolicyEvaluation, 0, len(lines))
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") {
			continue
		}
		var e PolicyEvaluation
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			return nil, fmt.Errorf("reading policy evaluations: %w", err)
		}
		evs = append(evs, e)
	}
	return evs, nil
}

// IsAdmin reports whether the login role for email is a superuser or a member
// of db_admin on a branch.
func IsAdmin(name, email string) (bool, error) {
	name, err := ledgerBranchName(name)
	if err != nil {
		return false, err
	}
	if email == "" {
		return false, nil
	}
	lines, err := ledgerLines(name, fmt.Sprintf(`SELECT CASE WHEN to_regrole('db_admin') IS NULL THEN false ELSE
  coalesce((SELECT rolsuper OR pg_has_role(oid, 'db_admin', 'MEMBER') FROM pg_roles WHERE rolname = %s), false) END`,
		quoteLiteral(email)))
	if err != nil {
		return false, err
	}
	return len(lines) > 0 && lines[0] == "t", nil
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// FormatPolicyRules renders rules as a text table.
func FormatPolicyRules(rules []PolicyRule) string {
	if len(rules) == 0 {
		return "No policy rules."
	}
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tACTION\tENABLED\tCOMMAND\tPATTERN\tREASON")
	for _, r := range rules {
		id := r.RuleID
		if r.Builtin {
			id += " (built-in)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\t%s\n", id, r.Action, r.Enabled, r.CommandTag, str(r.Pattern), r.Reason)
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// FormatPolicyCheck renders a policy preview.
func FormatPolicyCheck(tag string, matches []ledger.PolicyDetail) string {
	var b strings.Builder
	fmt.Fprintf(&b, "command: %s\n", tag)
	if len(matches) == 0 {
		b.WriteString("no policy rule matches")
		return b.String()
	}
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, m := range matches {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", strings.ToUpper(m.Action), m.RuleID, m.Reason)
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// FormatPolicyEvaluations renders evaluations as a text table.
func FormatPolicyEvaluations(evs []PolicyEvaluation) string {
	if len(evs) == 0 {
		return "No policy evaluations."
	}
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTIME (UTC)\tRULE\tACTION\tCOMMAND\tACTOR\tBLACKBOX ENTRY")
	for _, e := range evs {
		entry := ""
		if e.BlackboxID != nil {
			entry = fmt.Sprint(*e.BlackboxID)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.At, e.RuleID, e.Action, str(e.CommandTag), str(e.Actor), entry)
	}
	_ = tw.Flush()
	return strings.TrimRight(b.String(), "\n")
}

// The authoring half, supplied by enterprise/policy in an Enterprise build and
// nil in a Standard one.
var (
	addPolicy    func(name string, r PolicyRule, actor string) error
	updatePolicy func(name, ruleID string, action *string, enabled *bool, actor string) error
	removePolicy func(name, ruleID, actor string) error
)

// SetPolicyAuthoring installs them. Called from enterprise/policy's init, and
// from nowhere else.
func SetPolicyAuthoring(
	add func(string, PolicyRule, string) error,
	update func(string, string, *string, *bool, string) error,
	remove func(string, string, string) error,
) {
	addPolicy, updatePolicy, removePolicy = add, update, remove
}

// AddPolicyRule writes a new rule to a branch's policy gate.
func AddPolicyRule(name string, r PolicyRule, actor string) error {
	// Authoring is the paid half. PolicyRules, PolicyCheck and
	// PolicyEvaluations above stay free.
	if err := requireFeature(edition.Policy); err != nil {
		return err
	}
	if addPolicy == nil {
		return ErrPolicyNotLicensed
	}
	return addPolicy(name, r, actor)
}

// UpdatePolicyRule changes a rule's action or whether it is enabled. `policy
// block`, `warn`, `enable` and `disable` all land here.
func UpdatePolicyRule(name, ruleID string, action *string, enabled *bool, actor string) error {
	if err := requireFeature(edition.Policy); err != nil {
		return err
	}
	if updatePolicy == nil {
		return ErrPolicyNotLicensed
	}
	return updatePolicy(name, ruleID, action, enabled, actor)
}

// RemovePolicyRule deletes a rule.
func RemovePolicyRule(name, ruleID, actor string) error {
	if err := requireFeature(edition.Policy); err != nil {
		return err
	}
	if removePolicy == nil {
		return ErrPolicyNotLicensed
	}
	return removePolicy(name, ruleID, actor)
}
