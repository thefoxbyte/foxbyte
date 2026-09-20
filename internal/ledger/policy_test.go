// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// lf normalises line endings: a Windows checkout may give text files CRLF.
func lf(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// The policy gate must stay additive and match the approved contract.
func TestSchemaPolicy(t *testing.T) {
	if SchemaPolicy == "" {
		t.Fatal("SchemaPolicy is empty — is policy.sql embedded?")
	}
	SchemaPolicy := lf(SchemaPolicy)
	for _, want := range []string{
		"ERRCODE = 'BBX01'", "ERRCODE = 'BBX02'", // the two SQLSTATEs
		"CREATE EVENT TRIGGER bb_policy_start ON ddl_command_start", // sorts after bb_guard_start
		"bb._may_override()",               // same override check as the guardrail
		"'BLOCKED','policy'",               // blocked attempts become Blackbox entries
		"dblink(conn",                      // …recorded so they survive the rollback
		"ON CONFLICT (rule_id) DO NOTHING", // admins' rule changes survive a reinstall
		"SET session_replication_role = replica;", "SET session_replication_role = DEFAULT;",
		"EXCEPTION WHEN OTHERS THEN\n    RAISE WARNING 'Blackbox policy: evaluation skipped",
		"'v', 1,", "'rule_id'", "'action'", "'command'", "'matched'", "'reason'", "'hint'",
		"'override'", "'evaluation_id'", "'blackbox_id'", "'impact'",
	} {
		if !strings.Contains(SchemaPolicy, want) {
			t.Errorf("policy.sql is missing %q", want)
		}
	}
	// Every shipped rule warns.
	for _, id := range []string{"alter-column-type", "drop-column", "drop-index", "grant-to-public"} {
		re := regexp.MustCompile(`\('` + id + `', '[A-Z ]+',\s*(?:NULL|'[^']*'),\s*'(warn|block)',`)
		m := re.FindStringSubmatch(SchemaPolicy)
		if m == nil || m[1] != "warn" {
			t.Errorf("default rule %s must ship as warn (got %v)", id, m)
		}
	}
	// A client-settable session flag must not be able to switch the gate off.
	if strings.Contains(SchemaPolicy, "current_setting('bb.v2'") {
		t.Error("the policy gate must not honour the session setting bb.v2")
	}
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)alter\s+table\s+(if\s+exists\s+)?bb\.(schema_ledger|policy)\b`),
		regexp.MustCompile(`(?i)drop\s+(table|trigger|function|event\s+trigger)`),
		// Redefining an existing function is forbidden; calling one is fine.
		regexp.MustCompile(`(?i)create\s+(or\s+replace\s+)?function\s+bb\.(_ledger_hash|chain_row|deny_change|guard_ddl_start|log_ddl_end|log_ddl_drop|_ctx|_skip|_may_override|capture_ext|deny_ext_change)\b`),
		regexp.MustCompile(`(?i)event\s+trigger\s+key_(guard_start|log_end|log_drop)\b`),
	}
	for _, re := range forbidden {
		if loc := re.FindStringIndex(SchemaPolicy); loc != nil {
			t.Errorf("policy.sql touches an existing object: %q", SchemaPolicy[loc[0]:loc[1]])
		}
	}
	// Row triggers catch their own errors.
	if strings.Count(SchemaPolicy, "RETURNS trigger") > strings.Count(SchemaPolicy, "EXCEPTION WHEN OTHERS THEN")-2 {
		t.Error("every policy row trigger must catch its own errors")
	}
}

func TestParsePolicyDetail(t *testing.T) {
	d, err := ParsePolicyDetail(`{"v": 1, "hint": "h", "action": "block", "impact": null, "reason": "r", "command": "ALTER TABLE",
		"matched": "x", "rule_id": "drop-column", "override": "db_admin", "blackbox_id": 918, "evaluation_id": 42, "future_key": true}`)
	if err != nil {
		t.Fatal(err)
	}
	if d.RuleID != "drop-column" || d.Action != "block" || *d.BlackboxID != 918 || *d.EvaluationID != 42 || *d.Override != "db_admin" {
		t.Fatalf("parsed %+v", d)
	}
	d, err = ParsePolicyDetail(`{"v":1,"rule_id":"drop-index","action":"warn","command":"DROP INDEX","matched":null,"reason":"r","hint":"h","override":null,"evaluation_id":7,"blackbox_id":null,"impact":null}`)
	if err != nil || d.Matched != nil || d.BlackboxID != nil || d.Override != nil {
		t.Fatalf("warn detail: %+v %v", d, err)
	}
	for _, bad := range []string{`nope`, `{"rule_id":"x","action":"warn"}`, `{"v":1,"rule_id":"Bad Id","action":"warn"}`, `{"v":1,"rule_id":"x","action":"deny"}`} {
		if _, err := ParsePolicyDetail(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// The example in the approved contract must stay valid.
func TestPolicyContractExample(t *testing.T) {
	raw, err := os.ReadFile("../../docs/policy-errors.md")
	if err != nil {
		t.Skip("docs/policy-errors.md not found")
	}
	doc := []byte(lf(string(raw)))
	m := regexp.MustCompile(`(?m)^DETAIL:  (\{.*\})$`).FindSubmatch(doc)
	if m == nil {
		t.Fatal("no DETAIL example in docs/policy-errors.md")
	}
	d, err := ParsePolicyDetail(string(m[1]))
	if err != nil {
		t.Fatalf("the contract's own example doesn't parse: %v", err)
	}
	if d.V != 1 || d.Action != "block" {
		t.Fatalf("example: %+v", d)
	}
	for _, code := range []string{PolicyBlockCode, PolicyWarnCode} {
		if !strings.Contains(string(doc), code) || !strings.Contains(SchemaPolicy, "'"+code+"'") {
			t.Errorf("SQLSTATE %s must appear in both the contract and policy.sql", code)
		}
	}
}

func TestCommandTag(t *testing.T) {
	cases := map[string]string{
		"ALTER TABLE orders DROP COLUMN total":                      "ALTER TABLE",
		"  alter table if exists orders alter column a type bigint": "ALTER TABLE",
		"CREATE UNIQUE INDEX i ON t(a)":                             "CREATE INDEX",
		"create or replace function f() returns int as $$ $$":       "CREATE FUNCTION",
		"CREATE TEMP TABLE x(a int)":                                "CREATE TABLE",
		"CREATE MATERIALIZED VIEW mv AS SELECT 1":                   "CREATE MATERIALIZED VIEW",
		"CREATE OR REPLACE RECURSIVE VIEW v AS SELECT 1":            "CREATE VIEW",
		"DROP INDEX CONCURRENTLY i":                                 "DROP INDEX",
		"drop foreign table ft":                                     "DROP FOREIGN TABLE",
		"ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO r":      "ALTER DEFAULT PRIVILEGES",
		"GRANT SELECT ON t TO PUBLIC":                               "GRANT",
		"revoke all on t from public":                               "REVOKE",
		"-- a comment\n/* another */ DROP TABLE t":                  "DROP TABLE",
		"CREATE CONSTRAINT TRIGGER tr AFTER INSERT ON t":            "CREATE TRIGGER",
		"CREATE TEXT SEARCH DICTIONARY d (template = simple)":       "CREATE TEXT SEARCH DICTIONARY",
		"":                  "",
		"-- only a comment": "",
	}
	for in, want := range cases {
		if got := CommandTag(in); got != want {
			t.Errorf("CommandTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidRuleID(t *testing.T) {
	for _, ok := range []string{"drop-column", "a", "rule-2"} {
		if !ValidRuleID(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-x", "Drop", "a b", "a_b", strings.Repeat("a", 64)} {
		if ValidRuleID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
