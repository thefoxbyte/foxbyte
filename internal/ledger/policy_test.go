// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"strings"
	"testing"
)

// lf normalises line endings: a Windows checkout may give text files CRLF.
func lf(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

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
