// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	"regexp"
	"testing"
)

func TestSchemaProvenance(t *testing.T) {
	s := lf(SchemaProvenance)
	if s == "" {
		t.Fatal("SchemaProvenance is empty — is provenance.sql embedded?")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS bb.agent_sessions",
		"BEFORE UPDATE OR DELETE ON bb.agent_sessions", // append-only
		"BEFORE TRUNCATE ON bb.agent_sessions",
		"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bb.agent_sessions FROM PUBLIC;",
		"GRANT SELECT ON bb.agent_sessions TO db_client;",
		"SET session_replication_role = replica;", "SET session_replication_role = DEFAULT;",
	} {
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(s) {
			t.Errorf("provenance.sql is missing %q", want)
		}
	}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)alter\s+table\s+(if\s+exists\s+)?bb\.(schema_ledger|ledger_ext|policy)\b`),
		regexp.MustCompile(`(?i)drop\s+(table|trigger|function|event\s+trigger|index)`),
		regexp.MustCompile(`(?i)create\s+(or\s+replace\s+)?function\s+bb\.(capture_ext|deny_ext_change|_ctx|_ledger_hash|chain_row)\b`),
		regexp.MustCompile(`(?i)on\s+bb\.schema_ledger\b`),
	} {
		if loc := re.FindStringIndex(s); loc != nil {
			t.Errorf("provenance.sql touches an existing object: %q", s[loc[0]:loc[1]])
		}
	}
}
