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

// The record of applied change requests is what refuses a second apply of the
// same request, so a client must be able to add to it and never take from it.
func TestAppliedRequestsIsAppendOnlyForClients(t *testing.T) {
	s := lf(SchemaProvenance)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS bb.applied_requests",
		// The key: the id and the store's name for the request together, a
		// table made before it migrated (drop the old key, add the new one).
		"request_id  bigint NOT NULL",
		"ADD COLUMN IF NOT EXISTS request_uid text",
		"DROP CONSTRAINT applied_requests_pkey",
		"UNIQUE NULLS NOT DISTINCT (request_id, request_uid)",
		"BEFORE UPDATE OR DELETE ON bb.applied_requests",
		"BEFORE TRUNCATE ON bb.applied_requests",
		"REVOKE ALL ON bb.applied_requests FROM PUBLIC;",
		"REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON bb.applied_requests FROM db_client;",
		"GRANT SELECT, INSERT ON bb.applied_requests TO db_client;",
	} {
		if !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(s) {
			t.Errorf("provenance.sql is missing %q", want)
		}
	}
	if regexp.MustCompile(`(?i)grant\s[^;]*\b(update|delete|truncate|all)\b[^;]*\bon\s+bb\.applied_requests`).MatchString(s) {
		t.Error("db_client is granted a way to change or remove an applied-request record")
	}
}
