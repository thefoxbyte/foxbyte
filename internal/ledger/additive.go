// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import "regexp"

// ForbiddenInAdditiveSchema matches anything a schema layered on top of
// ledger.sql must never touch: the base ledger's tables, its hash-chain
// functions and its event triggers.
//
// Every chain already written keeps verifying only because nothing added later
// redefines what wrote it. The rule is checked by the tests of each additive
// schema — ledger_ext.sql here, and checkpoints.sql, policy.sql and impact.sql
// in enterprise/schema, which is in a different package and a different licence
// and so cannot share a test helper. One list, so the two cannot drift into
// enforcing different rules about the same base.
func ForbiddenInAdditiveSchema() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`(?i)alter\s+table\s+(if\s+exists\s+)?bb\.schema_ledger`),
		regexp.MustCompile(`(?i)alter\s+table\s+(if\s+exists\s+)?bb\.policy`),
		regexp.MustCompile(`(?i)drop\s+(table|trigger|function|event\s+trigger)`),
		regexp.MustCompile(`(?i)function\s+bb\.(_ledger_hash|chain_row|deny_change|guard_ddl_start|log_ddl_end|log_ddl_drop|_ctx|_skip|_may_override)\b`),
		regexp.MustCompile(`(?i)trigger\s+(bb_chain|bb_append_only|bb_no_truncate)\b`),
		regexp.MustCompile(`(?i)event\s+trigger\s+key_(guard_start|log_end|log_drop)\b`),
	}
}
