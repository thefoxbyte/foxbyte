// SPDX-License-Identifier: AGPL-3.0-or-later

package ledger

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// SchemaPolicy is the idempotent SQL for the Blackbox policy gate. Apply it after
// Schema and SchemaV2. What clients receive is specified in docs/policy-errors.md.
//
//go:embed policy.sql
var SchemaPolicy string

// SQLSTATEs of the policy gate (docs/policy-errors.md).
const (
	PolicyBlockCode = "BBX01" // ERROR: the statement was refused
	PolicyWarnCode  = "BBX02" // NOTICE: the statement ran
)

// PolicyDetail is the JSON object in the DETAIL of a policy error or warning
// (contract v1). Unknown keys are ignored, as the contract asks of clients.
type PolicyDetail struct {
	V            int             `json:"v"`
	RuleID       string          `json:"rule_id"`
	Action       string          `json:"action"`
	Command      string          `json:"command"`
	Matched      *string         `json:"matched"`
	Reason       string          `json:"reason"`
	Hint         string          `json:"hint"`
	Override     *string         `json:"override"`
	EvaluationID *int64          `json:"evaluation_id"`
	BlackboxID   *int64          `json:"blackbox_id"`
	Impact       json.RawMessage `json:"impact"`
}

var ruleIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidRuleID reports whether id is a valid policy rule id.
func ValidRuleID(id string) bool { return ruleIDRe.MatchString(id) }

// ParsePolicyDetail decodes and checks a DETAIL string from the policy gate.
func ParsePolicyDetail(s string) (PolicyDetail, error) {
	var d PolicyDetail
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		return PolicyDetail{}, fmt.Errorf("policy detail is not JSON: %w", err)
	}
	switch {
	case d.V < 1:
		return PolicyDetail{}, fmt.Errorf("policy detail has no contract version")
	case !ValidRuleID(d.RuleID):
		return PolicyDetail{}, fmt.Errorf("policy detail has an invalid rule_id %q", d.RuleID)
	case d.Action != "warn" && d.Action != "block":
		return PolicyDetail{}, fmt.Errorf("policy detail has an unknown action %q", d.Action)
	}
	return d, nil
}

// Object types whose name is several words in a command tag.
var multiWordObjects = [][]string{
	{"FOREIGN", "DATA", "WRAPPER"},
	{"TEXT", "SEARCH", "CONFIGURATION"}, {"TEXT", "SEARCH", "DICTIONARY"},
	{"TEXT", "SEARCH", "PARSER"}, {"TEXT", "SEARCH", "TEMPLATE"},
	{"MATERIALIZED", "VIEW"}, {"FOREIGN", "TABLE"}, {"EVENT", "TRIGGER"},
	{"ACCESS", "METHOD"}, {"USER", "MAPPING"}, {"OPERATOR", "CLASS"},
	{"OPERATOR", "FAMILY"}, {"DEFAULT", "PRIVILEGES"}, {"LARGE", "OBJECT"},
}

// Words between CREATE and the object type that aren't part of the tag.
var createModifiers = map[string]bool{
	"OR": true, "REPLACE": true, "UNIQUE": true, "TEMP": true, "TEMPORARY": true,
	"UNLOGGED": true, "GLOBAL": true, "LOCAL": true, "CONSTRAINT": true,
	"RECURSIVE": true, "TRUSTED": true, "PROCEDURAL": true,
}

// CommandTag guesses the command tag PostgreSQL reports for a statement (for
// example "CREATE INDEX" for CREATE UNIQUE INDEX), so rules can be previewed
// without running the statement. The gate itself uses the real tag.
func CommandTag(sql string) string {
	words := leadingWords(stripLeadingComments(sql), 6)
	if len(words) == 0 {
		return ""
	}
	verb := words[0]
	if verb != "CREATE" && verb != "ALTER" && verb != "DROP" {
		return verb
	}
	rest := words[1:]
	if verb == "CREATE" {
		for len(rest) > 0 && createModifiers[rest[0]] {
			rest = rest[1:]
		}
	}
	for _, obj := range multiWordObjects {
		if len(rest) >= len(obj) && equalWords(rest[:len(obj)], obj) {
			return verb + " " + strings.Join(obj, " ")
		}
	}
	if len(rest) == 0 {
		return verb
	}
	return verb + " " + rest[0]
}

func equalWords(a, b []string) bool {
	for i := range b {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stripLeadingComments(s string) string {
	for {
		s = strings.TrimLeftFunc(s, unicode.IsSpace)
		switch {
		case strings.HasPrefix(s, "--"):
			i := strings.IndexByte(s, '\n')
			if i < 0 {
				return ""
			}
			s = s[i+1:]
		case strings.HasPrefix(s, "/*"):
			i := strings.Index(s, "*/")
			if i < 0 {
				return ""
			}
			s = s[i+2:]
		default:
			return s
		}
	}
}

// leadingWords returns up to n leading words (runs of letters), upper-cased.
func leadingWords(s string, n int) []string {
	var words []string
	var cur strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) {
			cur.WriteRune(unicode.ToUpper(r))
			continue
		}
		if cur.Len() > 0 {
			words = append(words, cur.String())
			cur.Reset()
			if len(words) == n {
				return words
			}
		}
		if r == ';' {
			break
		}
	}
	if cur.Len() > 0 && len(words) < n {
		words = append(words, cur.String())
	}
	return words
}
