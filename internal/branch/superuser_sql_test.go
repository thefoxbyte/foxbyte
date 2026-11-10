// SPDX-License-Identifier: AGPL-3.0-or-later

package branch

import (
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/ledger"
)

// Values that try to end a dollar-quoted body early. Each is a plausible
// email, table name or app name as far as their own checks go, which is why
// the SQL builders, not the inputs, are what must hold (audit API-1).
var hostileValues = []string{
	"x$$",
	"x$$; SELECT 1; $$",
	"t$do$ BEGIN END $do$",
	"a$id$b",
	"$",
	"$$$",
	`a$$\! true`,
	"plain'quote",
}

// tagCount is how many times the dollar-quote tag appears in sql.
func tagCount(sql, tag string) int { return strings.Count(sql, tag) }

func TestBodyLiteralNeverHoldsADollar(t *testing.T) {
	for _, v := range append(hostileValues, "", "ordinary", "a\x00b") {
		got := bodyLiteral(v)
		if strings.Contains(got, "$") {
			t.Errorf("bodyLiteral(%q) = %s holds a '$'", v, got)
		}
		if strings.Contains(got, "\x00") {
			t.Errorf("bodyLiteral(%q) kept a NUL", v)
		}
	}
	// Without a '$' it is exactly the literal it always was, so every SQL test
	// written before it still describes what is sent.
	for _, v := range []string{"", "orders", "o'brien", "ada@example.com"} {
		if bodyLiteral(v) != quoteLiteral(v) {
			t.Errorf("bodyLiteral(%q) = %s, want %s", v, bodyLiteral(v), quoteLiteral(v))
		}
	}
	if got, want := bodyLiteral("a$b"), "('a' || chr(36) || 'b')"; got != want {
		t.Errorf("bodyLiteral(a$b) = %s, want %s", got, want)
	}
}

// A table name can no longer close the DO body the audit marks run in: the
// body's tag appears exactly twice, opening and closing it, whatever the name.
func TestAuditMarkSQLCannotBeClosedByATableName(t *testing.T) {
	for _, name := range hostileValues {
		rel := tableRef("public", name)
		for what, sql := range map[string]string{
			"markSQL":       markSQL(rel, true),
			"unmarkSQL":     unmarkSQL(rel),
			"markWritesSQL": markWritesSQL(rel),
		} {
			if n := tagCount(sql, "$$"); n != 2 {
				t.Errorf("%s with table %q: $$ appears %d times, want 2:\n%s", what, name, n, sql)
			}
		}
		if rel2 := tableRef(name, "t"); strings.Contains(rel2, "$") {
			t.Errorf("tableRef with schema %q holds a '$': %s", name, rel2)
		}
	}
}

// The role builders put emails and role names inside $do$ bodies.
func TestRoleSQLCannotBeClosedByAName(t *testing.T) {
	for _, v := range hostileValues {
		for what, sql := range map[string]string{
			"userRoleSQL":     userRoleSQL(v, "pw"),
			"agentKeyRoleSQL": agentKeyRoleSQL(v, "pw"),
		} {
			if n := tagCount(sql, "$do$"); n != 2 {
				t.Errorf("%s(%q): $do$ appears %d times, want 2:\n%s", what, v, n, sql)
			}
		}
	}
}

func TestIdentityDataSQLCannotBeClosedByAnAppName(t *testing.T) {
	for _, v := range hostileValues {
		st := identityState{installID: "i", apps: []auth.App{{
			Name: v, Account: "a@example.com", MaxLife: 60, OnInvalid: "none",
			Keys: []auth.AppKey{{Kid: v, PublicKey: "ab"}},
		}}}
		if n := tagCount(identityDataSQL(v, st), "$id$"); n != 2 {
			t.Errorf("app %q: $id$ appears %d times, want 2", v, n)
		}
	}
}

func TestCheckTableName(t *testing.T) {
	for _, ok := range [][2]string{{"public", "orders"}, {"", "orders"}, {"s", "weird $ name"}, {"s", strings.Repeat("t", 63)}} {
		if err := checkTableName(ok[0], ok[1]); err != nil {
			t.Errorf("checkTableName(%q, %q) refused: %v", ok[0], ok[1], err)
		}
	}
	for _, bad := range [][2]string{
		{"public", ""},
		{"public", strings.Repeat("t", 64)},
		{strings.Repeat("s", 64), "t"},
		{"public", "a\x00b"},
		{"public", "a\nb"},
		{"pub\rlic", "t"},
		{"public", "a\x7fb"},
	} {
		if err := checkTableName(bad[0], bad[1]); err == nil {
			t.Errorf("checkTableName(%q, %q) accepted", bad[0], bad[1])
		}
	}
	// Every entry point refuses before any SQL is built or run.
	for what, err := range map[string]error{
		"MarkAudited":       MarkAudited("b", "public", "a\x00", true, "ada@x.com", "t"),
		"UnmarkAudited":     UnmarkAudited("b", "public", "", "ada@x.com", "t"),
		"MarkAuditedWrites": MarkAuditedWrites("b", "public", "a\nb", "ada@x.com", "t"),
		"TrackTable":        TrackTable("b", "public", "", DefaultTrackOptions, "ada@x.com", "t"),
		"UntrackTable":      UntrackTable("b", "public", "a\x00", "ada@x.com", "t"),
	} {
		if err == nil {
			t.Errorf("%s accepted a bad table name", what)
		}
	}
}

// An import source with no password of its own must never fall back to the
// container's (audit GW-1).
func TestNoAmbientPassword(t *testing.T) {
	const none = "password=&passfile=%2Fdev%2Fnull"
	for in, want := range map[string]string{
		"postgres://u@h/db":                          "postgres://u@h/db?" + none,
		"postgresql://u@h:5432/db?sslmode=require":   "postgresql://u@h:5432/db?sslmode=require&" + none,
		"postgres://h":                               "postgres://h?" + none,
		"postgres://u@h/db?hostaddr=203.0.113.8":     "postgres://u@h/db?hostaddr=203.0.113.8&" + none,
		"postgres://u:pw@h/db":                       "postgres://u:pw@h/db?passfile=%2Fdev%2Fnull",
		"postgres://u:@h/db":                         "postgres://u:@h/db?passfile=%2Fdev%2Fnull",
		"postgres://u@h/db?password=x":               "postgres://u@h/db?password=x&passfile=%2Fdev%2Fnull",
		"postgres://u@h/db?password=x&passfile=/p":   "postgres://u@h/db?password=x&passfile=/p",
		"postgres://u@h/db?pass%77ord=x&passfile=/p": "postgres://u@h/db?pass%77ord=x&passfile=/p",
		"mysql://u@h/db":                             "mysql://u@h/db",
		"mongodb://u@h/db":                           "mongodb://u@h/db",
	} {
		if got := noAmbientPassword(in); got != want {
			t.Errorf("noAmbientPassword(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	env := strings.Join(noAmbientPasswordEnv, " ")
	for _, must := range []string{"PGPASSWORD=", "PGPASSFILE=/dev/null"} {
		if !strings.Contains(env, must) {
			t.Errorf("noAmbientPasswordEnv lacks %s", must)
		}
	}
}

// dblink is taken away from clients wherever it is (re)installed.
func TestDblinkIsNotGrantedToClients(t *testing.T) {
	for what, sql := range map[string]string{"ensureDblinkSQL": ensureDblinkSQL, "ledger.sql": ledger.Schema} {
		if !strings.Contains(sql, "REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC") {
			t.Errorf("%s does not revoke dblink from PUBLIC", what)
		}
		if !strings.Contains(sql, "e.extname = 'dblink'") {
			t.Errorf("%s does not find dblink's functions by extension", what)
		}
	}
}

// The masked-reader role builders put emails and role names in $do$ bodies too.
func TestMaskedRoleSQLCannotBeClosedByAName(t *testing.T) {
	for _, v := range hostileValues {
		for what, sql := range map[string]string{
			"maskedRoleSQL":         maskedRoleSQL(v, "pw"),
			"maskedAgentKeyRoleSQL": maskedAgentKeyRoleSQL(v, "pw"),
		} {
			if n := tagCount(sql, "$do$"); n != 2 {
				t.Errorf("%s(%q): $do$ appears %d times, want 2:\n%s", what, v, n, sql)
			}
		}
	}
}

func TestDollarTag(t *testing.T) {
	for _, c := range [][3]string{
		{"b", "SELECT 1", "$b$"},
		{"b", "x$b$y", "$b1$"},
		{"b", "x$b$y$b1$z", "$b2$"},
	} {
		if got := DollarTag(c[0], c[1]); got != c[2] {
			t.Errorf("DollarTag(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}
