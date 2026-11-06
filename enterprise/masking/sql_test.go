//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package masking

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

var customers = []branch.MaskColumn{
	{Name: "id", Type: "bigint", Key: true},
	{Name: "name", Type: "text"},
	{Name: "email", Type: "text"},
	{Name: "phone", Type: "text"},
	{Name: "aadhaar", Type: "text"},
	{Name: "notes", Type: "text"},
	{Name: "prefs", Type: "jsonb"},
	{Name: "city", Type: "text"},
}

func rule(col, path, r, cat string) branch.MaskRule {
	return branch.MaskRule{Schema: "public", Table: "customers", Column: col, Path: path, Rule: r, Category: cat}
}

var everyRule = []branch.MaskRule{
	rule("name", "", "fake", "name"),
	rule("email", "", "hash", "email"),
	rule("phone", "", "partial", "mobile"),
	rule("aadhaar", "", "partial", "aadhaar"),
	rule("notes", "", "empty", "other"),
	rule("prefs", "$.contact.mobile", "partial", "mobile"),
}

// Every rule: a shadow for what needs the key, the view computing the rest,
// the hash never in the view, a trigger a statement, and the rights taken
// before anything is made.
func TestMaskTableEveryRule(t *testing.T) {
	m, err := maskTable("public", "customers", customers, everyRule, "default")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.Drop[0], `REVOKE ALL ON "public"."customers" FROM db_masked`) {
		t.Errorf("the masked reader's rights should go first: %s", m.Drop[0])
	}
	build := strings.Join(m.Build, ";\n")
	for _, want := range []string{
		`CREATE TABLE bb_mask."public__customers"`,
		"REFERENCING OLD TABLE AS o NEW TABLE AS n FOR EACH STATEMENT",
		`AFTER TRUNCATE ON "public"."customers" FOR EACH STATEMENT`,
		`bb_f1.bbid_mask_hmac('default', (n."email")::text)`,
		`bb_mask.fake('name', bb_f1.bbid_mask_hmac('default', (n."name")::text))`,
		`jsonb_set(n."prefs", '{contact,mobile}'`,
		"SECURITY DEFINER SET search_path = pg_catalog",
		`OWNER TO bb_masker`,
	} {
		if !strings.Contains(build, want) {
			t.Errorf("build is missing %q:\n%s", want, build)
		}
	}
	view := m.View[0]
	for _, want := range []string{`m."name" AS "name"`, `m."email" AS "email"`, `right((n."phone")::text, 4)) AS "phone"`,
		`NULL::text AS "notes"`, `m."prefs" AS "prefs"`, `n."city"`, `JOIN bb_mask."public__customers" m ON m."id" = n."id"`} {
		if !strings.Contains(view, want) {
			t.Errorf("the view is missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "bbid_mask_hmac") || strings.Contains(view, ".fake(") {
		t.Errorf("the view computes a hash, which a masked reader would need to call:\n%s", view)
	}
	if !strings.Contains(m.Fill, "LIMIT 10000") || !strings.Contains(m.Fill, "COMMIT") || !strings.Contains(m.Fill, "DO NOTHING") {
		t.Errorf("the fill should go in committed batches:\n%s", m.Fill)
	}
	if got := m.View[len(m.View)-1]; got != `GRANT SELECT ON bb_mask."customers" TO db_masked` {
		t.Errorf("the last grant: %s", got)
	}
	if f := os.Getenv("F5_DUMP"); f != "" {
		_ = os.WriteFile(f, []byte(strings.Join(setupSQL(), ";\n")+";\n"+strings.Join(append(m.Drop, m.Build...), ";\n")+";\n"+m.Fill+"\n"+strings.Join(m.View, ";\n")+";\n"), 0o644)
	}
}

// Only partial and empty need no key: no shadow, no trigger, nothing more on
// a write.
func TestMaskTableWithoutAShadow(t *testing.T) {
	m, err := maskTable("public", "customers", customers, []branch.MaskRule{rule("aadhaar", "", "partial", "aadhaar")}, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Build) != 0 || m.Fill != "" {
		t.Fatalf("a shadow for partial alone: %v %q", m.Build, m.Fill)
	}
	if !strings.Contains(m.View[0], `FROM "public"."customers" n`) || strings.Contains(m.View[0], "JOIN") {
		t.Fatalf("the view: %s", m.View[0])
	}
}

// No rules: the masks go, and the masked reader's rights come back.
func TestMaskTableNoRules(t *testing.T) {
	m, err := maskTable("public", "customers", customers, nil, "default")
	if err != nil {
		t.Fatal(err)
	}
	if last := m.Drop[len(m.Drop)-1]; last != `GRANT SELECT, INSERT, UPDATE, DELETE ON "public"."customers" TO db_masked` || len(m.View) != 0 {
		t.Fatalf("no rules: %v %v", m.Drop, m.View)
	}
}

// What cannot be masked is refused, saying why.
func TestMaskTableRefuses(t *testing.T) {
	noKey := []branch.MaskColumn{{Name: "email", Type: "text"}}
	two := []branch.MaskColumn{{Name: "a", Type: "int", Key: true}, {Name: "b", Type: "int", Key: true}, {Name: "email", Type: "text"}}
	for name, c := range map[string]struct {
		cols  []branch.MaskColumn
		rules []branch.MaskRule
		want  string
	}{
		"no key":      {noKey, []branch.MaskRule{rule("email", "", "hash", "email")}, "no primary key"},
		"two keys":    {two, []branch.MaskRule{rule("email", "", "hash", "email")}, "several columns"},
		"the key":     {customers, []branch.MaskRule{rule("id", "", "hash", "other")}, "the table's key"},
		"no column":   {customers, []branch.MaskRule{rule("ssn", "", "hash", "other")}, "no column"},
		"not jsonb":   {customers, []branch.MaskRule{rule("city", "$.a", "partial", "other")}, "jsonb column"},
		"array path":  {customers, []branch.MaskRule{rule("prefs", "$.orders[*].email", "hash", "email")}, "array's elements"},
		"both levels": {customers, []branch.MaskRule{rule("prefs", "", "empty", "other"), rule("prefs", "$.a", "partial", "other")}, "take one off"},
	} {
		_, err := maskTable("public", "customers", c.cols, c.rules, "default")
		if err == nil || !errors.Is(err, branch.ErrInvalidRequest) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A table outside public: its view is named for its schema too.
func TestMaskNames(t *testing.T) {
	n := namesFor("crm", "leads")
	if n.view != `bb_mask."crm__leads"` || n.shadow != `bb_mask."crm__leads"` {
		t.Fatalf("%+v", n)
	}
	if namesFor("public", "orders").view != `bb_mask."orders"` {
		t.Fatal(namesFor("public", "orders"))
	}
}

// A table's masks under a named domain hash under that domain's key.
func TestMaskTableUnderADomain(t *testing.T) {
	m, err := maskTable("public", "customers", customers, everyRule, "tenant_a")
	if err != nil {
		t.Fatal(err)
	}
	build := strings.Join(m.Build, ";\n")
	if !strings.Contains(build, `bbid_mask_hmac('tenant_a', (n."email")::text)`) || strings.Contains(build, "'default'") {
		t.Errorf("not under tenant_a's key:\n%s", build)
	}
}

// Rekeying: a second shadow kept under the new key beside the old, filled
// without replacing what the triggers wrote, then swapped in with the view
// replaced in place (its grants kept) and the triggers keeping only it.
func TestRekeyTable(t *testing.T) {
	rk, keyed, err := rekeyTable("public", "customers", customers, everyRule, "default", "default--next")
	if err != nil || !keyed {
		t.Fatalf("keyed %v: %v", keyed, err)
	}
	start := strings.Join(rk.Start, ";\n")
	for _, want := range []string{
		`DROP TABLE IF EXISTS bb_mask."public__customers__next"`,
		`CREATE TABLE bb_mask."public__customers__next"`,
		`INSERT INTO bb_mask."public__customers" ("id", "name", "email"`,
		`bbid_mask_hmac('default', (n."email")::text)`,
		`INSERT INTO bb_mask."public__customers__next" ("id", "name", "email"`,
		`bbid_mask_hmac('default--next', (n."email")::text)`,
		`TRUNCATE bb_mask."public__customers", bb_mask."public__customers__next"`,
		`CREATE OR REPLACE FUNCTION bb_mask."keep__public__customers"()`,
	} {
		if !strings.Contains(start, want) {
			t.Errorf("start is missing %q:\n%s", want, start)
		}
	}
	if strings.Contains(start, "DROP VIEW") || strings.Contains(start, "REVOKE ALL ON \"public\"") {
		t.Errorf("a masked reader loses the table while it is rekeyed:\n%s", start)
	}
	if !strings.Contains(rk.Fill, `bb_mask."public__customers__next"`) || !strings.Contains(rk.Fill, "DO NOTHING") ||
		!strings.Contains(rk.Fill, "'default--next'") || !strings.Contains(rk.Fill, "COMMIT") {
		t.Errorf("the fill:\n%s", rk.Fill)
	}
	swap := strings.Join(rk.Swap, ";\n")
	for _, want := range []string{
		`ALTER TABLE bb_mask."public__customers" RENAME TO "public__customers__old"`,
		`ALTER TABLE bb_mask."public__customers__next" RENAME TO "public__customers"`,
		`CREATE OR REPLACE VIEW bb_mask."customers"`,
		`DROP TABLE bb_mask."public__customers__old"`,
	} {
		if !strings.Contains(swap, want) {
			t.Errorf("the swap is missing %q:\n%s", want, swap)
		}
	}
	if strings.Contains(swap, "'default'") || strings.Contains(swap, "__next\" (") || strings.Contains(swap, "GRANT") {
		t.Errorf("after the swap the triggers keep only the new shadow, under the new key, and grants are kept:\n%s", swap)
	}
	if i, j := strings.Index(swap, "RENAME TO \"public__customers\""), strings.Index(swap, "CREATE OR REPLACE VIEW"); i < 0 || j < i {
		t.Errorf("the view is replaced before the new shadow has the shadow's name:\n%s", swap)
	}
}

// Only partial and empty: no key, so nothing to rekey.
func TestRekeyTableNothingKeyed(t *testing.T) {
	_, keyed, err := rekeyTable("public", "customers", customers, []branch.MaskRule{rule("aadhaar", "", "partial", "aadhaar")}, "default", "x")
	if err != nil || keyed {
		t.Fatalf("keyed %v: %v", keyed, err)
	}
}

// After the new key is in the domain's file, the triggers write under the
// domain's name again, and nothing else changes.
func TestRepointTable(t *testing.T) {
	stmts, err := repointTable("public", "customers", customers, everyRule, "default")
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(stmts, ";\n")
	if !strings.HasPrefix(all, `CREATE OR REPLACE FUNCTION bb_mask."keep__public__customers"()`) ||
		strings.Contains(all, "--next") || strings.Contains(all, "DROP") || !strings.Contains(all, "'default'") {
		t.Errorf("repointing:\n%s", all)
	}
}
