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
	m, err := maskTable("public", "customers", customers, everyRule)
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
	m, err := maskTable("public", "customers", customers, []branch.MaskRule{rule("aadhaar", "", "partial", "aadhaar")})
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
	m, err := maskTable("public", "customers", customers, nil)
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
		_, err := maskTable("public", "customers", c.cols, c.rules)
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
