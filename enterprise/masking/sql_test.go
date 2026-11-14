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
	// Writes wait for the triggers to change, and only those: reads go on.
	for name, stmts := range map[string][]string{"start": rk.Start, "swap": rk.Swap} {
		if stmts[0] != "SET LOCAL lock_timeout = '3s'" || stmts[1] != `LOCK TABLE "public"."customers" IN SHARE ROW EXCLUSIVE MODE` {
			t.Errorf("%s does not hold writes first: %q", name, stmts[:2])
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
	// The swap locks what a masked read locks, in a read's order: the view
	// before the shadow. The other way round, a read arriving between the two
	// deadlocked with it.
	if rk.Swap[2] != strings.Split(swap, ";\n")[2] || !strings.HasPrefix(rk.Swap[2], `CREATE OR REPLACE VIEW bb_mask."customers"`) {
		t.Errorf("the swap does not take the view first, after holding writes:\n%s", swap)
	}
	if !strings.Contains(rk.Swap[2], `JOIN bb_mask."public__customers__next" m ON`) {
		t.Errorf("the view does not read the new shadow:\n%s", rk.Swap[2])
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
	if !strings.HasPrefix(all, "SET LOCAL lock_timeout") || !strings.Contains(all, `LOCK TABLE "public"."customers" IN SHARE ROW EXCLUSIVE MODE`) ||
		!strings.Contains(all, `CREATE OR REPLACE FUNCTION bb_mask."keep__public__customers"()`) ||
		strings.Contains(all, "--next") || strings.Contains(all, "DROP") || !strings.Contains(all, "'default'") {
		t.Errorf("repointing:\n%s", all)
	}
}

// The guard on the paths around the masks (step 4): made in bb, as the engine,
// run after every statement that can open a path, refusing a GRANT to PUBLIC
// and giving back what it took when nothing closes it any more; set up with
// every branch, and never callable by a masked reader.
func TestCloseSQL(t *testing.T) {
	all := strings.Join(closeSQL(), ";\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS bb.mask_closed",
		"FUNCTION bb.mask_close_paths(granting boolean",
		"SECURITY DEFINER SET search_path = pg_catalog",
		"REVOKE EXECUTE ON FUNCTION bb.mask_close_paths(boolean) FROM PUBLIC",
		"CREATE EVENT TRIGGER bb_mask_close ON ddl_command_end",
		"'CREATE VIEW'", "'CREATE MATERIALIZED VIEW'", "'GRANT'", "'ALTER TABLE'",
		"to PUBLIC would give masked accounts",
		"con.contype = 'f' AND con.confkey && mk.cols",
		"ARRAY['INSERT', 'UPDATE']",
		"GRANT %s ON %s TO %I",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the guard lacks %q", want)
		}
	}
	if strings.Contains(all, "CREATE TEMP") {
		t.Error("a temporary table would fire the guard's own event trigger")
	}
	if strings.Count(all, "(") != strings.Count(all, ")") {
		t.Error("unbalanced parentheses: plpgsql reads past the statement's end")
	}
	setup := strings.Join(setupSQL(), ";\n")
	if !strings.Contains(setup, "bb.mask_close_paths_et") {
		t.Error("setup does not make the guard")
	}
}

// A masked branch's steps (step 5): the machinery dropped, the Blackbox
// emptied past its append-only triggers with its numbering kept, each masked
// table rewritten with the statistics, and the WAL from before removed with
// recycling put back; each a statement of its own.
func TestMaskBranchSQL(t *testing.T) {
	for _, want := range []string{"SET bb.allow_destructive = on", "DROP EVENT TRIGGER IF EXISTS bb_mask_close", "DROP SCHEMA IF EXISTS bb_mask CASCADE",
		"DROP TABLE IF EXISTS bb.mask_closed, bb.mask_rules, bb.mask_tables"} {
		if !strings.Contains(dropMachinerySQL, want) {
			t.Errorf("the machinery's drop lacks %q", want)
		}
	}
	if !strings.Contains(freshBlackboxSQL, "session_replication_role = replica") || !strings.Contains(freshBlackboxSQL, "'bb.schema_ledger'") ||
		!strings.Contains(freshBlackboxSQL, "'bb.aadhaar_places'") || !strings.Contains(freshBlackboxSQL, "'bb.aadhaar_runs'") ||
		strings.Contains(freshBlackboxSQL, "RESTART IDENTITY") {
		t.Error("the Blackbox is emptied past its triggers, keeping its numbering")
	}
	rw := rewriteSQL([][2]string{{"public", "people"}, {"crm", "leads"}})
	for _, want := range []string{`VACUUM FULL "public"."people";` + "\n", `VACUUM FULL "crm"."leads";` + "\n", "ANALYZE;\n", "VACUUM FULL pg_statistic;\n", "VACUUM FULL pg_statistic_ext_data;\n", "CHECKPOINT;\n"} {
		if !strings.Contains(rw, want) {
			t.Errorf("the rewrite lacks %q", want)
		}
	}
	if strings.Count(dropWALSQL, "pg_switch_wal()") != 3 || strings.Count(dropWALSQL, "CHECKPOINT;") != 3 ||
		!strings.Contains(dropWALSQL, "ALTER SYSTEM SET wal_recycle = off") || !strings.Contains(dropWALSQL, "ALTER SYSTEM RESET wal_recycle") {
		t.Error("three switches and checkpoints with recycling off, then back")
	}
	if !strings.Contains(beforeWALSQL, "pg_drop_replication_slot") {
		t.Error("the source's slots would keep the old WAL")
	}
}

// A table's name is chosen by whoever made it, may hold '$', and ends up inside
// bodies the engine runs: it must not be able to end their quoting.
func TestATableNameCannotCloseTheMaskBodies(t *testing.T) {
	const hostile = "c$bbfill$d$bbmask$e"
	m, err := maskTable("public", hostile, customers, everyRule, "default")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.Fill, "DO $bbfill1$") || strings.Count(m.Fill, "$bbfill1$") != 2 {
		t.Errorf("fill's quoting can collide with the table's name:\n%s", m.Fill)
	}
	var keep string
	for _, s := range m.Build {
		if strings.Contains(s, "RETURNS trigger") {
			keep = s
		}
	}
	if keep == "" {
		t.Fatal("no trigger function was built")
	}
	if !strings.Contains(keep, "AS $bbmask1$") || strings.Count(keep, "$bbmask1$") != 2 {
		t.Errorf("the trigger function's quoting can collide with the table's name:\n%s", keep)
	}

	// With an ordinary name, what is sent is what always was.
	plain, err := maskTable("public", "customers", customers, everyRule, "default")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain.Fill, "DO $bbfill$\nDECLARE") || !strings.HasSuffix(plain.Fill, "END $bbfill$;") {
		t.Errorf("an ordinary table's fill changed:\n%s", plain.Fill)
	}
}
