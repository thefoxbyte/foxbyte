//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package masking

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// The SQL that makes a table's masks (docs/FOX_F5_Masking_Design.md, sections
// 6 and 7, as the prototype proved them in section 17), made from its rules and
// its columns by pure functions, so the tests can read it.

func ident(s string) string { return branch.QuoteIdent(s) }
func lit(s string) string   { return branch.QuoteLiteral(s) }

// names are a table's masking objects, all in bb_mask. The view has the
// table's own name for a table in public, so a masked reader's unqualified
// name reaches it; a table in another schema's view is <schema>__<table>.
type names struct {
	base, shadow, view, fn string
	next                   string // the shadow a rotation fills, until it is swapped in
	shadowName             string // the shadow's name in bb_mask, unquoted
}

func namesFor(schema, table string) names {
	view := table
	if schema != "public" {
		view = schema + "__" + table
	}
	return names{
		base:       ident(schema) + "." + ident(table),
		shadow:     branch.MaskSchema + "." + ident(schema+"__"+table),
		view:       branch.MaskSchema + "." + ident(view),
		fn:         branch.MaskSchema + "." + ident("keep__"+schema+"__"+table),
		next:       branch.MaskSchema + "." + ident(schema+"__"+table+"__next"),
		shadowName: schema + "__" + table,
	}
}

// A JSON path the masks follow: $.a.b, keys only. An array's elements ($.a[*])
// are not followed yet, and say so.
var pathRE = regexp.MustCompile(`^\$(\.[A-Za-z_][A-Za-z0-9_]*)+$`)

func pathKeys(p string) ([]string, error) {
	if !pathRE.MatchString(p) {
		return nil, fmt.Errorf("%w: the masks follow object keys ($.contact.mobile), not %q: an array's elements are not masked yet", branch.ErrInvalidRequest, p)
	}
	return strings.Split(strings.TrimPrefix(p, "$."), "."), nil
}

// hash is the keyed hash of an expression as text, under a key (a domain's,
// or its next one's during a rotation).
func hash(key, expr string) string {
	return fmt.Sprintf("bb_f1.bbid_mask_hmac(%s, (%s)::text)", lit(key), expr)
}

// partial keeps the last four characters, every other one an X, so the mask
// is as long as the value.
func partial(expr string) string {
	return fmt.Sprintf("(repeat('X', greatest(length((%[1]s)::text) - 4, 0)) || right((%[1]s)::text, 4))", expr)
}

// scalar is a rule applied to a text value.
func scalar(key, rule, category, expr string) string {
	switch rule {
	case branch.MaskHash:
		return hash(key, expr)
	case branch.MaskFake:
		return fmt.Sprintf("%s.fake(%s, %s)", branch.MaskSchema, lit(strings.ToLower(category)), hash(key, expr))
	case branch.MaskPartial:
		return partial(expr)
	}
	return "NULL"
}

// tableMask is what masking one table takes.
type tableMask struct {
	Drop  []string // the masks it replaces, and the masked reader's rights on the table
	Build []string // the shadow and its triggers
	Fill  string   // the masks of the rows already there, in batches
	View  []string // the view, once the shadow is full
}

// shadowCol is a column the shadow keeps a mask for: hash and fake columns,
// and a JSON column with a path rule, kept as the whole document masked.
type shadowCol struct {
	name, typ, expr string // expr over the row alias n
}

// plan is a table's masks under one key: what the shadow keeps, and how.
type plan struct {
	nm     names
	pk     branch.MaskColumn
	cols   []branch.MaskColumn
	own    map[string]branch.MaskRule
	shadow []shadowCol
}

// planTable checks a table's rules against its columns and works out its
// masks under a key. A table with no rules has no plan.
func planTable(schema, table string, cols []branch.MaskColumn, rules []branch.MaskRule, key string) (*plan, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	p := &plan{nm: namesFor(schema, table), cols: cols, own: map[string]branch.MaskRule{}}
	var keys []branch.MaskColumn
	byName := map[string]branch.MaskColumn{}
	for _, c := range cols {
		byName[c.Name] = c
		if c.Key {
			keys = append(keys, c)
		}
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("%w: %s.%s has %s: masks are kept by a one-column primary key", branch.ErrInvalidRequest, schema, table,
			map[bool]string{true: "no primary key", false: "a primary key of several columns"}[len(keys) == 0])
	}
	p.pk = keys[0]

	// The rules by column: the column's own, and its JSON paths.
	paths := map[string][]branch.MaskRule{}
	for _, r := range rules {
		c, ok := byName[r.Column]
		if !ok {
			return nil, fmt.Errorf("%w: %s.%s has no column %q", branch.ErrInvalidRequest, schema, table, r.Column)
		}
		if c.Key {
			return nil, fmt.Errorf("%w: %s is the table's key, which the masks are kept by: it cannot be masked", branch.ErrInvalidRequest, r.Where())
		}
		if r.Path == "" {
			p.own[r.Column] = r
			continue
		}
		if c.Type != "jsonb" {
			return nil, fmt.Errorf("%w: a JSON path is masked in a jsonb column, and %s is %s", branch.ErrInvalidRequest, r.Column, c.Type)
		}
		if _, err := pathKeys(r.Path); err != nil {
			return nil, err
		}
		paths[r.Column] = append(paths[r.Column], r)
	}

	for _, c := range cols {
		if r, ok := p.own[c.Name]; ok && (r.Rule == branch.MaskHash || r.Rule == branch.MaskFake) {
			p.shadow = append(p.shadow, shadowCol{c.Name, "text", scalar(key, r.Rule, r.Category, "n."+ident(c.Name))})
			continue
		}
		if ps, ok := paths[c.Name]; ok {
			if _, whole := p.own[c.Name]; whole {
				return nil, fmt.Errorf("%w: %s has a rule of its own and on its paths: take one off", branch.ErrInvalidRequest, c.Name)
			}
			sort.Slice(ps, func(i, j int) bool { return ps[i].Path < ps[j].Path })
			doc := "n." + ident(c.Name)
			for _, r := range ps {
				ks, _ := pathKeys(r.Path)
				arr := "'{" + strings.Join(ks, ",") + "}'"
				val := fmt.Sprintf("to_jsonb(%s)", scalar(key, r.Rule, r.Category, "n."+ident(c.Name)+" #>> "+arr))
				if r.Rule == branch.MaskEmpty {
					val = "'null'::jsonb"
				}
				doc = fmt.Sprintf("CASE WHEN n.%[1]s #> %[2]s IS NULL THEN %[3]s ELSE jsonb_set(%[3]s, %[2]s, %[4]s) END",
					ident(c.Name), arr, doc, val)
			}
			p.shadow = append(p.shadow, shadowCol{c.Name, "jsonb", doc})
		}
	}
	return p, nil
}

// k is the key column, quoted.
func (p *plan) k() string { return ident(p.pk.Name) }

// shadowDDL makes a shadow by the name given, owned by bb_masker, indexed on
// its hashes.
func (p *plan) shadowDDL(shadow string) []string {
	defs := []string{p.k() + " " + p.pk.Type + " PRIMARY KEY"}
	for _, s := range p.shadow {
		defs = append(defs, ident(s.name)+" "+s.typ)
	}
	out := []string{
		"CREATE TABLE " + shadow + " (" + strings.Join(defs, ", ") + ")",
		"ALTER TABLE " + shadow + " OWNER TO " + branch.MaskerRole,
	}
	for _, s := range p.shadow {
		if s.typ == "text" {
			out = append(out, fmt.Sprintf("CREATE INDEX ON %s (%s)", shadow, ident(s.name)))
		}
	}
	return out
}

// upsert writes the masks of the rows in from into a shadow; with keep, a
// row already there is left as it is.
func (p *plan) upsert(shadow, from string, keep bool) string {
	var names, exprs, sets []string
	for _, s := range p.shadow {
		names = append(names, ident(s.name))
		exprs = append(exprs, s.expr)
		sets = append(sets, ident(s.name)+" = EXCLUDED."+ident(s.name))
	}
	k := p.k()
	cols, vals, conflict := "", "", " ON CONFLICT ("+k+") DO NOTHING"
	if len(names) > 0 {
		cols, vals = ", "+strings.Join(names, ", "), ", "+strings.Join(exprs, ", ")
		if !keep {
			conflict = " ON CONFLICT (" + k + ") DO UPDATE SET " + strings.Join(sets, ", ")
		}
	}
	return fmt.Sprintf("INSERT INTO %s (%s%s) SELECT n.%s%s FROM %s%s", shadow, k, cols, k, vals, from, conflict)
}

// target is a shadow a trigger keeps, under one plan's key.
type target struct {
	shadow string
	p      *plan
}

// keepFn is the function the triggers run: one call a statement, from its
// transition tables (decision 9, and section 17: 198 ms rather than 307 for a
// 10,000-row update), keeping each target. Two during a rotation.
func keepFn(fn string, targets []target) []string {
	k := targets[0].p.k()
	var trunc, del, moved, ups []string
	for _, t := range targets {
		trunc = append(trunc, t.shadow)
		del = append(del, fmt.Sprintf("DELETE FROM %s s USING o WHERE s.%[2]s = o.%[2]s", t.shadow, k))
		moved = append(moved, fmt.Sprintf("DELETE FROM %s s USING o WHERE s.%[2]s = o.%[2]s AND NOT EXISTS (SELECT 1 FROM n WHERE n.%[2]s = o.%[2]s)", t.shadow, k))
		ups = append(ups, t.p.upsert(t.shadow, "n", false))
	}
	// The body names the table's columns, which whoever made it chose.
	body := fmt.Sprintf(`
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    TRUNCATE %s;
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    %s;
    RETURN NULL;
  END IF;
  IF TG_OP = 'UPDATE' THEN
    %s;
  END IF;
  %s;
  RETURN NULL;
END `, strings.Join(trunc, ", "), strings.Join(del, ";\n    "), strings.Join(moved, ";\n    "), strings.Join(ups, ";\n  "))
	tag := branch.DollarTag("bbmask", body)
	return []string{
		fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS %s%s%s`, fn, tag, body, tag),
		"ALTER FUNCTION " + fn + "() OWNER TO " + branch.MaskerRole,
		"REVOKE EXECUTE ON FUNCTION " + fn + "() FROM PUBLIC",
	}
}

// fill writes the masks of the rows already there into a shadow, 10,000 at a
// time, each batch committed: a writer meanwhile is never held up (section
// 17: 1,000,000 in 14 s). A row the triggers wrote first is left as it is.
func (p *plan) fill(shadow string) string {
	k := p.k()
	// The body names the table and its key, which whoever made it chose.
	body := fmt.Sprintf(`
DECLARE last %[1]s; nxt %[1]s;
BEGIN
  LOOP
    SELECT max(%[2]s) INTO nxt FROM (SELECT %[2]s FROM %[3]s WHERE last IS NULL OR %[2]s > last ORDER BY %[2]s LIMIT 10000) b;
    EXIT WHEN nxt IS NULL;
    %[4]s;
    last := nxt;
    COMMIT;
  END LOOP;
END `, p.pk.Type, k, p.nm.base, p.upsert(shadow, p.nm.base+" n WHERE (last IS NULL OR n."+k+" > last) AND n."+k+" <= nxt", true))
	tag := branch.DollarTag("bbfill", body)
	return "DO " + tag + body + tag + ";"
}

// maskTable makes a table's masks under a key, from its columns and its
// rules. A table with no rules gets only Drop and its rights back.
func maskTable(schema, table string, cols []branch.MaskColumn, rules []branch.MaskRule, key string) (tableMask, error) {
	nm := namesFor(schema, table)
	var m tableMask
	m.Drop = []string{
		"REVOKE ALL ON " + nm.base + " FROM " + branch.MaskedRole,
		"DROP VIEW IF EXISTS " + nm.view,
		"DROP TRIGGER IF EXISTS bb_mask_i ON " + nm.base,
		"DROP TRIGGER IF EXISTS bb_mask_u ON " + nm.base,
		"DROP TRIGGER IF EXISTS bb_mask_d ON " + nm.base,
		"DROP TRIGGER IF EXISTS bb_mask_t ON " + nm.base,
		"DROP FUNCTION IF EXISTS " + nm.fn + "()",
		"DROP TABLE IF EXISTS " + nm.next,
		"DROP TABLE IF EXISTS " + nm.shadow,
	}
	p, err := planTable(schema, table, cols, rules, key)
	if err != nil {
		return m, err
	}
	if p == nil {
		m.Drop = append(m.Drop, "GRANT SELECT, INSERT, UPDATE, DELETE ON "+nm.base+" TO "+branch.MaskedRole)
		return m, nil
	}
	if len(p.shadow) == 0 {
		// Only partial and empty: no secret, so nothing is kept, and writes
		// to the table cost nothing more. The view computes the masks.
		m.View = viewSQL(nm, cols, p.own, nil, "", false)
		return m, nil
	}
	m.Build = append(p.shadowDDL(nm.shadow), "GRANT SELECT ON "+nm.base+" TO "+branch.MaskerRole)
	m.Build = append(m.Build, keepFn(nm.fn, []target{{nm.shadow, p}})...)
	m.Build = append(m.Build,
		fmt.Sprintf("CREATE TRIGGER bb_mask_i AFTER INSERT ON %s REFERENCING NEW TABLE AS n FOR EACH STATEMENT EXECUTE FUNCTION %s()", nm.base, nm.fn),
		fmt.Sprintf("CREATE TRIGGER bb_mask_u AFTER UPDATE ON %s REFERENCING OLD TABLE AS o NEW TABLE AS n FOR EACH STATEMENT EXECUTE FUNCTION %s()", nm.base, nm.fn),
		fmt.Sprintf("CREATE TRIGGER bb_mask_d AFTER DELETE ON %s REFERENCING OLD TABLE AS o FOR EACH STATEMENT EXECUTE FUNCTION %s()", nm.base, nm.fn),
		fmt.Sprintf("CREATE TRIGGER bb_mask_t AFTER TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION %s()", nm.base, nm.fn),
	)
	m.Fill = p.fill(nm.shadow)
	m.View = viewSQL(nm, cols, p.own, p.shadow, p.k(), false)
	return m, nil
}

// tableRekey is moving a table's masks from one key to another while masked
// readers keep reading the old ones (design, section 8): a second shadow,
// kept by the triggers under the new key beside the old, filled, then swapped
// in for the old in one transaction.
type tableRekey struct {
	Start []string // the next shadow, and the triggers keeping both
	Fill  string   // the next shadow's masks of the rows already there
	Swap  []string // the next shadow becomes the shadow, the view reads it, the triggers keep only it
}

// rekeyTable makes it. A table with no keyed masks has nothing to move: ok is
// false.
func rekeyTable(schema, table string, cols []branch.MaskColumn, rules []branch.MaskRule, from, to string) (tableRekey, bool, error) {
	var rk tableRekey
	old, err := planTable(schema, table, cols, rules, from)
	if err != nil || old == nil || len(old.shadow) == 0 {
		return rk, false, err
	}
	nw, err := planTable(schema, table, cols, rules, to)
	if err != nil {
		return rk, false, err
	}
	nm := old.nm
	rk.Start = append(writesWait(nm), "DROP TABLE IF EXISTS "+nm.next)
	rk.Start = append(rk.Start, nw.shadowDDL(nm.next)...)
	rk.Start = append(rk.Start, keepFn(nm.fn, []target{{nm.shadow, old}, {nm.next, nw}})...)
	rk.Fill = nw.fill(nm.next)
	rk.Swap = append(writesWait(nm),
		"ALTER TABLE "+nm.shadow+" RENAME TO "+ident(nm.shadowName+"__old"),
		"ALTER TABLE "+nm.next+" RENAME TO "+ident(nm.shadowName),
	)
	// The view now reads the new shadow (by its name, now the shadow's), and
	// keeps its grants.
	rk.Swap = append(rk.Swap, viewSQL(nm, cols, nw.own, nw.shadow, nw.k(), true)[0])
	rk.Swap = append(rk.Swap, keepFn(nm.fn, []target{{nm.shadow, nw}})...)
	rk.Swap = append(rk.Swap, "DROP TABLE "+branch.MaskSchema+"."+ident(nm.shadowName+"__old"))
	return rk, true, nil
}

// repointTable has a table's triggers write its masks under another name for
// the same key: once a rotation's new key is in the domain's own file.
func repointTable(schema, table string, cols []branch.MaskColumn, rules []branch.MaskRule, key string) ([]string, error) {
	p, err := planTable(schema, table, cols, rules, key)
	if err != nil || p == nil || len(p.shadow) == 0 {
		return nil, err
	}
	return append(writesWait(p.nm), keepFn(p.nm.fn, []target{{p.nm.shadow, p}})...), nil
}

// writesWait starts a change to what a table's triggers write: it waits for
// the writes already running, which finish with the triggers as they were,
// and holds new ones until it commits, so no write runs triggers changed under
// it (one would write to a shadow renamed or dropped, or under a key gone).
// Reads go on. Waiting is bounded: a long transaction on the table is not
// waited behind with every new write queued after it; the change is tried
// again.
func writesWait(nm names) []string {
	return []string{
		"SET LOCAL lock_timeout = '" + lockWait + "'",
		"LOCK TABLE " + nm.base + " IN SHARE ROW EXCLUSIVE MODE",
	}
}

// lockWait bounds writesWait.
const lockWait = "3s"

// viewSQL is the view: every column, in order, the masked ones as their
// masks, joined to the shadow on key k when there is one. With replace, the
// view there is replaced and keeps its owner and grants.
func viewSQL(nm names, cols []branch.MaskColumn, own map[string]branch.MaskRule, shadow []shadowCol, k string, replace bool) []string {
	kept := map[string]bool{}
	for _, s := range shadow {
		kept[s.name] = true
	}
	var sel []string
	for _, c := range cols {
		q := ident(c.Name)
		switch r, ok := own[c.Name]; {
		case kept[c.Name]:
			sel = append(sel, "m."+q+" AS "+q)
		case ok && r.Rule == branch.MaskPartial:
			sel = append(sel, partial("n."+q)+" AS "+q)
		case ok && r.Rule == branch.MaskEmpty:
			sel = append(sel, "NULL::"+c.Type+" AS "+q)
		default:
			sel = append(sel, "n."+q)
		}
	}
	from := nm.base + " n"
	if len(shadow) > 0 {
		from += fmt.Sprintf(" JOIN %s m ON m.%s = n.%s", nm.shadow, k, k)
	}
	return []string{
		fmt.Sprintf("CREATE %sVIEW %s AS SELECT %s FROM %s", map[bool]string{true: "OR REPLACE "}[replace], nm.view, strings.Join(sel, ", "), from),
		"ALTER VIEW " + nm.view + " OWNER TO " + branch.MaskerRole,
		"GRANT SELECT ON " + nm.base + " TO " + branch.MaskerRole,
		// An unmask holder's reads of the table are logged (step 3).
		"GRANT SELECT ON " + nm.base + " TO " + branch.AuditReadRole,
		"GRANT SELECT ON " + nm.view + " TO " + branch.MaskedRole,
	}
}

// maskTablesDDL keeps each masked table's key (step 2): its domain, and the
// key of that domain its masks were made under. A table not in it is the
// default domain's, under its first key, as on a branch set up in step 1.
const maskTablesDDL = `CREATE TABLE IF NOT EXISTS bb.mask_tables (
  schema_name text NOT NULL, table_name text NOT NULL,
  key_domain text NOT NULL DEFAULT 'default', key_gen int NOT NULL DEFAULT 1,
  PRIMARY KEY (schema_name, table_name))`

// setupSQL is what a branch needs before any table is masked: the hash
// (bb_identity 0.2), the roles, the schema, the rules table, the fake values,
// and a masked reader's rights on every table that is not masked.
func setupSQL() []string {
	return append([]string{
		`DO $bbsetup$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'bb_identity') THEN
    EXECUTE 'ALTER EXTENSION bb_identity UPDATE';
  ELSE
    EXECUTE 'CREATE SCHEMA IF NOT EXISTS bb_f1';
    EXECUTE 'CREATE EXTENSION bb_identity WITH SCHEMA bb_f1';
  END IF;
  IF to_regrole('` + branch.MaskerRole + `') IS NULL THEN EXECUTE 'CREATE ROLE ` + branch.MaskerRole + ` NOLOGIN'; END IF;
  IF to_regrole('` + branch.MaskedRole + `') IS NULL THEN EXECUTE 'CREATE ROLE ` + branch.MaskedRole + ` NOLOGIN'; END IF;
END $bbsetup$`,
		"GRANT USAGE ON SCHEMA bb_f1 TO " + branch.MaskerRole,
		"GRANT EXECUTE ON FUNCTION bb_f1.bbid_mask_hmac(text, text) TO " + branch.MaskerRole,
		"CREATE SCHEMA IF NOT EXISTS " + branch.MaskSchema + " AUTHORIZATION " + branch.MaskerRole,
		"GRANT USAGE ON SCHEMA " + branch.MaskSchema + " TO " + branch.MaskedRole,
		`CREATE TABLE IF NOT EXISTS bb.mask_rules (
  schema_name text NOT NULL, table_name text NOT NULL, column_name text NOT NULL, json_path text NOT NULL DEFAULT '',
  rule text NOT NULL CHECK (rule IN ('partial', 'hash', 'fake', 'empty')), category text NOT NULL DEFAULT '',
  set_by text NOT NULL, set_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (schema_name, table_name, column_name, json_path))`,
		"REVOKE ALL ON bb.mask_rules FROM PUBLIC",
		maskTablesDDL,
		"REVOKE ALL ON bb.mask_tables FROM PUBLIC",
		// fake: a realistic value, the same for the same input, chosen by the
		// hash. Never granted: it takes a hash, and is called by the triggers.
		`CREATE OR REPLACE FUNCTION ` + branch.MaskSchema + `.fake(kind text, h text) RETURNS text LANGUAGE sql IMMUTABLE AS $bbfake$
  SELECT CASE kind
    WHEN 'name' THEN (ARRAY['Anil Mehta','Bina Das','Chetan Iyer','Divya Nair','Eshan Gupta','Farah Khan','Gopal Rao','Hema Pillai',
                            'Imran Sheikh','Jaya Menon','Karan Shah','Lata Joshi','Mohan Reddy','Neha Kapoor','Omar Ali','Priya Sen'])
                     [1 + ('x' || substr(h, 1, 7))::bit(28)::int % 16]
    WHEN 'email' THEN 'user' || substr(h, 1, 10) || '@example.invalid'
    WHEN 'mobile' THEN '+91 9' || lpad((('x' || substr(h, 1, 8))::bit(32)::bigint % 1000000000)::text, 9, '0')
    WHEN 'city' THEN (ARRAY['Pune','Delhi','Chennai','Kolkata','Jaipur','Lucknow','Bhopal','Kochi'])[1 + ('x' || substr(h, 1, 7))::bit(28)::int % 8]
    ELSE 'x' || substr(h, 1, 12) END $bbfake$`,
		"ALTER FUNCTION " + branch.MaskSchema + ".fake(text, text) OWNER TO " + branch.MaskerRole,
		"REVOKE EXECUTE ON FUNCTION " + branch.MaskSchema + ".fake(text, text) FROM PUBLIC",
		// A masked reader reads and writes every table as any account does,
		// except the masked ones, whose rights maskTable takes away: on what is
		// here now, and on what db_client makes later.
		`DO $bbgrant$
DECLARE s text;
BEGIN
  FOR s IN SELECT nspname FROM pg_namespace
            WHERE nspname NOT LIKE 'pg\_%' AND nspname NOT IN ('information_schema', 'bb', 'bb_f1', '` + branch.MaskSchema + `')
  LOOP
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO ` + branch.MaskedRole + `', s);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO ` + branch.MaskedRole + `', s);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO ` + branch.MaskedRole + `', s);
    IF to_regrole('db_client') IS NOT NULL THEN
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE db_client IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ` + branch.MaskedRole + `', s);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE db_client IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES TO ` + branch.MaskedRole + `', s);
    END IF;
  END LOOP;
END $bbgrant$`,
	}, append(lookupSQL(), closeSQL()...)...)
}

// closeSQL is the guard on the paths around the views (step 4; design,
// section 11). Masks are kept by taking a masked reader's grant on a marked
// table away; three things gave real values back, and the guard closes them:
//
//   - a view or materialized view reading a marked column, made by anyone but
//     the masks' owner: it reads as its owner, and the default privileges gave
//     a masked reader SELECT on it the moment it was made;
//   - a GRANT on a marked table, or on such a view, to db_masked, to one of
//     its members, or to PUBLIC, as a promoted change request can carry;
//   - INSERT and UPDATE on a table with a foreign key into a marked column: a
//     violation, or none, says whether a guessed value is there.
//
// bb.mask_close_paths takes a masked reader's rights on each away, keeping
// what it took in bb.mask_closed, and gives them back when the rule that
// closed them is taken off. It runs after every statement that can open one
// (an event trigger) and after every change of the masks. A GRANT to PUBLIC
// is refused, saying why; found by any other statement, PUBLIC's right is
// taken away, with a warning. In bb, as the engine's own superuser: it takes
// rights on objects others own, and bb is where the hardening report expects
// the engine's own definer functions.
func closeSQL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS bb.mask_closed (rel oid PRIMARY KEY, name text NOT NULL, kind text NOT NULL,
  privs text NOT NULL DEFAULT '', at timestamptz NOT NULL DEFAULT now())`,
		"REVOKE ALL ON bb.mask_closed FROM PUBLIC",
		"GRANT SELECT ON bb.mask_closed TO " + branch.MaskerRole,
		`CREATE OR REPLACE FUNCTION bb.mask_close_paths(granting boolean DEFAULT false) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $bbclose$
DECLARE o record; g record; want text[]; rels oid[]; kinds text[]; n int := 0; masked oid; ns oid;
BEGIN
  IF to_regclass('bb.mask_rules') IS NULL OR to_regrole('` + branch.MaskedRole + `') IS NULL THEN RETURN 0; END IF;
  masked := to_regrole('` + branch.MaskedRole + `');
  ns := (SELECT oid FROM pg_namespace WHERE nspname = '` + branch.MaskSchema + `');
  -- No temporary table: making one is a CREATE TABLE, and would fire this again.
  WITH RECURSIVE marked AS (
    SELECT c.oid AS rel, array_agg(a.attnum) AS cols
      FROM bb.mask_rules r
      JOIN pg_namespace s ON s.nspname = r.schema_name
      JOIN pg_class c ON c.relnamespace = s.oid AND c.relname = r.table_name
      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = r.column_name
     GROUP BY c.oid),
  readers(rel) AS (
    SELECT rw.ev_class
      FROM marked mk
      JOIN pg_depend d ON d.refclassid = 'pg_class'::regclass AND d.refobjid = mk.rel
                      AND (d.refobjsubid = 0 OR d.refobjsubid = ANY (mk.cols))
      JOIN pg_rewrite rw ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid
      JOIN pg_class v ON v.oid = rw.ev_class
     WHERE rw.ev_class <> mk.rel AND v.relnamespace IS DISTINCT FROM ns
    UNION
    SELECT rw.ev_class
      FROM readers x
      JOIN pg_depend d ON d.refclassid = 'pg_class'::regclass AND d.refobjid = x.rel
      JOIN pg_rewrite rw ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid
      JOIN pg_class v ON v.oid = rw.ev_class
     WHERE rw.ev_class <> x.rel AND v.relnamespace IS DISTINCT FROM ns),
  refs AS (SELECT DISTINCT con.conrelid AS rel
          FROM pg_constraint con JOIN marked mk ON mk.rel = con.confrelid
         WHERE con.contype = 'f' AND con.confkey && mk.cols
           AND con.conrelid NOT IN (SELECT rel FROM marked) AND con.conrelid NOT IN (SELECT rel FROM readers)),
  closing AS (SELECT rel, 'base' AS kind FROM marked
    UNION SELECT rel, 'reads' FROM readers WHERE rel NOT IN (SELECT rel FROM marked)
    UNION SELECT rel, 'refs' FROM refs)
  SELECT coalesce(array_agg(rel), '{}'), coalesce(array_agg(kind), '{}') INTO rels, kinds FROM closing;
  FOR o IN SELECT x.rel, x.kind, x.rel::regclass::text AS name, c.relacl
             FROM unnest(rels, kinds) AS x(rel, kind) JOIN pg_class c ON c.oid = x.rel LOOP
    want := CASE WHEN o.kind = 'refs' THEN ARRAY['INSERT', 'UPDATE']
                 ELSE ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'] END;
    FOR g IN SELECT a.grantee, array_agg(a.privilege_type::text) AS privs FROM aclexplode(o.relacl) a
              WHERE a.privilege_type = ANY (want)
                AND (a.grantee IN (0, masked) OR a.grantee IN (SELECT member FROM pg_auth_members WHERE roleid = masked))
              GROUP BY a.grantee LOOP
      IF g.grantee = 0 THEN
        IF granting THEN
          RAISE EXCEPTION 'refused: % on % to PUBLIC would give masked accounts the real values of a masked table', array_to_string(g.privs, ', '), o.name
            USING ERRCODE = '42501', HINT = 'grant to the roles that need it, not to PUBLIC';
        END IF;
        RAISE WARNING 'masking: % on % taken from PUBLIC, which masked accounts are members of', array_to_string(g.privs, ', '), o.name;
        EXECUTE format('REVOKE %s ON %s FROM PUBLIC', array_to_string(g.privs, ', '), o.name);
      ELSIF g.grantee = masked THEN
        IF o.kind <> 'base' THEN
          INSERT INTO bb.mask_closed (rel, name, kind, privs) VALUES (o.rel, o.name, o.kind, array_to_string(g.privs, ', '))
            ON CONFLICT (rel) DO NOTHING;
        END IF;
        EXECUTE format('REVOKE %s ON %s FROM %I', array_to_string(g.privs, ', '), o.name, '` + branch.MaskedRole + `');
      ELSE
        EXECUTE format('REVOKE %s ON %s FROM %I', array_to_string(g.privs, ', '), o.name, pg_get_userbyid(g.grantee));
      END IF;
      n := n + 1;
    END LOOP;
  END LOOP;
  -- Given back where nothing closes it any more; forgotten where it is gone.
  FOR o IN SELECT k.rel, k.privs, k.kind FROM bb.mask_closed k
            WHERE NOT EXISTS (SELECT 1 FROM unnest(rels, kinds) AS x(rel, kind) WHERE x.rel = k.rel AND x.kind = k.kind) LOOP
    DELETE FROM bb.mask_closed WHERE rel = o.rel;
    IF EXISTS (SELECT 1 FROM pg_class WHERE oid = o.rel) AND NOT (o.rel = ANY (rels)) THEN
      EXECUTE format('GRANT %s ON %s TO %I', o.privs, o.rel::regclass::text, '` + branch.MaskedRole + `');
    END IF;
  END LOOP;
  RETURN n;
END $bbclose$`,
		"REVOKE EXECUTE ON FUNCTION bb.mask_close_paths(boolean) FROM PUBLIC",
		`CREATE OR REPLACE FUNCTION bb.mask_close_paths_et() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $bbcloseet$
BEGIN
  PERFORM bb.mask_close_paths(tg_tag = 'GRANT');
END $bbcloseet$`,
		"REVOKE EXECUTE ON FUNCTION bb.mask_close_paths_et() FROM PUBLIC",
		`DO $bbet$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname = 'bb_mask_close') THEN
    CREATE EVENT TRIGGER bb_mask_close ON ddl_command_end
      WHEN TAG IN ('CREATE VIEW', 'ALTER VIEW', 'CREATE MATERIALIZED VIEW', 'ALTER MATERIALIZED VIEW', 'CREATE RULE',
                   'CREATE TABLE', 'ALTER TABLE', 'GRANT', 'ALTER DEFAULT PRIVILEGES')
      EXECUTE FUNCTION bb.mask_close_paths_et();
  END IF;
END $bbet$`,
	}
}

// closePathsSQL runs the guard now, after a change of the masks.
const closePathsSQL = "SELECT bb.mask_close_paths(false)"

// lookupSQL is the lookup (step 3; design, section 10): a masked reader finds
// a person by an exact value without unmasking. SECURITY DEFINER, as
// bb_masker, which reads the rules, the tables and the hash, and nobody logs
// in as. It looks only in a column with a rule of its own, returns the rows
// masked, as the view has them, allows a number of calls a minute for each
// account, and records each call without the value. A value that is not of
// the column's type is refused without being repeated, so it reaches no log.
func lookupSQL() []string {
	return []string{
		`DO $bbaudit$ BEGIN
  IF to_regrole('` + branch.AuditReadRole + `') IS NULL THEN EXECUTE 'CREATE ROLE ` + branch.AuditReadRole + ` NOLOGIN'; END IF;
END $bbaudit$`,
		"GRANT USAGE ON SCHEMA bb TO " + branch.MaskerRole,
		"GRANT SELECT ON bb.mask_rules, bb.mask_tables TO " + branch.MaskerRole,
		`CREATE TABLE IF NOT EXISTS ` + branch.MaskSchema + `.lookups (at timestamptz NOT NULL DEFAULT clock_timestamp(),
  who text NOT NULL, rel text NOT NULL, col text NOT NULL, found int NOT NULL)`,
		"ALTER TABLE " + branch.MaskSchema + ".lookups OWNER TO " + branch.MaskerRole,
		"REVOKE ALL ON " + branch.MaskSchema + ".lookups FROM PUBLIC",
		`CREATE INDEX IF NOT EXISTS lookups_who_at ON ` + branch.MaskSchema + `.lookups (who, at)`,
		fmt.Sprintf(`CREATE OR REPLACE FUNCTION %[1]s.find(tbl text, col text, val text) RETURNS SETOF jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $bbfind$
DECLARE s text; t text; v text; r text; d text; typ text; k text; rel regclass; n int; ok boolean;
BEGIN
  IF position('.' in tbl) > 0 THEN s := split_part(tbl, '.', 1); t := split_part(tbl, '.', 2); ELSE s := 'public'; t := tbl; END IF;
  SELECT rule INTO r FROM bb.mask_rules WHERE schema_name = s AND table_name = t AND column_name = col AND json_path = '';
  IF r IS NULL THEN
    RAISE EXCEPTION 'a lookup is by a column with a masking rule of its own, and %%.%%.%% has none', s, t, col USING ERRCODE = '42704';
  END IF;
  IF (SELECT count(*) FROM %[1]s.lookups WHERE who = session_user AND at > clock_timestamp() - interval '1 minute') >= %[2]d THEN
    RAISE EXCEPTION 'too many lookups: %[2]d a minute for each account' USING ERRCODE = '53400';
  END IF;
  rel := format('%%I.%%I', s, t)::regclass;
  v := CASE WHEN s = 'public' THEN t ELSE s || '__' || t END;
  SELECT format_type(a.atttypid, a.atttypmod) INTO typ FROM pg_attribute a WHERE a.attrelid = rel AND a.attname = col;
  SELECT a.attname INTO k FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
   WHERE i.indrelid = rel AND i.indisprimary;
  BEGIN
    EXECUTE format('SELECT CAST($1 AS %%s) IS NOT NULL', typ) INTO ok USING val;
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION 'the value is not a %%', typ USING ERRCODE = '22000';
  END;
  IF r = 'hash' THEN
    -- The value hashed here, under the table's domain, against the kept hashes.
    SELECT coalesce((SELECT key_domain FROM bb.mask_tables WHERE schema_name = s AND table_name = t), 'default') INTO d;
    RETURN QUERY EXECUTE format('SELECT to_jsonb(m) FROM %[1]s.%%I m WHERE m.%%I = bb_f1.bbid_mask_hmac($2, $1)', v, col) USING val, d;
  ELSE
    RETURN QUERY EXECUTE format('SELECT to_jsonb(m) FROM %[1]s.%%I m WHERE m.%%I IN (SELECT n.%%I FROM %%I.%%I n WHERE n.%%I = CAST($1 AS %%s))',
      v, k, k, s, t, col, typ) USING val;
  END IF;
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO %[1]s.lookups (who, rel, col, found) VALUES (session_user, s || '.' || t, col, n);
END $bbfind$`, branch.MaskSchema, branch.LookupsPerMinute),
		"ALTER FUNCTION " + branch.MaskSchema + ".find(text, text, text) OWNER TO " + branch.MaskerRole,
		"REVOKE EXECUTE ON FUNCTION " + branch.MaskSchema + ".find(text, text, text) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION " + branch.MaskSchema + ".find(text, text, text) TO " + branch.MaskedRole,
	}
}

// auditReadsSQL gives bb_audit_read SELECT on the tables with rules, for a
// branch whose masks were made before step 3.
func auditReadsSQL(tables [][2]string) []string {
	out := lookupSQL()[:1]
	for _, t := range tables {
		out = append(out, "GRANT SELECT ON "+ident(t[0])+"."+ident(t[1])+" TO "+branch.AuditReadRole)
	}
	return out
}
