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

const keyDomain = "default"

func ident(s string) string { return branch.QuoteIdent(s) }
func lit(s string) string   { return branch.QuoteLiteral(s) }

// names are a table's masking objects, all in bb_mask. The view has the
// table's own name for a table in public, so a masked reader's unqualified
// name reaches it; a table in another schema's view is <schema>__<table>.
type names struct {
	base, shadow, view, fn string
}

func namesFor(schema, table string) names {
	view := table
	if schema != "public" {
		view = schema + "__" + table
	}
	return names{
		base:   ident(schema) + "." + ident(table),
		shadow: branch.MaskSchema + "." + ident(schema+"__"+table),
		view:   branch.MaskSchema + "." + ident(view),
		fn:     branch.MaskSchema + "." + ident("keep__"+schema+"__"+table),
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

// hash is the keyed hash of an expression as text.
func hash(expr string) string {
	return fmt.Sprintf("bb_f1.bbid_mask_hmac(%s, (%s)::text)", lit(keyDomain), expr)
}

// partial keeps the last four characters, every other one an X, so the mask
// is as long as the value.
func partial(expr string) string {
	return fmt.Sprintf("(repeat('X', greatest(length((%[1]s)::text) - 4, 0)) || right((%[1]s)::text, 4))", expr)
}

// scalar is a rule applied to a text value.
func scalar(rule, category, expr string) string {
	switch rule {
	case branch.MaskHash:
		return hash(expr)
	case branch.MaskFake:
		return fmt.Sprintf("%s.fake(%s, %s)", branch.MaskSchema, lit(strings.ToLower(category)), hash(expr))
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

// maskTable makes it, from the table's columns and its rules. A table with no
// rules gets only Drop and its rights back.
func maskTable(schema, table string, cols []branch.MaskColumn, rules []branch.MaskRule) (tableMask, error) {
	nm := namesFor(schema, table)
	var keys []branch.MaskColumn
	byName := map[string]branch.MaskColumn{}
	for _, c := range cols {
		byName[c.Name] = c
		if c.Key {
			keys = append(keys, c)
		}
	}
	var m tableMask
	m.Drop = []string{
		"REVOKE ALL ON " + nm.base + " FROM " + branch.MaskedRole,
		"DROP VIEW IF EXISTS " + nm.view,
		"DROP TRIGGER IF EXISTS bb_mask_i ON " + nm.base,
		"DROP TRIGGER IF EXISTS bb_mask_u ON " + nm.base,
		"DROP TRIGGER IF EXISTS bb_mask_d ON " + nm.base,
		"DROP TRIGGER IF EXISTS bb_mask_t ON " + nm.base,
		"DROP FUNCTION IF EXISTS " + nm.fn + "()",
		"DROP TABLE IF EXISTS " + nm.shadow,
	}
	if len(rules) == 0 {
		m.Drop = append(m.Drop, "GRANT SELECT, INSERT, UPDATE, DELETE ON "+nm.base+" TO "+branch.MaskedRole)
		return m, nil
	}
	if len(keys) != 1 {
		return m, fmt.Errorf("%w: %s.%s has %s: masks are kept by a one-column primary key", branch.ErrInvalidRequest, schema, table,
			map[bool]string{true: "no primary key", false: "a primary key of several columns"}[len(keys) == 0])
	}
	pk := keys[0]

	// The rules by column: the column's own, and its JSON paths.
	own := map[string]branch.MaskRule{}
	paths := map[string][]branch.MaskRule{}
	for _, r := range rules {
		c, ok := byName[r.Column]
		if !ok {
			return m, fmt.Errorf("%w: %s.%s has no column %q", branch.ErrInvalidRequest, schema, table, r.Column)
		}
		if c.Key {
			return m, fmt.Errorf("%w: %s is the table's key, which the masks are kept by: it cannot be masked", branch.ErrInvalidRequest, r.Where())
		}
		if r.Path == "" {
			own[r.Column] = r
			continue
		}
		if c.Type != "jsonb" {
			return m, fmt.Errorf("%w: a JSON path is masked in a jsonb column, and %s is %s", branch.ErrInvalidRequest, r.Column, c.Type)
		}
		if _, err := pathKeys(r.Path); err != nil {
			return m, err
		}
		paths[r.Column] = append(paths[r.Column], r)
	}

	var shadow []shadowCol
	for _, c := range cols {
		if r, ok := own[c.Name]; ok && (r.Rule == branch.MaskHash || r.Rule == branch.MaskFake) {
			shadow = append(shadow, shadowCol{c.Name, "text", scalar(r.Rule, r.Category, "n."+ident(c.Name))})
			continue
		}
		if ps, ok := paths[c.Name]; ok {
			if _, whole := own[c.Name]; whole {
				return m, fmt.Errorf("%w: %s has a rule of its own and on its paths: take one off", branch.ErrInvalidRequest, c.Name)
			}
			sort.Slice(ps, func(i, j int) bool { return ps[i].Path < ps[j].Path })
			doc := "n." + ident(c.Name)
			for _, r := range ps {
				ks, _ := pathKeys(r.Path)
				arr := "'{" + strings.Join(ks, ",") + "}'"
				val := fmt.Sprintf("to_jsonb(%s)", scalar(r.Rule, r.Category, "n."+ident(c.Name)+" #>> "+arr))
				if r.Rule == branch.MaskEmpty {
					val = "'null'::jsonb"
				}
				doc = fmt.Sprintf("CASE WHEN n.%[1]s #> %[2]s IS NULL THEN %[3]s ELSE jsonb_set(%[3]s, %[2]s, %[4]s) END",
					ident(c.Name), arr, doc, val)
			}
			shadow = append(shadow, shadowCol{c.Name, "jsonb", doc})
		}
	}

	if len(shadow) == 0 {
		// Only partial and empty: no secret, so nothing is kept, and writes
		// to the table cost nothing more. The view computes the masks.
		m.View = viewSQL(nm, cols, own, nil, "")
		return m, nil
	}

	// The shadow: the key, and the masks kept.
	defs := []string{ident(pk.Name) + " " + pk.Type + " PRIMARY KEY"}
	var colNames, exprs, sets []string
	for _, s := range shadow {
		defs = append(defs, ident(s.name)+" "+s.typ)
		colNames = append(colNames, ident(s.name))
		exprs = append(exprs, s.expr)
		sets = append(sets, ident(s.name)+" = EXCLUDED."+ident(s.name))
	}
	k := ident(pk.Name)
	m.Build = []string{
		"CREATE TABLE " + nm.shadow + " (" + strings.Join(defs, ", ") + ")",
		"ALTER TABLE " + nm.shadow + " OWNER TO " + branch.MaskerRole,
		"GRANT SELECT ON " + nm.base + " TO " + branch.MaskerRole,
	}
	for _, s := range shadow {
		if s.typ == "text" {
			m.Build = append(m.Build, fmt.Sprintf("CREATE INDEX ON %s (%s)", nm.shadow, ident(s.name)))
		}
	}
	upsert := func(from string) string {
		cols, vals, set := "", "", ""
		if len(colNames) > 0 {
			cols, vals = ", "+strings.Join(colNames, ", "), ", "+strings.Join(exprs, ", ")
			set = " ON CONFLICT (" + k + ") DO UPDATE SET " + strings.Join(sets, ", ")
		} else {
			set = " ON CONFLICT (" + k + ") DO NOTHING"
		}
		return fmt.Sprintf("INSERT INTO %s (%s%s) SELECT n.%s%s FROM %s%s", nm.shadow, k, cols, k, vals, from, set)
	}
	// One trigger a statement, from its transition tables (decision 9, and
	// section 17: 198 ms rather than 307 for a 10,000-row update).
	m.Build = append(m.Build,
		fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $bbmask$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    TRUNCATE %[2]s;
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    DELETE FROM %[2]s s USING o WHERE s.%[3]s = o.%[3]s;
    RETURN NULL;
  END IF;
  IF TG_OP = 'UPDATE' THEN
    DELETE FROM %[2]s s USING o WHERE s.%[3]s = o.%[3]s AND NOT EXISTS (SELECT 1 FROM n WHERE n.%[3]s = o.%[3]s);
  END IF;
  %[4]s;
  RETURN NULL;
END $bbmask$`, nm.fn, nm.shadow, k, upsert("n")),
		"ALTER FUNCTION "+nm.fn+"() OWNER TO "+branch.MaskerRole,
		"REVOKE EXECUTE ON FUNCTION "+nm.fn+"() FROM PUBLIC",
		fmt.Sprintf("CREATE TRIGGER bb_mask_i AFTER INSERT ON %s REFERENCING NEW TABLE AS n FOR EACH STATEMENT EXECUTE FUNCTION %s()", nm.base, nm.fn),
		fmt.Sprintf("CREATE TRIGGER bb_mask_u AFTER UPDATE ON %s REFERENCING OLD TABLE AS o NEW TABLE AS n FOR EACH STATEMENT EXECUTE FUNCTION %s()", nm.base, nm.fn),
		fmt.Sprintf("CREATE TRIGGER bb_mask_d AFTER DELETE ON %s REFERENCING OLD TABLE AS o FOR EACH STATEMENT EXECUTE FUNCTION %s()", nm.base, nm.fn),
		fmt.Sprintf("CREATE TRIGGER bb_mask_t AFTER TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION %s()", nm.base, nm.fn),
	)

	// The rows already there, 10,000 at a time, each batch committed: a
	// writer meanwhile is never held up (section 17: 1,000,000 in 14 s).
	m.Fill = fmt.Sprintf(`DO $bbfill$
DECLARE last %[1]s; nxt %[1]s;
BEGIN
  LOOP
    SELECT max(%[2]s) INTO nxt FROM (SELECT %[2]s FROM %[3]s WHERE last IS NULL OR %[2]s > last ORDER BY %[2]s LIMIT 10000) b;
    EXIT WHEN nxt IS NULL;
    %[4]s;
    last := nxt;
    COMMIT;
  END LOOP;
END $bbfill$;`, pk.Type, k, nm.base,
		strings.Replace(upsert(nm.base+" n WHERE (last IS NULL OR n."+k+" > last) AND n."+k+" <= nxt"), "DO UPDATE SET "+strings.Join(sets, ", "), "DO NOTHING", 1))

	m.View = viewSQL(nm, cols, own, shadow, k)
	return m, nil
}

// viewSQL is the view: every column, in order, the masked ones as their
// masks, joined to the shadow on key k when there is one.
func viewSQL(nm names, cols []branch.MaskColumn, own map[string]branch.MaskRule, shadow []shadowCol, k string) []string {
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
		fmt.Sprintf("CREATE VIEW %s AS SELECT %s FROM %s", nm.view, strings.Join(sel, ", "), from),
		"ALTER VIEW " + nm.view + " OWNER TO " + branch.MaskerRole,
		"GRANT SELECT ON " + nm.base + " TO " + branch.MaskerRole,
		"GRANT SELECT ON " + nm.view + " TO " + branch.MaskedRole,
	}
}

// setupSQL is what a branch needs before any table is masked: the hash
// (bb_identity 0.2), the roles, the schema, the rules table, the fake values,
// and a masked reader's rights on every table that is not masked.
func setupSQL() []string {
	return []string{
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
	}
}
