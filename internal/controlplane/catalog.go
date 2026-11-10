// SPDX-License-Identifier: AGPL-3.0-or-later

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/internal/auth"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// The object browser (point 12.1): what a branch holds, read-only, and each
// object's CREATE script. GET /api/branches/{name}/schema and `fox schema`
// share this.
//
//   - Read as the caller, in a read-only transaction: the console's as the
//     signed-in user's own role, the CLI's as the shared client role. Postgres
//     shows its catalog to every role, so this shows nothing a role could not
//     ask for in SQL; tables and views are the ones the caller holds a
//     privilege on, as the console's table list always showed.
//   - The caller's objects, not the database's machinery: the system schemas
//     are left out, FoxByte's own (bb) is marked so the console can hide it,
//     and what an extension installed (dblink's functions, say) is listed
//     under the extension rather than among the user's own.
//   - A CREATE script is what it would take to make the object again. Postgres
//     writes most of them itself (pg_get_viewdef, pg_get_functiondef,
//     pg_get_constraintdef, pg_get_indexdef, pg_get_triggerdef); a table's is
//     put together here from its columns, constraints, indexes and triggers,
//     as pg_dump does. Grants and ownership are left out.

// CatalogObject is one entry in a branch's catalog.
type CatalogObject struct {
	Kind   string `json:"kind"` // schema, table, view, sequence, function, procedure, type, extension
	OID    uint32 `json:"oid"`
	Schema string `json:"schema,omitempty"`
	Name   string `json:"name"`
	// Args tells overloaded functions apart: integer, text.
	Args string `json:"args,omitempty"`
	// Sub says more about the kind: partitioned, foreign, materialized,
	// enum, composite, domain, range, or an extension's version.
	Sub    string `json:"sub,omitempty"`
	System bool   `json:"system,omitempty"` // FoxByte's own (the bb schemas)
}

// Catalog is a branch's objects.
type Catalog struct {
	Objects []CatalogObject `json:"objects"`
}

// ObjectDetail is one object, with what it is made of and its CREATE script.
type ObjectDetail struct {
	CatalogObject
	Comment     string          `json:"comment,omitempty"`
	Columns     []CatalogCol    `json:"columns,omitempty"`
	Constraints []CatalogPart   `json:"constraints,omitempty"`
	Indexes     []CatalogPart   `json:"indexes,omitempty"`
	Triggers    []CatalogPart   `json:"triggers,omitempty"`
	Facts       [][2]string     `json:"facts,omitempty"`  // label, value: a function's language, a sequence's range…
	Values      []string        `json:"values,omitempty"` // an enum's labels
	DDL         string          `json:"ddl"`
	Members     []CatalogMember `json:"members,omitempty"` // what an extension installed
	// Params are a function's or a procedure's arguments, in order, for a
	// form that calls it (point 12.4).
	Params []FuncParam `json:"params,omitempty"`
	// Routine is what an edit dialog needs to write a function or procedure
	// again without losing anything it was not asked to change (point 12.3).
	Routine *RoutineInfo `json:"routine,omitempty"`
}

// RoutineInfo is a function or a procedure, attribute by attribute.
type RoutineInfo struct {
	Arguments string `json:"arguments"` // as declared, defaults included
	Identity  string `json:"identity"`  // as ALTER and DROP name it
	Returns   string `json:"returns,omitempty"`
	Language  string `json:"language"`
	Body      string `json:"body"`
	// Atomic: written with BEGIN ATOMIC, which has no body as text to edit.
	Atomic     bool     `json:"atomic,omitempty"`
	Volatility string   `json:"volatility"` // immutable, stable, volatile
	Strict     bool     `json:"strict,omitempty"`
	Definer    bool     `json:"definer,omitempty"`
	Leakproof  bool     `json:"leakproof,omitempty"`
	Window     bool     `json:"window,omitempty"`
	Parallel   string   `json:"parallel"` // safe, restricted, unsafe
	Cost       float64  `json:"cost"`
	Rows       float64  `json:"rows,omitempty"`
	Set        []string `json:"set,omitempty"` // each SET clause, as Postgres writes it
	Trigger    bool     `json:"trigger,omitempty"`
}

// FuncParam is one argument of a function or a procedure.
type FuncParam struct {
	Name string `json:"name,omitempty"` // "" when it has none
	Type string `json:"type"`
	// Mode is in, out, inout, variadic or table (a RETURNS TABLE column).
	Mode string `json:"mode"`
	// Default: an input that may be left out, taking the default it was
	// declared with.
	Default bool `json:"default,omitempty"`
}

// CatalogCol is a column of a table, a view or a composite type.
type CatalogCol struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	NotNull   bool   `json:"not_null,omitempty"`
	Default   string `json:"default,omitempty"`
	Identity  string `json:"identity,omitempty"`  // always or by default
	Generated string `json:"generated,omitempty"` // the expression of a generated column
	Comment   string `json:"comment,omitempty"`
}

// CatalogPart is a constraint, an index or a trigger, with its definition.
type CatalogPart struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"` // primary key, unique, foreign key, check, exclusion; or for an index, unique/primary
	Def  string `json:"def"`
	// Constraint marks an index that backs a constraint, which the constraint's
	// own definition already creates.
	Constraint bool `json:"constraint,omitempty"`
	// System marks a trigger FoxByte installed (the Blackbox's), as opposed to one of the user's.
	System   bool `json:"system,omitempty"`
	Disabled bool `json:"disabled,omitempty"`
	// Trigger is a trigger's parts, for the dialog that edits it (point 12.3).
	Trigger *TriggerInfo `json:"trigger,omitempty"`
}

// TriggerInfo is a trigger, part by part.
type TriggerInfo struct {
	Timing      string   `json:"timing"` // BEFORE, AFTER, INSTEAD OF
	Events      []string `json:"events"` // INSERT, UPDATE, DELETE, TRUNCATE
	Columns     []string `json:"columns,omitempty"`
	ForEach     string   `json:"forEach"` // ROW or STATEMENT
	When        string   `json:"when,omitempty"`
	Function    string   `json:"function"`       // schema-qualified and quoted
	Args        string   `json:"args,omitempty"` // as written between the parentheses
	Referencing string   `json:"referencing,omitempty"`
	// Constraint: a CONSTRAINT TRIGGER, which CREATE OR REPLACE cannot replace.
	Constraint bool `json:"constraint,omitempty"`
}

// The bits of pg_trigger.tgtype.
const (
	tgRow      = 1 << 0
	tgBefore   = 1 << 1
	tgInsert   = 1 << 2
	tgDelete   = 1 << 3
	tgUpdate   = 1 << 4
	tgTruncate = 1 << 5
	tgInstead  = 1 << 6
)

// triggerInfo reads a trigger's parts from its type bits, and what only its
// definition holds (the WHEN condition, the arguments, REFERENCING) from the
// text pg_get_triggerdef writes.
func triggerInfo(tgtype int, columns []string, function string, constraint bool, def string) *TriggerInfo {
	t := &TriggerInfo{Timing: "AFTER", ForEach: "STATEMENT", Columns: columns, Function: function, Constraint: constraint, Events: []string{}}
	switch {
	case tgtype&tgBefore != 0:
		t.Timing = "BEFORE"
	case tgtype&tgInstead != 0:
		t.Timing = "INSTEAD OF"
	}
	if tgtype&tgRow != 0 {
		t.ForEach = "ROW"
	}
	for _, e := range []struct {
		bit  int
		name string
	}{{tgInsert, "INSERT"}, {tgUpdate, "UPDATE"}, {tgDelete, "DELETE"}, {tgTruncate, "TRUNCATE"}} {
		if tgtype&e.bit != 0 {
			t.Events = append(t.Events, e.name)
		}
	}
	exec := strings.LastIndex(def, " EXECUTE FUNCTION ")
	if exec < 0 {
		return t
	}
	head := def[:exec]
	if w := strings.Index(head, " WHEN ("); w >= 0 && strings.HasSuffix(head, ")") {
		t.When = head[w+len(" WHEN (") : len(head)-1]
		head = head[:w]
	}
	if r := strings.Index(head, " REFERENCING "); r >= 0 {
		if f := strings.Index(head[r:], " FOR EACH "); f >= 0 {
			t.Referencing = head[r+len(" REFERENCING ") : r+f]
		}
	}
	call := def[exec+len(" EXECUTE FUNCTION "):]
	if o := strings.Index(call, "("); o >= 0 && strings.HasSuffix(call, ")") {
		t.Args = call[o+1 : len(call)-1]
	}
	return t
}

// setClauses are the SET lines of a pg_get_functiondef text, as Postgres
// writes them: search_path's list quoting is its own to get right.
func setClauses(def string) []string {
	var out []string
	for _, l := range strings.Split(def, "\n") {
		if strings.HasPrefix(l, "AS ") || strings.HasPrefix(l, "BEGIN ATOMIC") {
			break
		}
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "SET ") {
			out = append(out, t)
		}
	}
	return out
}

// CatalogMember is something an extension installed.
type CatalogMember struct {
	Kind, Name string
}

// ErrNoObject means there is no such object, or not one the caller may see.
var ErrNoObject = errors.New("no such object on this branch")

// The schemas Postgres keeps for itself, never shown; nor the engine's private
// one (application identity's secret), which no client may use.
const userSchemas = `n.nspname NOT IN ('pg_catalog', 'information_schema', 'bb_f1') AND n.nspname NOT LIKE 'pg\_%'`

// notExtensionMember leaves out what an extension installed, and what
// Postgres made as part of something else (a range type's constructor
// functions, an identity column's sequence): those are the other object, not
// objects of their own. %s is the object's catalog and oid column, e.g.
// 'pg_proc'::regclass, p.oid.
// (A partitioned table depends internally on its own key columns, which is not
// being part of something else; hence the last clause.)
const notExtensionMember = `NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = %[1]s AND d.objid = %[2]s
	AND d.deptype IN ('e', 'i') AND NOT (d.refclassid = %[1]s AND d.refobjid = %[2]s))`

func isSystemSchema(s string) bool { return s == "bb" || strings.HasPrefix(s, "bb_") }

// readOnly runs fn in a read-only transaction.
func readOnly(ctx context.Context, conn *pgx.Conn, fn func(pgx.Tx) error) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	return fn(tx)
}

// readCatalog lists a branch's objects.
func readCatalog(ctx context.Context, conn *pgx.Conn) (Catalog, error) {
	var out Catalog
	err := readOnly(ctx, conn, func(tx pgx.Tx) error {
		add := func(q string, scan func(pgx.Rows) (CatalogObject, error)) error {
			rows, err := tx.Query(ctx, q)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				o, err := scan(rows)
				if err != nil {
					return err
				}
				o.System = o.System || isSystemSchema(o.Schema)
				out.Objects = append(out.Objects, o)
			}
			return rows.Err()
		}
		if err := add(`SELECT n.oid, n.nspname FROM pg_namespace n WHERE `+userSchemas+` ORDER BY n.nspname`,
			func(r pgx.Rows) (CatalogObject, error) {
				o := CatalogObject{Kind: "schema"}
				err := r.Scan(&o.OID, &o.Name)
				o.System = isSystemSchema(o.Name)
				return o, err
			}); err != nil {
			return err
		}
		// Tables and views the caller holds any privilege on, as
		// information_schema.tables lists them; sequences they may use.
		if err := add(`SELECT c.oid, n.nspname, c.relname, c.relkind::text FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE `+userSchemas+` AND c.relkind IN ('r','p','f','v','m','S') AND NOT c.relispartition
			  AND `+fmt.Sprintf(notExtensionMember, `'pg_class'::regclass`, `c.oid`)+`
			  AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(c.oid, 'USAGE,SELECT,UPDATE')
			           ELSE has_table_privilege(c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') END
			ORDER BY n.nspname, c.relname`,
			func(r pgx.Rows) (CatalogObject, error) {
				var o CatalogObject
				var k string
				err := r.Scan(&o.OID, &o.Schema, &o.Name, &k)
				o.Kind, o.Sub = relKind(k)
				return o, err
			}); err != nil {
			return err
		}
		if err := add(`SELECT p.oid, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), p.prokind::text, p.prorettype = 'trigger'::regtype FROM pg_proc p
			JOIN pg_namespace n ON n.oid = p.pronamespace
			WHERE `+userSchemas+` AND p.prokind IN ('f','p')
			  AND `+fmt.Sprintf(notExtensionMember, `'pg_proc'::regclass`, `p.oid`)+`
			ORDER BY n.nspname, p.proname, 4`,
			func(r pgx.Rows) (CatalogObject, error) {
				var o CatalogObject
				var k string
				var trig bool
				err := r.Scan(&o.OID, &o.Schema, &o.Name, &o.Args, &k, &trig)
				o.Kind = map[string]string{"f": "function", "p": "procedure"}[k]
				if trig {
					o.Sub = "trigger" // what a trigger's dialog offers (point 12.3)
				}
				return o, err
			}); err != nil {
			return err
		}
		// Types someone made: enums, composite types (not a table's own row
		// type), domains and ranges (not the multiranges Postgres makes with them).
		if err := add(`SELECT t.oid, n.nspname, t.typname, t.typtype::text FROM pg_type t
			JOIN pg_namespace n ON n.oid = t.typnamespace
			WHERE `+userSchemas+` AND t.typtype IN ('e','c','d','r')
			  AND (t.typtype <> 'c' OR (SELECT c.relkind FROM pg_class c WHERE c.oid = t.typrelid) = 'c')
			  AND `+fmt.Sprintf(notExtensionMember, `'pg_type'::regclass`, `t.oid`)+`
			ORDER BY n.nspname, t.typname`,
			func(r pgx.Rows) (CatalogObject, error) {
				o := CatalogObject{Kind: "type"}
				var k string
				err := r.Scan(&o.OID, &o.Schema, &o.Name, &k)
				o.Sub = map[string]string{"e": "enum", "c": "composite", "d": "domain", "r": "range"}[k]
				return o, err
			}); err != nil {
			return err
		}
		return add(`SELECT e.oid, n.nspname, e.extname, e.extversion FROM pg_extension e
			JOIN pg_namespace n ON n.oid = e.extnamespace ORDER BY e.extname`,
			func(r pgx.Rows) (CatalogObject, error) {
				o := CatalogObject{Kind: "extension"}
				err := r.Scan(&o.OID, &o.Schema, &o.Name, &o.Sub)
				return o, err
			})
	})
	return out, err
}

func relKind(k string) (kind, sub string) {
	switch k {
	case "r":
		return "table", ""
	case "p":
		return "table", "partitioned"
	case "f":
		return "table", "foreign"
	case "v":
		return "view", ""
	case "m":
		return "view", "materialized"
	case "S":
		return "sequence", ""
	}
	return k, ""
}

// readObject reads one object, its parts and its CREATE script. It answers
// ErrNoObject for an object the caller's catalog does not list, so a guessed
// oid reaches no further than the list does.
func readObject(ctx context.Context, conn *pgx.Conn, kind string, oid uint32) (ObjectDetail, error) {
	cat, err := readCatalog(ctx, conn)
	if err != nil {
		return ObjectDetail{}, err
	}
	var d ObjectDetail
	found := false
	for _, o := range cat.Objects {
		if o.Kind == kind && o.OID == oid {
			d.CatalogObject, found = o, true
			break
		}
	}
	if !found {
		return d, ErrNoObject
	}
	err = readOnly(ctx, conn, func(tx pgx.Tx) error {
		switch kind {
		case "schema":
			_ = tx.QueryRow(ctx, `SELECT coalesce(obj_description($1::oid, 'pg_namespace'), '')`, oid).Scan(&d.Comment)
			d.DDL = "CREATE SCHEMA " + quoteIdentIfNeeded(d.Name) + ";\n"
			return nil
		case "table", "view":
			return readRelation(ctx, tx, &d)
		case "sequence":
			return readSequence(ctx, tx, &d)
		case "function", "procedure":
			return readFunction(ctx, tx, &d)
		case "type":
			return readType(ctx, tx, &d)
		case "extension":
			return readExtension(ctx, tx, &d)
		}
		return ErrNoObject
	})
	if d.Comment != "" && kind != "extension" {
		d.DDL += commentDDL(d)
	}
	return d, err
}

func qualified(schema, name string) string {
	return quoteIdentIfNeeded(schema) + "." + quoteIdentIfNeeded(name)
}

func sqlString(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func commentDDL(d ObjectDetail) string {
	what := map[string]string{"table": "TABLE", "view": "VIEW", "sequence": "SEQUENCE", "function": "FUNCTION",
		"procedure": "PROCEDURE", "type": "TYPE", "schema": "SCHEMA"}[d.Kind]
	if d.Kind == "view" && d.Sub == "materialized" {
		what = "MATERIALIZED VIEW"
	}
	if d.Kind == "table" && d.Sub == "foreign" {
		what = "FOREIGN TABLE"
	}
	if d.Kind == "type" && d.Sub == "domain" {
		what = "DOMAIN"
	}
	target := qualified(d.Schema, d.Name)
	if d.Kind == "schema" {
		target = quoteIdentIfNeeded(d.Name)
	}
	if d.Kind == "function" || d.Kind == "procedure" {
		target += "(" + d.Args + ")"
	}
	return fmt.Sprintf("\nCOMMENT ON %s %s IS %s;\n", what, target, sqlString(d.Comment))
}

func readColumns(ctx context.Context, tx pgx.Tx, rel uint32) ([]CatalogCol, error) {
	rows, err := tx.Query(ctx, `SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
		  coalesce(CASE WHEN a.attgenerated = '' THEN pg_get_expr(d.adbin, d.adrelid) END, ''),
		  a.attidentity::text,
		  coalesce(CASE WHEN a.attgenerated <> '' THEN pg_get_expr(d.adbin, d.adrelid) END, ''),
		  coalesce(col_description(a.attrelid, a.attnum), '')
		FROM pg_attribute a
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attnum`, rel)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CatalogCol
	for rows.Next() {
		var c CatalogCol
		var ident string
		if err := rows.Scan(&c.Name, &c.Type, &c.NotNull, &c.Default, &ident, &c.Generated, &c.Comment); err != nil {
			return nil, err
		}
		c.Identity = map[string]string{"a": "always", "d": "by default"}[ident]
		out = append(out, c)
	}
	return out, rows.Err()
}

func readRelation(ctx context.Context, tx pgx.Tx, d *ObjectDetail) error {
	var err error
	if d.Columns, err = readColumns(ctx, tx, d.OID); err != nil {
		return err
	}
	_ = tx.QueryRow(ctx, `SELECT coalesce(obj_description($1::oid, 'pg_class'), '')`, d.OID).Scan(&d.Comment)
	if d.Kind == "view" {
		var def string
		if err := tx.QueryRow(ctx, `SELECT pg_get_viewdef($1::oid, true)`, d.OID).Scan(&def); err != nil {
			return err
		}
		head := "CREATE OR REPLACE VIEW "
		if d.Sub == "materialized" {
			head = "CREATE MATERIALIZED VIEW "
		}
		d.DDL = head + qualified(d.Schema, d.Name) + " AS\n" + strings.TrimRight(def, "; \n") + ";\n"
		if d.Sub == "materialized" {
			if err := readIndexes(ctx, tx, d); err != nil {
				return err
			}
			for _, ix := range d.Indexes {
				d.DDL += "\n" + ix.Def + ";\n"
			}
		}
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT conname, contype::text, pg_get_constraintdef(oid, true) FROM pg_constraint
		WHERE conrelid = $1::oid AND contype <> 'n'
		ORDER BY array_position(ARRAY['p','u','f','c','x'], contype::text), conname`, d.OID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p CatalogPart
		var k string
		if err := rows.Scan(&p.Name, &k, &p.Def); err != nil {
			rows.Close()
			return err
		}
		p.Kind = map[string]string{"p": "primary key", "u": "unique", "f": "foreign key", "c": "check", "x": "exclusion"}[k]
		d.Constraints = append(d.Constraints, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := readIndexes(ctx, tx, d); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT t.tgname, pg_get_triggerdef(t.oid, true), t.tgenabled = 'D',
		  pn.nspname = 'bb' OR pn.nspname LIKE 'bb\_%', t.tgtype::int, t.tgconstraint <> 0,
		  format('%I.%I', pn.nspname, p.proname),
		  coalesce((SELECT array_agg(a.attname::text ORDER BY k.o) FROM unnest(t.tgattr::int2[]) WITH ORDINALITY AS k(n, o)
		             JOIN pg_attribute a ON a.attrelid = t.tgrelid AND a.attnum = k.n), '{}')
		FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid JOIN pg_namespace pn ON pn.oid = p.pronamespace
		WHERE t.tgrelid = $1::oid AND NOT t.tgisinternal ORDER BY t.tgname`, d.OID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var p CatalogPart
		var tgtype int
		var constraint bool
		var fn string
		var cols []string
		if err := rows.Scan(&p.Name, &p.Def, &p.Disabled, &p.System, &tgtype, &constraint, &fn, &cols); err != nil {
			rows.Close()
			return err
		}
		p.Trigger = triggerInfo(tgtype, cols, fn, constraint, p.Def)
		d.Triggers = append(d.Triggers, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var partKey, server string
	var partitions []string
	if d.Sub == "partitioned" {
		_ = tx.QueryRow(ctx, `SELECT pg_get_partkeydef($1::oid)`, d.OID).Scan(&partKey)
		// Its partitions, which the list leaves out as tables of their own:
		// they are this table's, and its script makes them.
		rows, err := tx.Query(ctx, `SELECT format('%I.%I', n.nspname, c.relname), pg_get_expr(c.relpartbound, c.oid)
			FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE i.inhparent = $1::oid ORDER BY 1`, d.OID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name, bound string
			if err := rows.Scan(&name, &bound); err != nil {
				rows.Close()
				return err
			}
			d.Facts = append(d.Facts, [2]string{"partition", name + " " + bound})
			partitions = append(partitions, "CREATE TABLE "+name+" PARTITION OF "+qualified(d.Schema, d.Name)+" "+bound+";\n")
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	if d.Sub == "foreign" {
		_ = tx.QueryRow(ctx, `SELECT s.srvname FROM pg_foreign_table f JOIN pg_foreign_server s ON s.oid = f.ftserver WHERE f.ftrelid = $1::oid`, d.OID).Scan(&server)
	}
	d.DDL = tableDDL(*d, partKey, server)
	for _, p := range partitions {
		d.DDL += "\n" + p
	}
	return nil
}

func readIndexes(ctx context.Context, tx pgx.Tx, d *ObjectDetail) error {
	rows, err := tx.Query(ctx, `SELECT c.relname, pg_get_indexdef(i.indexrelid), i.indisprimary, i.indisunique,
		  EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = i.indexrelid AND k.conrelid = i.indrelid)
		FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
		WHERE i.indrelid = $1::oid ORDER BY c.relname`, d.OID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var p CatalogPart
		var primary, unique bool
		if err := rows.Scan(&p.Name, &p.Def, &primary, &unique, &p.Constraint); err != nil {
			return err
		}
		switch {
		case primary:
			p.Kind = "primary"
		case unique:
			p.Kind = "unique"
		}
		d.Indexes = append(d.Indexes, p)
	}
	return rows.Err()
}

// tableDDL writes a table's CREATE script: its columns, then its constraints
// inside the CREATE TABLE, then the indexes no constraint already made, the
// triggers that are the user's own, and the column comments. Triggers FoxByte
// installed are left out: FoxByte puts them on any table it records.
func tableDDL(d ObjectDetail, partKey, server string) string {
	var b strings.Builder
	head := "CREATE TABLE "
	if d.Sub == "foreign" {
		head = "CREATE FOREIGN TABLE "
	}
	b.WriteString(head + qualified(d.Schema, d.Name) + " (\n")
	var lines []string
	for _, c := range d.Columns {
		l := "    " + quoteIdentIfNeeded(c.Name) + " " + c.Type
		switch {
		case c.Generated != "":
			l += " GENERATED ALWAYS AS (" + c.Generated + ") STORED"
		case c.Identity != "":
			l += " GENERATED " + strings.ToUpper(c.Identity) + " AS IDENTITY"
		case c.Default != "":
			l += " DEFAULT " + c.Default
		}
		if c.NotNull && c.Identity == "" {
			l += " NOT NULL"
		}
		lines = append(lines, l)
	}
	for _, k := range d.Constraints {
		lines = append(lines, "    CONSTRAINT "+quoteIdentIfNeeded(k.Name)+" "+k.Def)
	}
	b.WriteString(strings.Join(lines, ",\n"))
	b.WriteString("\n)")
	if partKey != "" {
		b.WriteString(" PARTITION BY " + partKey)
	}
	if server != "" {
		b.WriteString(" SERVER " + quoteIdentIfNeeded(server))
	}
	b.WriteString(";\n")
	for _, ix := range d.Indexes {
		if !ix.Constraint {
			b.WriteString("\n" + ix.Def + ";\n")
		}
	}
	for _, t := range d.Triggers {
		if t.System {
			continue
		}
		b.WriteString("\n" + t.Def + ";\n")
		if t.Disabled {
			b.WriteString("ALTER TABLE " + qualified(d.Schema, d.Name) + " DISABLE TRIGGER " + quoteIdentIfNeeded(t.Name) + ";\n")
		}
	}
	for _, c := range d.Columns {
		if c.Comment != "" {
			b.WriteString("\nCOMMENT ON COLUMN " + qualified(d.Schema, d.Name) + "." + quoteIdentIfNeeded(c.Name) + " IS " + sqlString(c.Comment) + ";\n")
		}
	}
	return b.String()
}

func readSequence(ctx context.Context, tx pgx.Tx, d *ObjectDetail) error {
	var typ string
	var start, inc, minv, maxv, cache int64
	var cycle bool
	if err := tx.QueryRow(ctx, `SELECT format_type(seqtypid, NULL), seqstart, seqincrement, seqmin, seqmax, seqcache, seqcycle
		FROM pg_sequence WHERE seqrelid = $1::oid`, d.OID).Scan(&typ, &start, &inc, &minv, &maxv, &cache, &cycle); err != nil {
		return err
	}
	_ = tx.QueryRow(ctx, `SELECT coalesce(obj_description($1::oid, 'pg_class'), '')`, d.OID).Scan(&d.Comment)
	var owner string
	_ = tx.QueryRow(ctx, `SELECT format('%s.%I', d.refobjid::regclass, a.attname) FROM pg_depend d
		JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
		WHERE d.classid = 'pg_class'::regclass AND d.objid = $1::oid AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a','i')`, d.OID).Scan(&owner)
	cyc := "NO CYCLE"
	if cycle {
		cyc = "CYCLE"
	}
	d.Facts = [][2]string{{"type", typ}, {"start", fmt.Sprint(start)}, {"increment", fmt.Sprint(inc)},
		{"minimum", fmt.Sprint(minv)}, {"maximum", fmt.Sprint(maxv)}, {"cache", fmt.Sprint(cache)}, {"cycle", fmt.Sprint(cycle)}}
	if owner != "" {
		d.Facts = append(d.Facts, [2]string{"owned by", owner})
	}
	d.DDL = fmt.Sprintf("CREATE SEQUENCE %s\n    AS %s\n    START WITH %d\n    INCREMENT BY %d\n    MINVALUE %d\n    MAXVALUE %d\n    CACHE %d\n    %s;\n",
		qualified(d.Schema, d.Name), typ, start, inc, minv, maxv, cache, cyc)
	return nil
}

func readFunction(ctx context.Context, tx pgx.Tx, d *ObjectDetail) error {
	var def, lang, args, result, vol string
	if err := tx.QueryRow(ctx, `SELECT pg_get_functiondef(p.oid), l.lanname, pg_get_function_arguments(p.oid),
		  coalesce(pg_get_function_result(p.oid), ''), p.provolatile::text, coalesce(obj_description(p.oid, 'pg_proc'), '')
		FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang WHERE p.oid = $1::oid`, d.OID).Scan(&def, &lang, &args, &result, &vol, &d.Comment); err != nil {
		return err
	}
	d.Facts = [][2]string{{"arguments", args}}
	if d.Kind == "function" {
		d.Facts = append(d.Facts, [2]string{"returns", result},
			[2]string{"volatility", map[string]string{"i": "immutable", "s": "stable", "v": "volatile"}[vol]})
	}
	d.Facts = append(d.Facts, [2]string{"language", lang})
	d.DDL = strings.TrimRight(def, "\n") + ";\n"
	r := &RoutineInfo{Arguments: args, Returns: result, Language: lang, Set: setClauses(def),
		Volatility: map[string]string{"i": "immutable", "s": "stable", "v": "volatile"}[vol]}
	var parallel string
	if err := tx.QueryRow(ctx, `SELECT pg_get_function_identity_arguments(p.oid), p.prosrc, p.prosqlbody IS NOT NULL, p.proisstrict, p.prosecdef,
		  p.proleakproof, p.prokind = 'w', p.proparallel::text, p.procost::float8, p.prorows::float8, p.prorettype = 'trigger'::regtype
		FROM pg_proc p WHERE p.oid = $1::oid`, d.OID).Scan(&r.Identity, &r.Body, &r.Atomic, &r.Strict, &r.Definer,
		&r.Leakproof, &r.Window, &parallel, &r.Cost, &r.Rows, &r.Trigger); err != nil {
		return err
	}
	r.Parallel = map[string]string{"s": "safe", "r": "restricted", "u": "unsafe"}[parallel]
	d.Routine = r
	return readParams(ctx, tx, d)
}

// paramsSQL reads a function's arguments: every one, with its mode and name,
// and how many inputs at the end have defaults.
const paramsSQL = `SELECT coalesce(json_agg(json_build_object('name', coalesce(a.n, ''), 'type', format_type(a.t, NULL), 'mode', a.m) ORDER BY a.o)
         FILTER (WHERE a.o IS NOT NULL), '[]'::json),
       p.pronargdefaults
  FROM pg_proc p
  LEFT JOIN LATERAL unnest(coalesce(p.proallargtypes, p.proargtypes::oid[]),
                          coalesce(p.proargmodes, array_fill('i'::"char", ARRAY[cardinality(p.proargtypes::oid[])])),
                          coalesce(p.proargnames, array_fill(''::text, ARRAY[cardinality(coalesce(p.proallargtypes, p.proargtypes::oid[]))])))
         WITH ORDINALITY AS a(t, m, n, o) ON true
 WHERE p.oid = $1::oid
 GROUP BY p.pronargdefaults`

func readParams(ctx context.Context, tx pgx.Tx, d *ObjectDetail) error {
	var raw []byte
	var defaults int
	if err := tx.QueryRow(ctx, paramsSQL, d.OID).Scan(&raw, &defaults); err != nil {
		return err
	}
	var ps []struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &ps); err != nil {
		return err
	}
	modes := map[string]string{"i": "in", "o": "out", "b": "inout", "v": "variadic", "t": "table"}
	for _, p := range ps {
		d.Params = append(d.Params, FuncParam{Name: p.Name, Type: p.Type, Mode: modes[p.Mode]})
	}
	markDefaults(d.Params, defaults)
	return nil
}

// markDefaults marks the last n inputs as having defaults, as pronargdefaults
// counts them: OUT and TABLE arguments are not inputs.
func markDefaults(ps []FuncParam, n int) {
	for i := len(ps) - 1; i >= 0 && n > 0; i-- {
		if m := ps[i].Mode; m == "in" || m == "inout" || m == "variadic" {
			ps[i].Default = true
			n--
		}
	}
}

func readType(ctx context.Context, tx pgx.Tx, d *ObjectDetail) error {
	_ = tx.QueryRow(ctx, `SELECT coalesce(obj_description($1::oid, 'pg_type'), '')`, d.OID).Scan(&d.Comment)
	q := qualified(d.Schema, d.Name)
	switch d.Sub {
	case "enum":
		rows, err := tx.Query(ctx, `SELECT enumlabel FROM pg_enum WHERE enumtypid = $1::oid ORDER BY enumsortorder`, d.OID)
		if err != nil {
			return err
		}
		defer rows.Close()
		var labels []string
		for rows.Next() {
			var l string
			if err := rows.Scan(&l); err != nil {
				return err
			}
			d.Values = append(d.Values, l)
			labels = append(labels, sqlString(l))
		}
		d.DDL = "CREATE TYPE " + q + " AS ENUM (" + strings.Join(labels, ", ") + ");\n"
		return rows.Err()
	case "composite":
		var rel uint32
		if err := tx.QueryRow(ctx, `SELECT typrelid FROM pg_type WHERE oid = $1::oid`, d.OID).Scan(&rel); err != nil {
			return err
		}
		cols, err := readColumns(ctx, tx, rel)
		if err != nil {
			return err
		}
		d.Columns = cols
		var fs []string
		for _, c := range cols {
			fs = append(fs, "    "+quoteIdentIfNeeded(c.Name)+" "+c.Type)
		}
		d.DDL = "CREATE TYPE " + q + " AS (\n" + strings.Join(fs, ",\n") + "\n);\n"
		return nil
	case "domain":
		var base, def string
		var notNull bool
		if err := tx.QueryRow(ctx, `SELECT format_type(typbasetype, typtypmod), typnotnull, coalesce(typdefault, '') FROM pg_type WHERE oid = $1::oid`,
			d.OID).Scan(&base, &notNull, &def); err != nil {
			return err
		}
		d.Facts = [][2]string{{"base type", base}}
		ddl := "CREATE DOMAIN " + q + " AS " + base
		if def != "" {
			ddl += "\n    DEFAULT " + def
			d.Facts = append(d.Facts, [2]string{"default", def})
		}
		if notNull {
			ddl += "\n    NOT NULL"
			d.Facts = append(d.Facts, [2]string{"not null", "true"})
		}
		rows, err := tx.Query(ctx, `SELECT conname, pg_get_constraintdef(oid, true) FROM pg_constraint WHERE contypid = $1::oid AND contype = 'c' ORDER BY conname`, d.OID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p CatalogPart
			if err := rows.Scan(&p.Name, &p.Def); err != nil {
				return err
			}
			p.Kind = "check"
			d.Constraints = append(d.Constraints, p)
			ddl += "\n    CONSTRAINT " + quoteIdentIfNeeded(p.Name) + " " + p.Def
		}
		d.DDL = ddl + ";\n"
		return rows.Err()
	case "range":
		var sub string
		if err := tx.QueryRow(ctx, `SELECT format_type(rngsubtype, NULL) FROM pg_range WHERE rngtypid = $1::oid`, d.OID).Scan(&sub); err != nil {
			return err
		}
		d.Facts = [][2]string{{"subtype", sub}}
		d.DDL = "CREATE TYPE " + q + " AS RANGE (SUBTYPE = " + sub + ");\n"
		return nil
	}
	return nil
}

func readExtension(ctx context.Context, tx pgx.Tx, d *ObjectDetail) error {
	_ = tx.QueryRow(ctx, `SELECT coalesce(obj_description($1::oid, 'pg_extension'), '')`, d.OID).Scan(&d.Comment)
	d.Facts = [][2]string{{"version", d.Sub}, {"schema", d.Schema}}
	d.DDL = fmt.Sprintf("CREATE EXTENSION IF NOT EXISTS %s WITH SCHEMA %s VERSION %s;\n",
		quoteIdentIfNeeded(d.Name), quoteIdentIfNeeded(d.Schema), sqlString(d.Sub))
	rows, err := tx.Query(ctx, `SELECT CASE d.classid WHEN 'pg_proc'::regclass THEN 'function' WHEN 'pg_class'::regclass THEN 'relation'
		  WHEN 'pg_type'::regclass THEN 'type' ELSE 'other' END, pg_describe_object(d.classid, d.objid, 0)
		FROM pg_depend d WHERE d.refclassid = 'pg_extension'::regclass AND d.refobjid = $1::oid AND d.deptype = 'e'
		ORDER BY 1, 2 LIMIT 500`, d.OID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var m CatalogMember
		if err := rows.Scan(&m.Kind, &m.Name); err != nil {
			return err
		}
		d.Members = append(d.Members, m)
	}
	return rows.Err()
}

// BranchCatalog is `fox schema`: a branch's objects, read as the shared client
// role, labelled for the Blackbox like `fox sql`.
func BranchCatalog(branchName, label string) (Catalog, error) {
	var out Catalog
	err := withCLISession(branchName, label, func(ctx context.Context, conn *pgx.Conn) error {
		var err error
		out, err = readCatalog(ctx, conn)
		return err
	})
	return out, err
}

// BranchObject is `fox schema <object>`: one object, its parts and its CREATE script.
func BranchObject(branchName, label, kind string, oid uint32) (ObjectDetail, error) {
	var out ObjectDetail
	err := withCLISession(branchName, label, func(ctx context.Context, conn *pgx.Conn) error {
		var err error
		out, err = readObject(ctx, conn, kind, oid)
		return err
	})
	return out, err
}

func withCLISession(branchName, label string, fn func(context.Context, *pgx.Conn) error) error {
	addr, err := branch.EnsureRunning(branchName)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := openSession(ctx, addr, queryAs{Branch: branchName, Label: label, App: "fox schema"})
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	return fn(ctx, conn)
}

// handleCatalog is GET /api/branches/{name}/schema: the branch's objects, read
// as the signed-in user.
func handleCatalog(w http.ResponseWriter, r *http.Request) {
	withUserSession(w, r, func(ctx context.Context, conn *pgx.Conn) {
		c, err := readCatalog(ctx, conn)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, c)
	})
}

// handleCatalogObject is GET /api/branches/{name}/schema/{kind}/{oid}: one
// object, its parts and its CREATE script.
func handleCatalogObject(w http.ResponseWriter, r *http.Request) {
	oid, err := strconv.ParseUint(r.PathValue("oid"), 10, 32)
	if err != nil {
		writeErr(w, 400, fmt.Errorf("oid must be a number"))
		return
	}
	withUserSession(w, r, func(ctx context.Context, conn *pgx.Conn) {
		d, err := readObject(ctx, conn, r.PathValue("kind"), uint32(oid))
		switch {
		case errors.Is(err, ErrNoObject):
			writeErr(w, 404, err)
		case err != nil:
			writeErr(w, 500, err)
		default:
			writeJSON(w, 200, d)
		}
	})
}

func withUserSession(w http.ResponseWriter, r *http.Request, fn func(context.Context, *pgx.Conn)) {
	name := r.PathValue("name")
	addr, err := branch.EnsureRunning(name)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	conn, err := openSession(ctx, addr, queryAs{Branch: name, Actor: u.Email})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	defer conn.Close(context.Background())
	fn(ctx, conn)
}
