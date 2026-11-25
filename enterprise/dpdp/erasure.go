//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package dpdp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thefoxbyte/foxbyte/enterprise/pii"
	"github.com/thefoxbyte/foxbyte/enterprise/schema"
	"github.com/thefoxbyte/foxbyte/internal/branch"
)

// Erasure requests' paid half (F4, Gate 1 step 1; docs/FOX_F4_Erasure_Design.md,
// sections 4, 5, 7, 13 and 16): finding the person's rows on a branch, the
// plan, applying it in one transaction, and the vacuum and rewrite after.
//
// Rows are found as `fox subject find` counts them: a column (or JSON path) a
// reviewer confirmed, in the value's category, holding the value compared
// whole and normalised. From those rows the plan follows foreign keys to the
// rows that refer to them, at any depth up to maxDepth (decision 5). A table
// holding confirmed personal data takes its inventory entry's action; one
// holding none is left as it is, unless its foreign key deletes it, or clears
// its reference, with a row the plan deletes. A foreign key that refuses the
// delete stops the plan before anything runs.
//
// Within a run a row is named by its table and its ctid: every table has one,
// with or without a key. The rows are found again, and locked, in the
// transaction that changes them, so a ctid names the same row throughout. The
// request keeps primary keys (or the replica identity's columns), never a
// ctid.

func init() {
	branch.SetErasure(branch.ErasureEngine{Refs: erasureRefs, Plan: erasurePlan, Apply: erasureApply,
		Settle: erasureSettle, AppliedOn: erasureAppliedOn})
}

const (
	// maxDepth is how far along foreign keys a plan follows.
	maxDepth = 10
	// eraseTimeout bounds a plan or an apply's transaction.
	eraseTimeout = 10 * time.Minute
	// rewriteMaxEnv is the size above which a table's rewrite is left for an
	// admin to run at a quiet time (section 7; decision 7).
	rewriteMaxEnv     = "FOX_ERASURE_REWRITE_MAX"
	defaultRewriteMax = int64(1) << 30
)

// --- the values ---------------------------------------------------------------

// matchSet is the values to search for, each category's in the form its
// columns are compared in.
type matchSet map[pii.Category][]string

func readValues(values []branch.ErasureValue) (matchSet, []branch.ErasureRef, error) {
	ms := matchSet{}
	refs := []branch.ErasureRef{}
	seen := map[string]bool{}
	for i, v := range values {
		v.Value = strings.TrimSpace(v.Value)
		if v.Value == "" {
			continue
		}
		cat := pii.Category(strings.TrimSpace(v.Category))
		if cat != "" && !pii.IsCategory(string(cat)) {
			return nil, nil, fmt.Errorf("%w: value %d: %q is not a category this recognises (email, mobile, pan, aadhaar, …)", branch.ErrInvalidRequest, i+1, cat)
		}
		found := pii.SubjectMatches(v.Value, cat)
		if len(found) == 0 {
			return nil, nil, fmt.Errorf("%w: value %d does not look like any kind of personal data this recognises; say which, as category:value",
				branch.ErrInvalidRequest, i+1)
		}
		sort.Slice(found, func(a, b int) bool { return found[a].Category < found[b].Category })
		ref := branch.ErasureRef{Categories: []string{}, Last4: last4(found[0].Value)}
		for _, m := range found {
			ref.Categories = append(ref.Categories, string(m.Category))
			if !contains(ms[m.Category], m.Value) {
				ms[m.Category] = append(ms[m.Category], m.Value)
			}
		}
		k := strings.Join(ref.Categories, "/") + "\x00" + found[0].Value
		if seen[k] {
			continue
		}
		seen[k] = true
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		return nil, nil, fmt.Errorf("%w: give at least one value the person is known by", branch.ErrInvalidRequest)
	}
	return ms, refs, nil
}

// last4 is what a request keeps of a value: its last four characters, or
// two of a value so short that four would be most of it.
func last4(v string) string {
	r := []rune(v)
	n := 4
	if len(r) <= 6 {
		n = 2
	}
	if len(r) < n {
		n = len(r)
	}
	return string(r[len(r)-n:])
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func erasureRefs(values []branch.ErasureValue) ([]branch.ErasureRef, error) {
	_, refs, err := readValues(values)
	return refs, err
}

// --- the catalog ----------------------------------------------------------------

type tkey struct{ schema, table string }

func (k tkey) String() string { return k.schema + "." + k.table }

type colInfo struct {
	typ        string
	notNull    bool
	hasDefault bool
	generated  bool
}

type fkInfo struct {
	name    string
	child   tkey
	cols    []string // the child's columns
	refs    []string // the parent's columns they refer to
	delType byte     // a no action, r restrict, c cascade, n set null, d set default
}

type relInfo struct {
	key     tkey
	rel     string // quoted schema.table
	kind    byte   // r table, p partitioned
	size    int64
	cols    map[string]colInfo
	keyCols []string // the primary key's, else the replica identity's; nil for neither
	inbound []fkInfo
}

type catalog struct {
	ctx  context.Context
	tx   pgx.Tx
	rels map[tkey]*relInfo
}

func (c *catalog) rel(k tkey) (*relInfo, error) {
	if r, ok := c.rels[k]; ok {
		return r, nil
	}
	r := &relInfo{key: k, rel: branch.QuoteIdent(k.schema) + "." + branch.QuoteIdent(k.table), cols: map[string]colInfo{}}
	var oid uint32
	var kind string
	err := c.tx.QueryRow(c.ctx, `SELECT c.oid, c.relkind::text, pg_total_relation_size(c.oid)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2`,
		k.schema, k.table).Scan(&oid, &kind, &r.size)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%s is not a table here any more", k)
	}
	if err != nil {
		return nil, err
	}
	r.kind = kind[0]
	rows, err := c.tx.Query(c.ctx, `SELECT attname, format_type(atttypid, atttypmod), attnotnull, atthasdef, attgenerated <> ''
		FROM pg_attribute WHERE attrelid = $1 AND attnum > 0 AND NOT attisdropped`, oid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n string
		var ci colInfo
		if err := rows.Scan(&n, &ci.typ, &ci.notNull, &ci.hasDefault, &ci.generated); err != nil {
			rows.Close()
			return nil, err
		}
		r.cols[n] = ci
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The primary key, else the replica identity: what names a row once the
	// run is over (section 16).
	err = c.tx.QueryRow(c.ctx, `SELECT array_agg(a.attname ORDER BY k.ord) FROM pg_index i
		CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
		WHERE i.indrelid = $1 AND (i.indisprimary OR i.indisreplident)
		GROUP BY i.indexrelid, i.indisprimary ORDER BY i.indisprimary DESC LIMIT 1`, oid).Scan(&r.keyCols)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	// The foreign keys referring to it. A partitioned table's constraint is
	// read once, on the partitioned table, not again on each partition.
	fks, err := c.tx.Query(c.ctx, `SELECT con.conname, cn.nspname, cc.relname, con.confdeltype::text,
			(SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(con.conkey) WITH ORDINALITY AS k(n, ord)
				JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.n),
			(SELECT array_agg(a.attname ORDER BY k.ord) FROM unnest(con.confkey) WITH ORDINALITY AS k(n, ord)
				JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.n)
		FROM pg_constraint con JOIN pg_class cc ON cc.oid = con.conrelid JOIN pg_namespace cn ON cn.oid = cc.relnamespace
		WHERE con.contype = 'f' AND con.confrelid = $1 AND con.conparentid = 0 ORDER BY con.conname`, oid)
	if err != nil {
		return nil, err
	}
	for fks.Next() {
		var f fkInfo
		var del string
		if err := fks.Scan(&f.name, &f.child.schema, &f.child.table, &del, &f.cols, &f.refs); err != nil {
			fks.Close()
			return nil, err
		}
		f.delType = del[0]
		r.inbound = append(r.inbound, f)
	}
	fks.Close()
	if err := fks.Err(); err != nil {
		return nil, err
	}
	c.rels[k] = r
	return r, nil
}

// keyExpr is the row's key as text, a JSON array, for alias a; NULL for a
// table with neither key.
func (r *relInfo) keyExpr(a string) string {
	if len(r.keyCols) == 0 {
		return "NULL::text"
	}
	parts := make([]string, len(r.keyCols))
	for i, c := range r.keyCols {
		parts[i] = a + "." + branch.QuoteIdent(c) + "::text"
	}
	return "jsonb_build_array(" + strings.Join(parts, ", ") + ")::text"
}

// --- the rows ----------------------------------------------------------------

// rowID names a row for the run: its table's oid (the partition, for a
// partitioned table) and its ctid.
type rowID struct {
	oid  uint32
	ctid string
}

// link is one foreign key a row refers to a person's row through.
type link struct {
	parent tkey
	prow   rowID
	fk     fkInfo
}

type row struct {
	id      rowID
	key     string // JSON array, or "" for a table with neither key
	matched bool
	links   []link
	// fate, decided once every row is found: what the plan does to it.
	fate string
}

type tableRows struct {
	rel      *relInfo
	rows     map[rowID]*row
	order    []rowID
	depth    int
	why      string
	personal bool // the table holds confirmed personal data
	self     []selfRef
}

// selfRef is rows of a table referring, through its own key, to the
// person's rows in it: other rows, perhaps other people's.
type selfRef struct {
	fk   fkInfo
	rows int
}

func (t *tableRows) add(r *row) bool {
	if old, ok := t.rows[r.id]; ok {
		old.matched = old.matched || r.matched
		old.links = append(old.links, r.links...)
		return false
	}
	t.rows[r.id] = r
	t.order = append(t.order, r.id)
	return true
}

// state is one run's view of a branch: its catalog, inventory, and the rows
// found.
type state struct {
	cat      *catalog
	lock     bool
	ms       matchSet
	inv      branch.DPDPInventory
	findings []branch.PIIFinding
	tables   map[tkey]*tableRows
	order    []tkey
	searched int
	limits   []string
	maxDepth bool
}

func (s *state) table(k tkey) (*tableRows, error) {
	if t, ok := s.tables[k]; ok {
		return t, nil
	}
	r, err := s.cat.rel(k)
	if err != nil {
		return nil, err
	}
	t := &tableRows{rel: r, rows: map[rowID]*row{}}
	for _, it := range s.inv.Tables {
		if it.Schema == k.schema && it.Table == k.table {
			t.personal = true
		}
	}
	s.tables[k] = t
	s.order = append(s.order, k)
	return t, nil
}

func (s *state) forUpdate(alias string) string {
	if s.lock {
		return " FOR UPDATE OF " + alias
	}
	return ""
}

// scanRows reads (oid, ctid, key) rows from a query into a table; with l,
// each row also names the parent row it refers to (its oid and ctid).
func (s *state) scanRows(t *tableRows, matched bool, l *link, q string, args ...any) (int, error) {
	rows, err := s.cat.tx.Query(s.cat.ctx, q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	added := 0
	for rows.Next() {
		var r row
		var key *string
		dest := []any{&r.id.oid, &r.id.ctid, &key}
		var p rowID
		if l != nil {
			dest = append(dest, &p.oid, &p.ctid)
		}
		if err := rows.Scan(dest...); err != nil {
			return 0, err
		}
		if key != nil {
			r.key = *key
		}
		r.matched = matched
		if l != nil {
			lk := *l
			lk.prow = p
			r.links = []link{lk}
		}
		if t.add(&r) {
			added++
		}
	}
	return added, rows.Err()
}

// match finds the rows holding a value, in every confirmed place of its
// category.
func (s *state) match() error {
	seen := map[string]bool{}
	for _, f := range s.findings {
		if f.State != branch.PIIConfirmed {
			continue
		}
		vals, ok := s.ms[pii.Category(f.Category)]
		if !ok {
			continue
		}
		k := f.Schema + "\x00" + f.Table + "\x00" + f.Column + "\x00" + f.Path + "\x00" + f.Category
		if seen[k] {
			continue
		}
		seen[k] = true
		s.searched++
		t, err := s.table(tkey{f.Schema, f.Table})
		if err != nil {
			s.limits = append(s.limits, fmt.Sprintf("%s.%s could not be searched: %v", f.Schema, f.Table, err))
			continue
		}
		if _, ok := t.rel.cols[f.Column]; !ok {
			s.limits = append(s.limits, fmt.Sprintf("%s.%s.%s was confirmed but is not a column any more; scan again", f.Schema, f.Table, f.Column))
			continue
		}
		q, args := matchQuery(t.rel, f, vals)
		if _, err := s.scanRows(t, true, nil, q+s.forUpdate("x"), args...); err != nil {
			return fmt.Errorf("searching %s: %w", f.Where(), readErr(err))
		}
	}
	return nil
}

func matchQuery(r *relInfo, f branch.PIIFinding, vals []string) (string, []any) {
	col := "x." + branch.QuoteIdent(f.Column)
	sel := "SELECT x.tableoid, x.ctid::text, " + r.keyExpr("x") + " FROM " + r.rel + " x WHERE "
	if f.Path == "" {
		return sel + pii.SubjectSQL(pii.Category(f.Category), col+"::text") + " = ANY($1::text[])", []any{vals}
	}
	return sel + `EXISTS (SELECT 1 FROM jsonb_path_query(` + col + `::jsonb, $2::jsonpath) AS v
		WHERE jsonb_typeof(v) IN ('string', 'number') AND ` + pii.SubjectSQL(pii.Category(f.Category), "(v #>> '{}')") + ` = ANY($1::text[]))`,
		[]any{vals, f.Path}
}

// follow walks foreign keys from the rows found to the rows referring to
// them, breadth first, each table's new rows once.
func (s *state) follow() error {
	type step struct {
		k     tkey
		ids   []rowID
		depth int
	}
	var queue []step
	for _, k := range s.order {
		t := s.tables[k]
		queue = append(queue, step{k, append([]rowID(nil), t.order...), 0})
	}
	for len(queue) > 0 {
		st := queue[0]
		queue = queue[1:]
		if len(st.ids) == 0 {
			continue
		}
		parent := s.tables[st.k]
		for _, fk := range parent.rel.inbound {
			if fk.child == st.k {
				n, err := s.countSelf(parent, fk, st.ids)
				if err != nil {
					return err
				}
				if n > 0 {
					parent.self = append(parent.self, selfRef{fk: fk, rows: n})
				}
				continue
			}
			if st.depth+1 > maxDepth {
				s.maxDepth = true
				continue
			}
			child, err := s.table(fk.child)
			if err != nil {
				return err
			}
			before := len(child.order)
			if _, err := s.scanRows(child, false, &link{parent: st.k, fk: fk}, s.followQuery(parent.rel, child.rel, fk), oids(st.ids), ctids(st.ids)); err != nil {
				return fmt.Errorf("following %s from %s: %w", fk.name, st.k, readErr(err))
			}
			if child.depth == 0 && !hasMatched(child) {
				child.depth = st.depth + 1
				child.why = fmt.Sprintf("refers to %s (%s)", st.k, fk.name)
			}
			if len(child.order) > before {
				queue = append(queue, step{fk.child, append([]rowID(nil), child.order[before:]...), st.depth + 1})
			}
		}
	}
	return nil
}

func hasMatched(t *tableRows) bool {
	for _, r := range t.rows {
		if r.matched {
			return true
		}
	}
	return false
}

func (s *state) followQuery(parent, child *relInfo, fk fkInfo) string {
	on := make([]string, len(fk.cols))
	for i := range fk.cols {
		on[i] = "c." + branch.QuoteIdent(fk.cols[i]) + " = p." + branch.QuoteIdent(fk.refs[i])
	}
	// No DISTINCT, which FOR UPDATE refuses: a row reached through two
	// parent rows is added once, with both links (tableRows.add).
	return "SELECT c.tableoid, c.ctid::text, " + child.keyExpr("c") + ", p.tableoid, p.ctid::text FROM " + child.rel + " c JOIN " + parent.rel + " p ON " +
		strings.Join(on, " AND ") + " WHERE p.ctid = ANY($2::text[]::tid[]) AND (p.tableoid, p.ctid::text) IN (SELECT * FROM unnest($1::oid[], $2::text[]))" +
		s.forUpdate("c")
}

func (s *state) countSelf(t *tableRows, fk fkInfo, ids []rowID) (int, error) {
	on := make([]string, len(fk.cols))
	for i := range fk.cols {
		on[i] = "c." + branch.QuoteIdent(fk.cols[i]) + " = p." + branch.QuoteIdent(fk.refs[i])
	}
	var n int
	err := s.cat.tx.QueryRow(s.cat.ctx, "SELECT count(DISTINCT (c.tableoid, c.ctid)) FROM "+t.rel.rel+" c JOIN "+t.rel.rel+" p ON "+
		strings.Join(on, " AND ")+" WHERE p.ctid = ANY($2::text[]::tid[]) AND (p.tableoid, p.ctid::text) IN (SELECT * FROM unnest($1::oid[], $2::text[]))"+
		" AND (c.tableoid, c.ctid::text) NOT IN (SELECT * FROM unnest($1::oid[], $2::text[]))", oids(ids), ctids(ids)).Scan(&n)
	return n, readErr(err)
}

func oids(ids []rowID) []uint32 {
	out := make([]uint32, len(ids))
	for i, id := range ids {
		out[i] = id.oid
	}
	return out
}

func ctids(ids []rowID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.ctid
	}
	return out
}

// readErr says where instead of quoting: Postgres's message can carry a
// value.
func readErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if i := strings.Index(msg, "DETAIL"); i > 0 {
		msg = strings.TrimSpace(msg[:i])
	}
	return errors.New(msg)
}

// --- the plan ----------------------------------------------------------------

// entries is a table's inventory entry and its columns' own.
type entries struct {
	table   *branch.DPDPEntry
	columns map[string]*branch.DPDPEntry
	confirm map[string][]branch.PIIFinding // confirmed findings by column
	waiting int                            // findings no reviewer has decided
}

func (s *state) entriesOf(k tkey) entries {
	e := entries{columns: map[string]*branch.DPDPEntry{}, confirm: map[string][]branch.PIIFinding{}}
	for _, t := range s.inv.Tables {
		if t.Schema != k.schema || t.Table != k.table {
			continue
		}
		e.table = t.Entry
		for _, c := range t.Columns {
			if c.Override != nil {
				e.columns[c.Column] = c.Override
			}
		}
	}
	for _, f := range s.findings {
		if f.Schema != k.schema || f.Table != k.table {
			continue
		}
		switch f.State {
		case branch.PIIConfirmed:
			e.confirm[f.Column] = append(e.confirm[f.Column], f)
		case branch.PIISuggested:
			e.waiting++
		}
	}
	return e
}

func exception(e *branch.DPDPEntry, column string, events map[string]string) branch.ErasureException {
	x := branch.ErasureException{Column: column, Citation: e.Keep.Citation, Keep: e.Keep}
	if d, ok := events[e.Keep.From]; ok {
		if t, err := time.Parse("2006-01-02", d); err == nil {
			end := t
			switch e.Keep.Unit {
			case "days":
				end = t.AddDate(0, 0, e.Keep.Count)
			case "months":
				end = t.AddDate(0, e.Keep.Count, 0)
			case "years":
				end = t.AddDate(e.Keep.Count, 0, 0)
			}
			x.Ends = &end
		}
	}
	where := "the table"
	if column != "" {
		where = column
	}
	x.Text = fmt.Sprintf("%s is kept under %s: %s", where, e.Keep.Citation, e.Keep)
	if x.Ends != nil {
		x.Text += "; ends " + x.Ends.Format("2 January 2006")
	} else {
		x.Text += "; the date it ends is not known until " + branch.DPDPLabel(branch.DPDPWords.From, e.Keep.From) + "'s date is given"
	}
	return x
}

// decided is a table's plan before the rows' fates are settled.
type decided struct {
	k          tkey
	act        string // clear, delete, kept, keep (no personal data)
	entry      *branch.DPDPEntry
	isDefault  bool
	columns    []branch.ErasureColumn
	sets       []setCol // what a clear sets, as SQL
	paths      map[string][]string
	exceptions []branch.ErasureException
	problems   []string
	notes      []string
}

type setCol struct {
	col  string
	expr string // NULL, DEFAULT, or $n
	arg  *string
}

func (s *state) decide(k tkey, events map[string]string) (*decided, error) {
	t := s.tables[k]
	d := &decided{k: k, act: branch.ErasureActKeep, paths: map[string][]string{}}
	if !t.personal {
		return d, nil
	}
	e := s.entriesOf(k)
	d.entry = e.table
	d.act = branch.ErasureActClear
	if e.table == nil {
		d.isDefault = true
		d.notes = append(d.notes, "The table has no inventory entry, so its personal columns are cleared, the default; this is not a decision anybody made.")
	} else {
		switch e.table.Keep.Reason {
		case "law":
			d.act = branch.ErasureActKeptLaw
			d.exceptions = append(d.exceptions, exception(e.table, "", events))
			return d, nil
		case "contract":
			d.notes = append(d.notes, "The entry keeps it under a contract ("+e.table.Keep.Citation+"); a contract does not override s.8(7), so it is erased.")
		}
		if e.table.OnErasure == branch.EraseDelete {
			d.act = branch.ErasureActDelete
		}
	}
	if e.waiting > 0 {
		d.notes = append(d.notes, fmt.Sprintf("%d finding(s) in this table are undecided and were not searched or cleared; decide them first (%s).",
			e.waiting, "fox pii"))
	}
	cols := make([]string, 0, len(e.confirm))
	for c := range e.confirm {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	kept := 0
	for _, c := range cols {
		if ce := e.columns[c]; ce != nil && ce.Keep.Reason == "law" {
			d.exceptions = append(d.exceptions, exception(ce, c, events))
			kept++
			continue
		}
		if ce := e.columns[c]; ce != nil && ce.Keep.Reason == "contract" {
			d.notes = append(d.notes, c+"'s entry keeps it under a contract ("+ce.Keep.Citation+"), which does not override s.8(7); it is erased.")
		}
		info, ok := t.rel.cols[c]
		if !ok {
			continue
		}
		var cats []string
		whole := false
		var paths []string
		for _, f := range e.confirm[c] {
			if !contains(cats, f.Category) {
				cats = append(cats, f.Category)
			}
			if f.Path == "" {
				whole = true
			} else if !contains(paths, f.Path) {
				paths = append(paths, f.Path)
			}
		}
		sort.Strings(cats)
		sort.Strings(paths)
		if !whole {
			for _, p := range paths {
				d.columns = append(d.columns, branch.ErasureColumn{Column: c, Path: p, Categories: cats, To: "null at the path"})
			}
			d.paths[c] = paths
			continue
		}
		col := branch.ErasureColumn{Column: c, Categories: cats}
		switch ce := e.columns[c]; {
		case info.generated:
			d.notes = append(d.notes, c+" is a generated column: it follows the columns it is made from, and is not set itself.")
			continue
		case ce != nil && ce.ClearTo != nil:
			v := *ce.ClearTo
			if err := s.castable(v, info.typ); err != nil {
				d.problems = append(d.problems, fmt.Sprintf("%s is cleared to %q, which is not a %s: %v", c, v, info.typ, err))
			}
			col.To = strconv.Quote(v)
			d.sets = append(d.sets, setCol{col: c, expr: "$" + info.typ, arg: &v})
		case !info.notNull:
			col.To = "NULL"
			d.sets = append(d.sets, setCol{col: c, expr: "NULL"})
		case info.hasDefault:
			col.To = "DEFAULT"
			d.sets = append(d.sets, setCol{col: c, expr: "DEFAULT"})
		default:
			d.problems = append(d.problems, fmt.Sprintf("%s is NOT NULL with no default, so it cannot be cleared: set the table's action to delete "+
				"(fox dpdp set %s --on-erasure delete …), or give it a placeholder on its own entry (fox dpdp set %s.%s --clear-to '…' …)",
				c, k, k, c))
		}
		d.columns = append(d.columns, col)
	}
	if d.act == branch.ErasureActDelete && kept > 0 {
		d.act = branch.ErasureActClear
		d.notes = append(d.notes, "A column here is kept under a law, so the row is not deleted: its other personal columns are cleared instead.")
	}
	if d.act == branch.ErasureActDelete {
		d.columns, d.sets, d.paths = nil, nil, map[string][]string{}
		// What a delete takes with it is settled with every table's rows.
		d.problems = filterClearProblems(d.problems)
	}
	return d, nil
}

// filterClearProblems drops the problems only a clear has: a row deleted is
// not cleared.
func filterClearProblems(ps []string) []string {
	var out []string
	for _, p := range ps {
		if !strings.Contains(p, "cannot be cleared") && !strings.Contains(p, "is cleared to") {
			out = append(out, p)
		}
	}
	return out
}

// castable checks a placeholder is a value of the column's type, without
// leaving the transaction aborted when it is not.
func (s *state) castable(v, typ string) error {
	ctx, tx := s.cat.ctx, s.cat.tx
	if _, err := tx.Exec(ctx, "SAVEPOINT bb_erasure_cast"); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "SELECT $1::text::"+typ, v)
	if err != nil {
		_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT bb_erasure_cast")
		return readErr(err)
	}
	_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT bb_erasure_cast")
	return nil
}

// settle decides every row's fate: a deleting table's rows are deleted; a
// row referring to a deleted row is deleted with it, has its reference
// cleared, or stops the plan, as its foreign key says; the rest take their
// table's action.
func (s *state) settle(ds map[tkey]*decided) {
	for _, k := range s.order {
		for _, id := range s.tables[k].order {
			s.tables[k].rows[id].fate = ds[k].act
		}
	}
	gone := func(l link) bool {
		p := s.tables[l.parent].rows[l.prow]
		return p != nil && (p.fate == branch.ErasureActDelete || p.fate == branch.ErasureActCascade)
	}
	for changed := true; changed; {
		changed = false
		for _, k := range s.order {
			t := s.tables[k]
			for _, id := range t.order {
				r := t.rows[id]
				if r.fate == branch.ErasureActDelete || r.fate == branch.ErasureActCascade {
					continue
				}
				for _, l := range r.links {
					if !gone(l) {
						continue
					}
					switch l.fk.delType {
					case 'c':
						if r.fate == branch.ErasureActKeptLaw {
							continue // a law keeps it: the delete is refused below
						}
						r.fate, changed = branch.ErasureActCascade, true
					case 'n', 'd':
						if r.fate == branch.ErasureActKeep {
							r.fate, changed = branch.ErasureActSetNull, true
						}
					}
					if r.fate == branch.ErasureActCascade {
						break
					}
				}
			}
		}
	}
	// What is left referring to a deleted row through a key that refuses the
	// delete stops the plan, on the table whose rows are deleted.
	type refusal struct{ table, fk, what string }
	refused := map[tkey]map[refusal]int{}
	for _, k := range s.order {
		t := s.tables[k]
		for _, id := range t.order {
			r := t.rows[id]
			if r.fate == branch.ErasureActDelete || r.fate == branch.ErasureActCascade {
				continue
			}
			for _, l := range r.links {
				if !gone(l) {
					continue
				}
				what := ""
				switch {
				case r.fate == branch.ErasureActKeptLaw && l.fk.delType == 'c':
					what = ", and are kept under a law, which the delete would take with them (CASCADE)"
				case l.fk.delType != 'c' && l.fk.delType != 'n' && l.fk.delType != 'd':
					what = ", which refuses a delete (RESTRICT or NO ACTION)"
				default:
					continue
				}
				if refused[l.parent] == nil {
					refused[l.parent] = map[refusal]int{}
				}
				refused[l.parent][refusal{k.String(), l.fk.name, what}]++
				break
			}
		}
	}
	for _, p := range s.order {
		by := refused[p]
		keys := make([]refusal, 0, len(by))
		for n := range by {
			keys = append(keys, n)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].table+keys[i].fk < keys[j].table+keys[j].fk })
		for _, n := range keys {
			ds[p].problems = append(ds[p].problems, fmt.Sprintf(
				"%d row(s) of %s refer to the rows this deletes through %s%s: "+
					"set this table's action to clear, or delete those rows too (their table's entry)", by[n], n.table, n.fk, n.what))
		}
	}
	for _, k := range s.order {
		t := s.tables[k]
		deleting := ds[k].act == branch.ErasureActDelete
		for _, sr := range t.self {
			switch {
			case !deleting:
				ds[k].notes = append(ds[k].notes, fmt.Sprintf("%d other row(s) of this table refer to the person's through %s; they are left as they are.", sr.rows, sr.fk.name))
			case sr.fk.delType == 'n' || sr.fk.delType == 'd':
				ds[k].notes = append(ds[k].notes, fmt.Sprintf("%d other row(s) of this table refer to the person's through %s; their reference is cleared with the delete.", sr.rows, sr.fk.name))
			default:
				ds[k].problems = append(ds[k].problems, fmt.Sprintf("%d other row(s) of this table, perhaps other people's, refer to the person's through %s, "+
					"which would delete them too or refuse the delete; set the table's action to clear", sr.rows, sr.fk.name))
			}
		}
	}
}

func rewriteMax() int64 {
	v := strings.TrimSpace(os.Getenv(rewriteMaxEnv))
	if v == "" {
		return defaultRewriteMax
	}
	mult := int64(1)
	switch u := strings.ToUpper(v[len(v)-1:]); u {
	case "K":
		mult = 1 << 10
	case "M":
		mult = 1 << 20
	case "G":
		mult = 1 << 30
	case "T":
		mult = 1 << 40
	}
	if mult > 1 {
		v = v[:len(v)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return defaultRewriteMax
	}
	return n * mult
}

// build runs the whole of finding and deciding, in tx: the plan, its
// fingerprint, and the run's state for an apply.
func build(ctx context.Context, tx pgx.Tx, name string, ms matchSet, refs []branch.ErasureRef, events map[string]string,
	actor string, lock bool) (branch.ErasurePlan, string, *state, map[tkey]*decided, error) {
	plan := branch.ErasurePlan{Branch: name, Made: time.Now().UTC(), By: actor, Refs: refs, Tables: []branch.ErasureTable{},
		Review: branch.ErasureReview}
	inv, err := branch.DPDPInventoryOf(name)
	if err != nil {
		return plan, "", nil, nil, err
	}
	rep, err := branch.PersonalDataFindings(name)
	if err != nil {
		return plan, "", nil, nil, err
	}
	st := &state{cat: &catalog{ctx: ctx, tx: tx, rels: map[tkey]*relInfo{}}, lock: lock, ms: ms, inv: inv,
		findings: rep.Findings, tables: map[tkey]*tableRows{}}
	if err := st.match(); err != nil {
		return plan, "", nil, nil, err
	}
	for _, k := range st.order {
		st.tables[k].why = matchWhy(st, k)
	}
	if err := st.follow(); err != nil {
		return plan, "", nil, nil, err
	}
	ds := map[tkey]*decided{}
	for _, k := range st.order {
		d, err := st.decide(k, events)
		if err != nil {
			return plan, "", nil, nil, err
		}
		ds[k] = d
	}
	st.settle(ds)
	plan.Searched = st.searched

	var avail int64 = -1
	if n, err := branch.DatasetAvailable(name); err == nil {
		avail = n
	}
	limit := rewriteMax()
	type fpTable struct {
		T, A    string
		N       int
		Keys    []string
		Cols    []branch.ErasureColumn
		Problem []string
	}
	var fp []fpTable
	for _, k := range st.order {
		t, d := st.tables[k], ds[k]
		byFate := map[string][]*row{}
		var fates []string
		for _, id := range t.order {
			r := t.rows[id]
			if _, ok := byFate[r.fate]; !ok {
				fates = append(fates, r.fate)
			}
			byFate[r.fate] = append(byFate[r.fate], r)
		}
		for _, f := range fates {
			rs := byFate[f]
			et := branch.ErasureTable{Schema: k.schema, Table: k.table, Why: t.why, Depth: t.depth, Rows: len(rs), Action: f,
				Columns: []branch.ErasureColumn{}, Entry: d.entry, Default: d.isDefault && f == branch.ErasureActClear,
				Exceptions: d.exceptions, Problems: d.problems, Notes: d.notes, Keyed: len(t.rel.keyCols) > 0, Size: t.rel.size}
			if et.Exceptions == nil {
				et.Exceptions = []branch.ErasureException{}
			}
			if et.Problems == nil {
				et.Problems = []string{}
			}
			if et.Notes == nil {
				et.Notes = []string{}
			}
			if f == branch.ErasureActClear {
				et.Columns = d.columns
				if et.Columns == nil {
					et.Columns = []branch.ErasureColumn{}
				}
				if len(d.sets) == 0 && len(d.paths) == 0 && len(d.problems) == 0 {
					et.Action = branch.ErasureActKeep
					et.Notes = append(append([]string(nil), et.Notes...), "Nothing here is left to clear: every personal column is kept or generated.")
				}
			}
			et.Problems = problemsFor(et.Problems, f)
			if et.Changes() {
				switch {
				case et.Size > limit:
					et.Rewrite, et.RewriteWhy = "later", fmt.Sprintf("larger than %s, so it is rewritten when an admin runs it (fox dpdp erase rewrite)", size(limit))
				case avail >= 0 && et.Size*12/10 > avail:
					et.Rewrite, et.RewriteWhy = "later", "the branch has too little free space for a second copy of it"
				default:
					et.Rewrite = "apply"
				}
			}
			for _, r := range rs {
				if r.matched {
					plan.Matched++
				}
			}
			if et.Changes() {
				plan.Rows += len(rs)
			}
			if len(et.Problems) > 0 {
				plan.Blocked = true
			}
			plan.Tables = append(plan.Tables, et)
			ft := fpTable{T: k.String(), A: et.Action, N: len(rs), Cols: et.Columns, Problem: et.Problems}
			if len(t.rel.keyCols) > 0 {
				for _, r := range rs {
					ft.Keys = append(ft.Keys, r.key)
				}
				sort.Strings(ft.Keys)
			}
			fp = append(fp, ft)
		}
	}
	sort.Slice(fp, func(i, j int) bool { return fp[i].T+fp[i].A < fp[j].T+fp[j].A })
	raw, _ := json.Marshal(fp)
	sum := sha256.Sum256(raw)

	plan.Limits = append(st.limits,
		fmt.Sprintf("Only places a reviewer confirmed as personal data were searched (%d here); a value in a column no scan found, in free text, or spelt differently is not found.", st.searched),
		"Values are compared whole, after normalising case and separators.",
		"In a JSON column, every value at a confirmed path in the person's rows is cleared.",
		"This request erases "+name+". Every other branch, the Blackbox and query history, the vault, restores and the backups are the next steps of F4: until they are built, the person can remain in them.",
	)
	if st.maxDepth {
		plan.Limits = append(plan.Limits, fmt.Sprintf("Foreign keys were followed %d deep and no further.", maxDepth))
	}
	return plan, hex.EncodeToString(sum[:]), st, ds, nil
}

// problemsFor keeps the problems that matter to rows with this fate: a
// refused delete to the rows deleted, a column that cannot be cleared to the
// rows cleared.
func problemsFor(ps []string, fate string) []string {
	out := []string{}
	for _, p := range ps {
		deleting := strings.Contains(p, "refer to the rows this deletes") || strings.Contains(p, "would delete them too")
		clearing := strings.Contains(p, "cannot be cleared") || strings.Contains(p, "is cleared to")
		switch fate {
		case branch.ErasureActDelete, branch.ErasureActCascade:
			if !clearing {
				out = append(out, p)
			}
		case branch.ErasureActClear:
			if !deleting {
				out = append(out, p)
			}
		}
	}
	return out
}

func matchWhy(st *state, k tkey) string {
	var cols []string
	for _, f := range st.findings {
		if f.Schema != k.schema || f.Table != k.table || f.State != branch.PIIConfirmed {
			continue
		}
		if _, ok := st.ms[pii.Category(f.Category)]; !ok {
			continue
		}
		w := f.Column
		if f.Path != "" {
			w += " at " + f.Path
		}
		if !contains(cols, w) {
			cols = append(cols, w)
		}
	}
	sort.Strings(cols)
	return "holds a value in " + strings.Join(cols, ", ")
}

func size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d kB", n/1024)
}

// erasurePlan finds the person's rows and says what it would do, in a
// read-only transaction that is rolled back.
func erasurePlan(name string, values []branch.ErasureValue, events map[string]string, actor string) (branch.ErasurePlan, string, error) {
	ms, refs, err := readValues(values)
	if err != nil {
		return branch.ErasurePlan{}, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), eraseTimeout)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return branch.ErasurePlan{}, "", err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return branch.ErasurePlan{}, "", err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '5min'"); err != nil {
		return branch.ErasurePlan{}, "", err
	}
	plan, fp, _, _, err := build(ctx, tx, name, ms, refs, events, actor, false)
	return plan, fp, err
}

// --- applying ------------------------------------------------------------------

func erasureApply(name string, a branch.ErasureApply) (branch.ErasurePlan, string, branch.ErasureResult, error) {
	var res branch.ErasureResult
	ms, refs, err := readValues(a.Values)
	if err != nil {
		return branch.ErasurePlan{}, "", res, err
	}
	if err := schema.EnsureDPDP(name); err != nil {
		return branch.ErasurePlan{}, "", res, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), eraseTimeout)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return branch.ErasurePlan{}, "", res, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(ctx)
	if err != nil {
		return branch.ErasurePlan{}, "", res, err
	}
	defer tx.Rollback(context.Background())
	// The engine's own statements: the tracking columns (point 5) name the
	// request, not the admin's login, as what changed the row.
	if _, err := tx.Exec(ctx, "SELECT set_config('statement_timeout', '5min', true), set_config('lock_timeout', '30s', true), "+
		"set_config('bb.actor', $1, true)", fmt.Sprintf("erasure request #%d", a.ID)); err != nil {
		return branch.ErasurePlan{}, "", res, err
	}
	plan, fp, st, ds, err := build(ctx, tx, name, ms, refs, a.Events, a.Actor, true)
	if err != nil {
		return plan, fp, res, err
	}
	if fp != a.Fingerprint {
		return plan, fp, res, branch.ErrErasurePlanChanged
	}
	if plan.Blocked {
		return plan, fp, res, fmt.Errorf("%w: a table has a problem", branch.ErrErasureBlocked)
	}
	res = branch.ErasureResult{Applied: time.Now().UTC(), By: a.Actor, Tables: []branch.ErasureDone{}, Rewrites: []branch.ErasureRewrite{}, Notes: []string{}}
	names, err := relNames(ctx, tx, st)
	if err != nil {
		return plan, fp, res, err
	}
	// Clears first: a row cleared and then cascaded away by a delete is
	// gone either way, but a delete first would leave a clear with no row.
	for _, k := range st.order {
		d := ds[k]
		ids := fated(st.tables[k], branch.ErasureActClear)
		if len(ids) == 0 || (len(d.sets) == 0 && len(d.paths) == 0) {
			continue
		}
		n, err := clearRows(ctx, tx, names, d, ids)
		if err != nil {
			return plan, fp, res, fmt.Errorf("clearing %s (nothing was applied): %w", k, readErr(err))
		}
		if n != len(ids) {
			return plan, fp, res, fmt.Errorf("clearing %s changed %d row(s), not %d; nothing was applied", k, n, len(ids))
		}
	}
	// Then deletes, the deepest first, so a row a key protects goes before
	// the row it refers to.
	byDepth := append([]tkey(nil), st.order...)
	sort.SliceStable(byDepth, func(i, j int) bool { return st.tables[byDepth[i]].depth > st.tables[byDepth[j]].depth })
	for _, k := range byDepth {
		ids := fated(st.tables[k], branch.ErasureActDelete)
		if len(ids) == 0 {
			continue
		}
		n, err := execByRow(ctx, tx, names, ids, func(rel string) string { return "DELETE FROM " + rel + " WHERE ctid = ANY($1::text[]::tid[])" })
		if err != nil {
			return plan, fp, res, fmt.Errorf("deleting from %s (nothing was applied): %w", k, readErr(err))
		}
		if n != len(ids) {
			return plan, fp, res, fmt.Errorf("deleting from %s removed %d row(s), not %d; nothing was applied", k, n, len(ids))
		}
	}
	// What the foreign keys were to take with the deletes, taken.
	for _, k := range st.order {
		ids := fated(st.tables[k], branch.ErasureActCascade)
		if len(ids) == 0 {
			continue
		}
		left, err := countByRow(ctx, tx, names, ids)
		if err != nil {
			return plan, fp, res, err
		}
		if left != 0 {
			return plan, fp, res, fmt.Errorf("%d row(s) of %s were to go with the deletes and did not; nothing was applied", left, k)
		}
	}
	// A search afterwards, in the same transaction, finds the values nowhere
	// they were to be erased.
	if left, where, err := searchAgain(ctx, tx, st, ds); err != nil {
		return plan, fp, res, err
	} else if left > 0 {
		return plan, fp, res, fmt.Errorf("after erasing, %d row(s) still hold a value in %s; nothing was applied", left, where)
	}
	res.Verified = true
	for _, t := range plan.Tables {
		if t.Changes() {
			res.Rows += t.Rows
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bb.erasures_applied (request_uid, request_id, rows) VALUES ($1, $2, $3)`,
		a.UID, a.ID, res.Rows); err != nil {
		return plan, fp, res, fmt.Errorf("recording the erasure on %s (nothing was applied): %w", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return plan, fp, res, fmt.Errorf("committing the erasure on %s: %w", name, err)
	}
	for _, k := range st.order {
		t := st.tables[k]
		for _, act := range []string{branch.ErasureActClear, branch.ErasureActDelete, branch.ErasureActCascade, branch.ErasureActSetNull} {
			rs := fatedRows(t, act)
			if len(rs) == 0 || (act == branch.ErasureActClear && len(ds[k].sets) == 0 && len(ds[k].paths) == 0) {
				continue
			}
			done := branch.ErasureDone{Schema: k.schema, Table: k.table, Action: act, Rows: len(rs), KeyColumns: t.rel.keyCols}
			for _, r := range rs {
				if r.key != "" {
					done.Keys = append(done.Keys, json.RawMessage(r.key))
				}
			}
			res.Tables = append(res.Tables, done)
		}
	}
	seen := map[tkey]bool{}
	for _, t := range plan.Tables {
		k := tkey{t.Schema, t.Table}
		if !t.Changes() || seen[k] || t.Rewrite == "" {
			continue
		}
		seen[k] = true
		w := branch.ErasureRewrite{Schema: t.Schema, Table: t.Table, Size: t.Size, State: branch.RewritePending}
		if t.Rewrite == "later" {
			w.Why = t.RewriteWhy
		}
		res.Rewrites = append(res.Rewrites, w)
	}
	return plan, fp, res, nil
}

func fated(t *tableRows, fate string) []rowID {
	var out []rowID
	for _, id := range t.order {
		if t.rows[id].fate == fate {
			out = append(out, id)
		}
	}
	return out
}

func fatedRows(t *tableRows, fate string) []*row {
	var out []*row
	for _, id := range t.order {
		if t.rows[id].fate == fate {
			out = append(out, t.rows[id])
		}
	}
	return out
}

// relNames is each row's own relation, by oid: a partition, for a
// partitioned table, so a ctid is looked up where it lives.
func relNames(ctx context.Context, tx pgx.Tx, st *state) (map[uint32]string, error) {
	out := map[uint32]string{}
	for _, k := range st.order {
		for id := range st.tables[k].rows {
			if _, ok := out[id.oid]; ok {
				continue
			}
			var n string
			if err := tx.QueryRow(ctx, "SELECT $1::oid::regclass::text", id.oid).Scan(&n); err != nil {
				return nil, err
			}
			out[id.oid] = n
		}
	}
	return out, nil
}

func byOID(ids []rowID) map[uint32][]string {
	out := map[uint32][]string{}
	for _, id := range ids {
		out[id.oid] = append(out[id.oid], id.ctid)
	}
	return out
}

func execByRow(ctx context.Context, tx pgx.Tx, names map[uint32]string, ids []rowID, stmt func(rel string) string) (int, error) {
	n := 0
	for oid, cs := range byOID(ids) {
		tag, err := tx.Exec(ctx, stmt("ONLY "+names[oid]), cs)
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	return n, nil
}

func countByRow(ctx context.Context, tx pgx.Tx, names map[uint32]string, ids []rowID) (int, error) {
	n := 0
	for oid, cs := range byOID(ids) {
		var c int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM ONLY "+names[oid]+" WHERE ctid = ANY($1::text[]::tid[])", cs).Scan(&c); err != nil {
			return n, err
		}
		n += c
	}
	return n, nil
}

// clearRows sets a table's rows' personal columns. A JSON path is cleared
// in the document, row by row; otherwise one statement does it.
func clearRows(ctx context.Context, tx pgx.Tx, names map[uint32]string, d *decided, ids []rowID) (int, error) {
	var sets []string
	var args []any
	for _, sc := range d.sets {
		switch {
		case sc.arg != nil:
			args = append(args, *sc.arg)
			sets = append(sets, fmt.Sprintf("%s = $%d::text::%s", branch.QuoteIdent(sc.col), len(args)+1, strings.TrimPrefix(sc.expr, "$")))
		default:
			sets = append(sets, branch.QuoteIdent(sc.col)+" = "+sc.expr)
		}
	}
	if len(d.paths) == 0 {
		return execArgs(ctx, tx, names, ids, sets, args)
	}
	cols := make([]string, 0, len(d.paths))
	for c := range d.paths {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	n := 0
	for _, id := range ids {
		rel := "ONLY " + names[id.oid]
		reads := make([]string, len(cols))
		for i, c := range cols {
			reads[i] = branch.QuoteIdent(c) + "::text"
		}
		docs := make([]*string, len(cols))
		dest := make([]any, len(cols))
		for i := range docs {
			dest[i] = &docs[i]
		}
		if err := tx.QueryRow(ctx, "SELECT "+strings.Join(reads, ", ")+" FROM "+rel+" WHERE ctid = $1::tid", id.ctid).Scan(dest...); err != nil {
			return n, err
		}
		rowSets := append([]string(nil), sets...)
		rowArgs := append([]any(nil), args...)
		for i, c := range cols {
			if docs[i] == nil {
				continue
			}
			doc, err := clearJSONPaths(*docs[i], d.paths[c])
			if err != nil {
				return n, fmt.Errorf("%s: %w", c, err)
			}
			rowArgs = append(rowArgs, doc)
			rowSets = append(rowSets, fmt.Sprintf("%s = $%d::text::%s", branch.QuoteIdent(c), len(rowArgs)+1, jsonType(ctx, tx, id.oid, c)))
		}
		if len(rowSets) == 0 {
			n++
			continue
		}
		tag, err := tx.Exec(ctx, "UPDATE "+rel+" SET "+strings.Join(rowSets, ", ")+" WHERE ctid = $1::tid", append([]any{id.ctid}, rowArgs...)...)
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	return n, nil
}

func jsonType(ctx context.Context, tx pgx.Tx, oid uint32, col string) string {
	var t string
	if err := tx.QueryRow(ctx, "SELECT format_type(atttypid, atttypmod) FROM pg_attribute WHERE attrelid = $1 AND attname = $2", oid, col).Scan(&t); err != nil || t == "" {
		return "jsonb"
	}
	return t
}

func execArgs(ctx context.Context, tx pgx.Tx, names map[uint32]string, ids []rowID, sets []string, args []any) (int, error) {
	if len(sets) == 0 {
		return len(ids), nil
	}
	n := 0
	for oid, cs := range byOID(ids) {
		tag, err := tx.Exec(ctx, "UPDATE ONLY "+names[oid]+" SET "+strings.Join(sets, ", ")+" WHERE ctid = ANY($1::text[]::tid[])",
			append([]any{cs}, args...)...)
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	return n, nil
}

// searchAgain counts the rows still holding a value in a place the plan was
// to erase: none, or the apply is rolled back.
func searchAgain(ctx context.Context, tx pgx.Tx, st *state, ds map[tkey]*decided) (int, string, error) {
	for _, f := range st.findings {
		if f.State != branch.PIIConfirmed {
			continue
		}
		vals, ok := st.ms[pii.Category(f.Category)]
		if !ok {
			continue
		}
		k := tkey{f.Schema, f.Table}
		t, ok := st.tables[k]
		if !ok {
			continue
		}
		d := ds[k]
		if d.act == branch.ErasureActKeptLaw || keptColumn(d, f.Column) {
			continue
		}
		if c, ok := t.rel.cols[f.Column]; !ok || c.generated {
			continue
		}
		q, args := matchQuery(t.rel, f, vals)
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM ("+q+") AS left_over", args...).Scan(&n); err != nil {
			return 0, "", readErr(err)
		}
		if n > 0 {
			return n, f.Where(), nil
		}
	}
	return 0, "", nil
}

func keptColumn(d *decided, col string) bool {
	for _, x := range d.exceptions {
		if x.Column == col {
			return true
		}
	}
	return false
}

// --- after the commit: vacuum and rewrite ---------------------------------------

// erasureSettle vacuums what the apply changed and rewrites the tables to be
// rewritten with it; given only, it rewrites those tables. Failures are
// recorded in the result, not returned: the erasure is applied either way.
func erasureSettle(name string, plan branch.ErasurePlan, res branch.ErasureResult, only []string) branch.ErasureResult {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		res.Notes = append(res.Notes, "The vacuum and rewrite could not start: "+readErr(err).Error())
		return res
	}
	defer conn.Close(context.Background())
	rel := func(schemaName, table string) string {
		return branch.QuoteIdent(schemaName) + "." + branch.QuoteIdent(table)
	}
	if only == nil {
		// Removed from live queries (section 7, E3–E5): the dead versions
		// and the index entries pointing at them.
		seen := map[string]bool{}
		for _, t := range plan.Tables {
			r := rel(t.Schema, t.Table)
			if !t.Changes() || seen[r] {
				continue
			}
			seen[r] = true
			if _, err := conn.Exec(ctx, "VACUUM (INDEX_CLEANUP ON) "+r); err != nil {
				res.Notes = append(res.Notes, fmt.Sprintf("Vacuuming %s.%s failed: %v", t.Schema, t.Table, readErr(err)))
			}
		}
		now := time.Now().UTC()
		res.Vacuumed = &now
	}
	want := map[string]bool{}
	for _, t := range only {
		want[t] = true
	}
	rewrote := false
	for i := range res.Rewrites {
		w := &res.Rewrites[i]
		where := w.Schema + "." + w.Table
		switch {
		case only != nil && !want[where]:
			continue
		case only == nil && (w.Why != "" || w.State == branch.RewriteDone):
			continue // left for later, or done
		}
		if avail, err := branch.DatasetAvailable(name); err == nil && w.Size*12/10 > avail {
			w.State, w.Error = branch.RewriteFailed, "the branch has too little free space for a second copy of the table"
			continue
		}
		// ACCESS EXCLUSIVE for as long as it runs; a table busy for longer
		// than the lock timeout is left pending, not waited on.
		_, err := conn.Exec(ctx, "SET lock_timeout = '30s'")
		if err == nil {
			_, err = conn.Exec(ctx, "VACUUM FULL "+rel(w.Schema, w.Table))
		}
		if err == nil {
			_, err = conn.Exec(ctx, "ANALYZE "+rel(w.Schema, w.Table))
		}
		if err != nil {
			w.State, w.Error = branch.RewriteFailed, readErr(err).Error()
			continue
		}
		now := time.Now().UTC()
		w.State, w.At, w.Error = branch.RewriteDone, &now, ""
		rewrote = true
	}
	_, _ = conn.Exec(ctx, "RESET lock_timeout")
	if rewrote {
		// ANALYZE wrote new statistics and left the old in pg_statistic's
		// file; and the WAL holds the old pages until it is recycled
		// (section 21, as masked branches do).
		var err error
		for _, q := range []string{"VACUUM FULL pg_statistic", "VACUUM FULL pg_statistic_ext_data", "CHECKPOINT",
			"SELECT pg_switch_wal()", "CHECKPOINT", "SELECT pg_switch_wal()", "CHECKPOINT", "SELECT pg_switch_wal()", "CHECKPOINT"} {
			if _, err = conn.Exec(ctx, q); err != nil {
				res.Notes = append(res.Notes, fmt.Sprintf("Rewriting the statistics and switching out the WAL stopped at %q: %v", q, readErr(err)))
				break
			}
		}
		if err == nil {
			now := time.Now().UTC()
			res.Statistics = &now
		}
	}
	return res
}

func erasureAppliedOn(name, uid string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := branch.OpenSuper(ctx, name)
	if err != nil {
		return false, err
	}
	defer conn.Close(context.Background())
	var on bool
	err = conn.QueryRow(ctx, `SELECT to_regclass('bb.erasures_applied') IS NOT NULL
		AND EXISTS (SELECT 1 FROM bb.erasures_applied WHERE request_uid = $1)`, uid).Scan(&on)
	return on, err
}
