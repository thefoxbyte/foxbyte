//go:build enterprise

// SPDX-License-Identifier: LicenseRef-FoxByte-Enterprise-1.0

package realtime

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/thefoxbyte/foxbyte/internal/branch"
	"github.com/thefoxbyte/foxbyte/internal/brand"
)

// Which columns a table streams.
//
// A change feed used to carry whole rows: every column of every change, and
// under REPLICA IDENTITY FULL every column of the row before it too. That is
// fine for a cache the application owns and wrong for a realtime key handed to
// somebody else, who then receives every email address and phone number the
// table holds, including the ones that were just overwritten.
//
// So enabling a table can name the columns it streams. The choice is kept in
// two places, on purpose:
//
//   - in the publication, as a column list (PostgreSQL 15 and later), so the
//     columns left out never leave Postgres at all;
//   - in bb.realtime_columns, which the decoder reads and enforces on every
//     change, whether or not the publication could.
//
// The second is not a copy for its own sake. There are cases a publication
// cannot narrow: a major without column lists, and a table under REPLICA
// IDENTITY FULL that publishes updates or deletes, where Postgres requires the
// column list to cover the whole replica identity (every column) and would
// otherwise refuse the application's UPDATEs. In those cases the decoder is
// the only filter, and in every other case it is a second one.
//
// A table with no row in bb.realtime_columns streams every column. That is how
// every table enabled before this existed keeps working after an upgrade:
// nothing about it changes until an admin narrows it.

// ColumnListMajor is the first PostgreSQL major whose publications take a
// column list. FoxByte runs 16 and 18 (branch.SupportedPGMajors), so in
// practice every install has it; the fallback is for an image override whose
// major cannot be read, and for any older server that might be pointed at.
const ColumnListMajor = 15

// columnsTable is where the admin's choice is recorded on the branch. In bb so
// it is a system table: never offered for streaming, never readable by
// db_client, and cloned with the branch exactly as the publication is.
const columnsTable = "bb.realtime_columns"

// columnsDDL creates the record and lets the decode role read it. The grant is
// only to that table: the decode role still cannot read any application data
// over SQL, which is the property EnsureRealtimeRole is built around.
func columnsDDL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + columnsTable + ` (
  schema_name text NOT NULL, table_name text NOT NULL,
  columns text[],
  old_values boolean NOT NULL DEFAULT false,
  pii_allowed text[] NOT NULL DEFAULT '{}',
  set_by text NOT NULL DEFAULT '', set_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (schema_name, table_name))`,
		"REVOKE ALL ON " + columnsTable + " FROM PUBLIC",
		grantColumnsSQL,
	}
}

// grantColumnsSQL is the decode role's read of the record, if both exist. Run
// at enable and again before each decoder starts, because the role may be made
// after the table (a branch older than `fox realtime setup`) or the other way
// round.
var grantColumnsSQL = fmt.Sprintf(`DO $$ BEGIN
  IF to_regrole(%[1]s) IS NOT NULL AND to_regclass(%[2]s) IS NOT NULL THEN
    EXECUTE format('GRANT USAGE ON SCHEMA bb TO %%I', %[1]s);
    EXECUTE format('GRANT SELECT ON %%s TO %%I', %[2]s, %[1]s);
  END IF;
END $$`, branch.BodyLiteral(branch.RealtimeRole), branch.BodyLiteral(columnsTable))

// TableColumns is what the catalog says about a table's columns, for choosing
// which of them stream.
type TableColumns struct {
	Names []string `json:"columns"` // in table order
	// PrimaryKey and IdentityIndex are the columns that name a row under the
	// default identity and under USING INDEX. They are what an update or
	// delete is located by, so they always stream.
	PrimaryKey    []string `json:"primary_key"`
	IdentityIndex []string `json:"identity_index"`
	ServerMajor   int      `json:"server_major"`
}

const tableColumnsSQL = `SELECT json_build_object(
  'columns', coalesce((SELECT json_agg(a.attname ORDER BY a.attnum) FROM pg_attribute a
      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped), '[]'::json),
  'primary_key', coalesce((SELECT json_agg(a.attname ORDER BY a.attnum) FROM pg_index i
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
      WHERE i.indrelid = c.oid AND i.indisprimary), '[]'::json),
  'identity_index', coalesce((SELECT json_agg(a.attname ORDER BY a.attnum) FROM pg_index i
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
      WHERE i.indrelid = c.oid AND i.indisreplident), '[]'::json),
  'server_major', current_setting('server_version_num')::int / 10000)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace`

func readTableColumns(branchName, schema, table string) (TableColumns, error) {
	lines, err := branch.LedgerQuery(branchName, tableColumnsSQL+fmt.Sprintf(
		" WHERE n.nspname = %s AND c.relname = %s", branch.QuoteLiteral(schema), branch.QuoteLiteral(table)))
	if err != nil {
		return TableColumns{}, fmt.Errorf("reading the columns of %s.%s: %w", schema, table, err)
	}
	if len(lines) == 0 {
		return TableColumns{}, fmt.Errorf("there is no table %s.%s on %q", schema, table, branchName)
	}
	var tc TableColumns
	if err := json.Unmarshal([]byte(lines[0]), &tc); err != nil {
		return TableColumns{}, fmt.Errorf("reading the columns of %s.%s: %w", schema, table, err)
	}
	return tc, nil
}

// PIIColumn is a column personal-data review has confirmed, or one a masking
// rule covers (which is only ever set on a confirmed finding).
type PIIColumn struct {
	Name     string `json:"column"`
	Category string `json:"category,omitempty"`
	Mask     string `json:"mask,omitempty"` // the masking rule, if one is set
}

func (p PIIColumn) String() string {
	var bits []string
	if p.Category != "" {
		bits = append(bits, p.Category)
	}
	if p.Mask != "" {
		// Said because masking does not reach the feed: decoded WAL is the
		// stored value, not what a masked reader's view returns.
		bits = append(bits, "masked ("+p.Mask+") for readers, but not in a change feed")
	}
	if len(bits) == 0 {
		return p.Name
	}
	return p.Name + " (" + strings.Join(bits, "; ") + ")"
}

// personalData is every confirmed PII column on a branch by table, or for one
// table when schema is set. Only confirmed findings count: a suspected one is a
// question for a reviewer, and refusing on it would make every scan a reason
// the feed stops working. A branch never scanned and never masked has neither
// record, and so nothing confirmed.
//
// The lookup is the engine's (branch.ConfirmedPersonalColumns), shared with
// the warnings given when a branch holding unmasked personal data is handed to
// an agent: one reading of the records, so the feed and the warnings never
// disagree about which columns hold personal data.
func personalData(branchName, schema, table string) (map[string][]PIIColumn, error) {
	cols, err := branch.ConfirmedPersonalColumns(branchName, schema, table)
	if err != nil {
		return nil, err
	}
	out := map[string][]PIIColumn{}
	for _, c := range cols {
		t := c.Schema + "." + c.Table
		out[t] = append(out[t], PIIColumn{Name: c.Column, Category: c.Category, Mask: c.Mask})
	}
	for t := range out {
		sort.Slice(out[t], func(i, j int) bool { return out[t][i].Name < out[t][j].Name })
	}
	return out, nil
}

// streamColumnsByTable is the recorded choice for every table that has one.
// A nil list means every column, which is also what a table with no entry
// streams.
func streamColumnsByTable(branchName string) (map[string][]string, error) {
	ok, err := branch.RelationExists(branchName, columnsTable)
	if err != nil || !ok {
		return map[string][]string{}, err
	}
	lines, err := branch.LedgerQuery(branchName, streamColumnsSQL)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", columnsTable, err)
	}
	return decodeStreamColumns(lines)
}

const columnsExistSQL = `SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'bb' AND c.relname = 'realtime_columns')`

const streamColumnsSQL = `SELECT json_build_object('schema', schema_name, 'table', table_name, 'columns', columns) FROM ` + columnsTable

func decodeStreamColumns(lines []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, l := range lines {
		if l == "" {
			continue
		}
		var r struct {
			Schema  string   `json:"schema"`
			Table   string   `json:"table"`
			Columns []string `json:"columns"`
		}
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			return nil, fmt.Errorf("reading %s: %w", columnsTable, err)
		}
		out[r.Schema+"."+r.Table] = r.Columns
	}
	return out, nil
}

// streamedPII is the confirmed PII columns a table's column choice lets
// through: all of them when it streams every column.
func streamedPII(pii []PIIColumn, stream []string) []PIIColumn {
	if stream == nil {
		return pii
	}
	var out []PIIColumn
	for _, p := range pii {
		if slices.Contains(stream, p.Name) {
			out = append(out, p)
		}
	}
	return out
}

func piiNames(ps []PIIColumn) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

// Filter is where a table's column choice is enforced.
const (
	FilterNone        = "none"        // every column streams
	FilterPublication = "publication" // Postgres sends only these; the decoder checks again
	FilterDecoder     = "decoder"     // Postgres sends the whole row; the decoder drops the rest
)

// Result is what enabling a table did, in enough detail that nobody has to
// guess which columns a subscriber will see.
type Result struct {
	Table  string   `json:"table"`
	Events []string `json:"events"`
	// Columns is what streams, in table order; empty means every column,
	// including ones added later.
	Columns []string `json:"columns,omitempty"`
	// KeyColumnsAdded are columns the caller did not name but that stream
	// anyway, because updates and deletes are located by them.
	KeyColumnsAdded []string `json:"key_columns_added,omitempty"`
	// Identity is how an update or delete names its row: "primary key",
	// "index", "full" or "none".
	Identity string `json:"identity"`
	// OldValues is whether subscribers receive the row as it was before an
	// update or delete, which only REPLICA IDENTITY FULL provides.
	OldValues bool   `json:"old_values"`
	Filter    string `json:"filter"`
	// PIIAllowed are confirmed personal-data columns the caller chose to
	// stream anyway. Recorded in the security log.
	PIIAllowed []string `json:"pii_allowed,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// enablePlan is Enable's decisions, made without a database so they can be
// read and tested: the statements to run and what to say about them.
type enablePlan struct {
	Result
	SQL string
}

// planEnable decides what enabling a table means. t is the table's facts,
// cols its columns, pii its confirmed personal data.
func planEnable(t Table, cols TableColumns, pii []PIIColumn, req Request) (enablePlan, error) {
	events := req.EventList()
	res := Result{Table: t.Qualified(), Events: events}

	// The identity. FULL when somebody asked for it: --old-values, or
	// --replica-identity=full. The second flag is also how a table with
	// nothing else to name a row by becomes streamable, and on a table that
	// already has a key it is still what it says — the whole previous row,
	// which costs WAL on every update. Leaving a keyed table as it was made
	// the flag a no-op, and a delete then carried only the key.
	identity := t.ReplicaIdentity
	setFull := false
	switch {
	case identity == 'f':
		// Already FULL, from an earlier enable or by hand. Not reverted: that
		// would be a schema change nobody asked for here.
	case req.OldValues || req.FullIdentity:
		setFull = true
	}
	if setFull {
		identity = 'f'
	}
	var key []string
	switch identity {
	case 'f':
		res.Identity = "full"
		key = cols.PrimaryKey
	case 'i':
		res.Identity = "index"
		key = cols.IdentityIndex
	case 'n':
		res.Identity = "none"
	default:
		if len(cols.PrimaryKey) > 0 {
			res.Identity = "primary key"
			key = cols.PrimaryKey
		} else {
			res.Identity = "none"
		}
	}
	res.OldValues = identity == 'f'
	if identity == 'f' && !t.HasPrimaryKey && t.ReplicaIdentity != 'i' {
		res.Notes = append(res.Notes, fmt.Sprintf("%s has no primary key, so it streams under REPLICA IDENTITY FULL: "+
			"every update and delete carries the previous row as well, limited to the columns that stream", t.Qualified()))
	} else if identity == 'f' {
		res.Notes = append(res.Notes, "updates and deletes carry the previous row as well, "+
			"limited to the columns that stream")
	}

	// The columns.
	var stream []string
	if len(req.Columns) > 0 {
		var unknown []string
		want := map[string]bool{}
		for _, c := range req.Columns {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if !slices.Contains(cols.Names, c) {
				unknown = append(unknown, c)
			}
			want[c] = true
		}
		if len(unknown) > 0 {
			return enablePlan{}, fmt.Errorf("%s has no column %s; its columns are %s",
				t.Qualified(), strings.Join(unknown, ", "), strings.Join(cols.Names, ", "))
		}
		if len(want) == 0 {
			return enablePlan{}, fmt.Errorf("--columns names no columns; leave it out to stream every column")
		}
		// The key stays in, whatever was asked: without it a subscriber
		// cannot tell which row an update or delete was about. Only when
		// updates or deletes are published -- an insert-only feed locates
		// nothing.
		if req.PublishesChanges() {
			for _, k := range key {
				if !want[k] {
					want[k] = true
					res.KeyColumnsAdded = append(res.KeyColumnsAdded, k)
				}
			}
		}
		for _, c := range cols.Names {
			if want[c] {
				stream = append(stream, c)
			}
		}
		res.Columns = stream
	}
	if len(res.KeyColumnsAdded) > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%s stream%s as well: updates and deletes are located by %s",
			strings.Join(res.KeyColumnsAdded, ", "), plural(len(res.KeyColumnsAdded), "s", ""),
			plural(len(res.KeyColumnsAdded), "them", "it")))
	}

	// Personal data. Refused unless every confirmed column is left out or the
	// caller says, by name of the flag, that it should stream anyway.
	if leak := streamedPII(pii, stream); len(leak) > 0 {
		if !req.AllowPII {
			return enablePlan{}, piiRefusal(t, leak, key, stream == nil)
		}
		res.PIIAllowed = piiNames(leak)
		res.Notes = append(res.Notes, fmt.Sprintf("streaming confirmed personal data: %s",
			strings.Join(res.PIIAllowed, ", ")))
	}

	// Where the filter is enforced.
	switch {
	case stream == nil:
		res.Filter = FilterNone
	case cols.ServerMajor > 0 && cols.ServerMajor < ColumnListMajor:
		res.Filter = FilterDecoder
		res.Notes = append(res.Notes, fmt.Sprintf("PostgreSQL %d has no publication column lists, so Postgres "+
			"decodes whole rows and the feed drops the other columns before any subscriber sees them",
			cols.ServerMajor))
	case cols.ServerMajor == 0:
		// Could not be read: assume the older behaviour rather than send a
		// statement the server may not parse.
		res.Filter = FilterDecoder
	case identity == 'f' && req.PublishesChanges():
		// Postgres requires a column list to cover the replica identity when
		// updates or deletes are published, and under FULL that is every
		// column: a narrower list would make the application's UPDATEs fail.
		res.Filter = FilterDecoder
		res.Notes = append(res.Notes, "under REPLICA IDENTITY FULL a publication cannot leave columns out, "+
			"so the feed drops the other columns itself before any subscriber sees them")
	default:
		res.Filter = FilterPublication
	}

	return enablePlan{Result: res, SQL: enableSQL(t, req, stream, setFull, res.Filter == FilterPublication, res.PIIAllowed)}, nil
}

func plural(n int, many, one string) string {
	if n == 1 {
		return one
	}
	return many
}

// piiRefusal names the columns and both ways forward.
func piiRefusal(t Table, leak []PIIColumn, key []string, all bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s has confirmed personal data that this feed would stream:\n", t.Qualified())
	var excludable []string
	for _, p := range leak {
		fmt.Fprintf(&b, "  %s\n", p)
		if !slices.Contains(key, p.Name) {
			excludable = append(excludable, p.Name)
		}
	}
	b.WriteString("\nA change feed sends stored values, so masking does not apply to it, and anyone " +
		"holding a realtime key for this branch would receive them.\n")
	if len(excludable) > 0 {
		if all {
			fmt.Fprintf(&b, "\n--columns a,b,c   stream only the columns you name (leave out %s)",
				strings.Join(excludable, ", "))
		} else {
			fmt.Fprintf(&b, "\n--columns ...     leave out %s", strings.Join(excludable, ", "))
		}
	}
	if len(excludable) < len(leak) {
		fmt.Fprintf(&b, "\n(a key column always streams, so it cannot be left out this way)")
	}
	fmt.Fprintf(&b, "\n--allow-pii       stream them anyway; recorded in the security log")
	return fmt.Errorf("%s", b.String())
}

// enableSQL is one transaction: the identity, the publication, the table in
// it with its column list, and the record the decoder enforces. One
// transaction so a failure leaves nothing half-enabled, and so a running
// decoder never sees the table out of every publication while it is moved.
func enableSQL(t Table, req Request, stream []string, setFull, columnList bool, piiAllowed []string) string {
	qt := branch.QuoteIdent(t.Schema) + "." + branch.QuoteIdent(t.Name)
	pub := branch.PublicationFor(req.EventList())
	var s []string
	s = append(s, "BEGIN")
	// REPLICA IDENTITY FULL is a schema change like any other, and is recorded
	// in the Blackbox as one.
	if setFull {
		s = append(s, "ALTER TABLE "+qt+" REPLICA IDENTITY FULL")
	}
	// Never FOR ALL TABLES: that would publish bb.schema_ledger, and with it
	// the recorded text of every statement ever run.
	s = append(s, fmt.Sprintf(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = %s) THEN
  EXECUTE format('CREATE PUBLICATION %%I WITH (publish = %%L)', %s, %s);
END IF; END $$`, branch.BodyLiteral(pub), branch.BodyLiteral(pub),
		branch.BodyLiteral(strings.Join(req.EventList(), ","))))
	// Out of every feed publication first, then into the one for these
	// events. A table enabled again is how its columns are changed, and
	// Postgres has no statement that changes one table's column list in
	// place. It also keeps a table in exactly one publication: pgoutput
	// refuses a table published with two different column lists.
	s = append(s, fmt.Sprintf(`DO $$ DECLARE p text; BEGIN
  FOR p IN SELECT pubname FROM pg_publication_tables
    WHERE pubname LIKE %s AND schemaname = %s AND tablename = %s LOOP
    EXECUTE format('ALTER PUBLICATION %%I DROP TABLE %%I.%%I', p, %s, %s);
  END LOOP;
END $$`, branch.BodyLiteral(branch.PublicationPrefix+"%"),
		branch.BodyLiteral(t.Schema), branch.BodyLiteral(t.Name),
		branch.BodyLiteral(t.Schema), branch.BodyLiteral(t.Name)))
	add := "ALTER PUBLICATION " + branch.QuoteIdent(pub) + " ADD TABLE " + qt
	if columnList {
		add += " (" + identList(stream) + ")"
	}
	s = append(s, add)
	s = append(s, columnsDDL()...)
	s = append(s, fmt.Sprintf(`INSERT INTO %s (schema_name, table_name, columns, old_values, pii_allowed, set_by)
VALUES (%s, %s, %s, %t, %s, %s)
ON CONFLICT (schema_name, table_name) DO UPDATE SET columns = EXCLUDED.columns,
  old_values = EXCLUDED.old_values, pii_allowed = EXCLUDED.pii_allowed,
  set_by = EXCLUDED.set_by, set_at = now()`, columnsTable,
		branch.QuoteLiteral(t.Schema), branch.QuoteLiteral(t.Name), textArray(stream, true),
		setFull || t.ReplicaIdentity == 'f', textArray(piiAllowed, false), branch.QuoteLiteral(req.Actor)))
	s = append(s, "COMMIT")
	return strings.Join(s, ";\n") + ";"
}

func identList(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = branch.QuoteIdent(c)
	}
	return strings.Join(q, ", ")
}

// textArray renders a text[] literal; nil is SQL NULL when nullable.
func textArray(vals []string, nullable bool) string {
	if vals == nil && nullable {
		return "NULL"
	}
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = branch.QuoteLiteral(v)
	}
	return "ARRAY[" + strings.Join(q, ", ") + "]::text[]"
}

// AuditDetail is the security-log line for an enable: the table, what
// streams, and above all any confirmed personal data streamed on purpose,
// which is the decision an auditor will ask about.
func AuditDetail(r Result) string {
	cols := "all columns"
	if len(r.Columns) > 0 {
		cols = "columns " + strings.Join(r.Columns, ",")
	}
	s := fmt.Sprintf("%s: %s; %s", r.Table, strings.Join(r.Events, ","), cols)
	if r.OldValues {
		s += "; old values"
	}
	if len(r.PIIAllowed) > 0 {
		s += "; personal data allowed: " + strings.Join(r.PIIAllowed, ",")
	}
	return s
}

// PIIWarning is a table streaming confirmed personal data, for `fox realtime
// status` and the readiness survey.
func (v Verdict) PIIWarning() string {
	if len(v.StreamingPII) == 0 {
		return ""
	}
	return fmt.Sprintf("%s streams confirmed personal data (%s): %s realtime enable %s --columns ... to narrow it",
		v.Table.Qualified(), strings.Join(v.StreamingPII, ", "), brand.CLI, v.Table.Qualified())
}
